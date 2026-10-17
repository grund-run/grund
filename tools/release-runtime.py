#!/usr/bin/env python3
"""Run the staged Linux binary with disposable, real PostgreSQL and NATS."""

import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def wait_for_port(url):
    address = urllib.parse.urlsplit(url)
    deadline = time.monotonic() + 60
    while True:
        try:
            with socket.create_connection((address.hostname, address.port), timeout=2):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"release dependency never accepted connections: {address.scheme}")
            time.sleep(1)


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: tools/release-runtime.py <staged-linux-binary>")
    binary = str(Path(sys.argv[1]).resolve())
    revision = os.environ.get("CI_COMMIT_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("CI_COMMIT_SHA must name the expected full public commit")
    database = os.environ["GRUND_RELEASE_DATABASE_URL"]
    nats = os.environ["GRUND_RELEASE_NATS_URL"]
    wait_for_port(database)
    wait_for_port(nats)
    root = Path(__file__).resolve().parent.parent
    work = root / "scratch/tag-release"
    work.mkdir(parents=True, exist_ok=True)
    address = os.environ.get("GRUND_RELEASE_LISTEN", "127.0.0.1:18080")
    origin = "http://" + address
    # No tag bypass: this harness accepts an explicit file for pretag proof;
    # the release builder and all publishing operations retain identity checks.
    with tempfile.TemporaryDirectory(prefix="runtime-", dir=work) as temporary:
        state = Path(temporary)
        secret = state / "instance-secret"
        with open(secret, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as target:
            target.write(secrets.token_hex(32))
        environment = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "SSL_CERT_FILE", "SSL_CERT_DIR")}
        environment.update({
            "DATABASE_URL": database,
            "GRUND_NATS_URL": nats,
            "GRUND_LISTEN": address,
            "GRUND_PUBLIC_URL": origin,
            "GRUND_ACCEPT_URL": origin,
            "GRUND_SECRET_KEY_FILE": str(secret),
            "GRUND_HEALTH_INTERVAL": "1",
            "GRUND_WORK_POLL_INTERVAL": "1",
            "GRUND_ORGANISATIONS": "multi",
            "GRUND_CREDENTIALS_FILE": str(state / "credentials.yaml"),
        })
        logfile = work / "runtime-server.log"
        with logfile.open("w") as log:
            server = subprocess.Popen([binary, "serve"], env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 90
                while True:
                    if server.poll() is not None:
                        raise RuntimeError("released binary exited before readiness")
                    try:
                        with urllib.request.urlopen(origin + "/health/ready", timeout=2) as response:
                            ready = json.load(response)
                        checks = {check["name"]: check["status"] for check in ready["checks"]}
                        if ready.get("revision") != revision:
                            raise RuntimeError("ready response does not identify the released commit")
                        if all(checks.get(name) == "healthy" for name in ("postgres", "nats")):
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("released binary never reported healthy PostgreSQL and NATS")
                    time.sleep(1)
                subprocess.run([binary, "probe", "--address", address], env=environment, check=True, timeout=10)
                # Existing bootstrap exercises setup-link, the real owner form,
                # CSRF/session handling, and owner creation without logging links.
                subprocess.run(["sh", str(root / "accept-bootstrap.sh"), binary], env=environment, check=True, timeout=120)
                client = environment | {"GRUND_INSTANCE": origin, "GRUND_TOKEN": "grund_pat_release-runtime-deliberately-invalid"}
                result = subprocess.run([binary, "whoami", "--output", "json"], env=client, capture_output=True, text=True, timeout=15)
                if result.returncode != 3:
                    raise RuntimeError("released CLI did not reject the live request's invalid credential")
                error = json.loads(result.stderr)["error"]
                if error.get("code") != "unauthenticated" or error.get("rpc") != "grund.token.v1.TokenService/GetCurrentToken":
                    raise RuntimeError("released CLI did not complete the expected real authentication RPC")
                print("Released binary passed readiness, dependency, owner bootstrap, HTTP probe and CLI RPC checks")
            except BaseException:
                log.flush()
                print(logfile.read_text(), file=sys.stderr)
                raise
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"release runtime failed: {error}", file=sys.stderr)
        sys.exit(1)
