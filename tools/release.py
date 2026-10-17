#!/usr/bin/env python3
"""Stage, verify and publish one immutable, explicitly tagged grund release."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "scratch/tag-release"
DIST = WORK / "dist"
OCI = WORK / "oci"
HOST = "https://git.kjuulh.io"
IMAGE = "git.kjuulh.io/grund/grund"
API = HOST + "/api/v1/repos/grund/grund"
TAG = os.environ.get("CI_COMMIT_TAG", "")
REVISION = os.environ.get("CI_COMMIT_SHA", "")
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-alpha\.([1-9][0-9]*))?")
FILES = ("grund-linux-amd64", "grund-linux-arm64", "compose.yaml", "agent-install.sh", "release.txt", "image-digest.txt")


def fail(message):
    raise RuntimeError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def identity():
    global REVISION
    if not VERSION.fullmatch(TAG):
        fail("release tag must be vX.Y.Z or vX.Y.Z-alpha.N (N starts at 1)")
    if not re.fullmatch(r"[0-9a-f]{40}", REVISION):
        fail("CI_COMMIT_SHA must be a full 40-character commit or annotated tag object")
    # Gitea's annotated-tag webhook names the tag object, not its source commit.
    REVISION = output("git", "rev-parse", f"{REVISION}^{{commit}}")
    if output("git", "rev-parse", "HEAD") != REVISION:
        fail("checkout does not match CI_COMMIT_SHA")
    if output("git", "rev-parse", f"refs/tags/{TAG}^{{commit}}") != REVISION:
        fail("release tag does not point to the checked-out commit")


def prepare():
    identity()
    DIST.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "compose.yaml", DIST / "compose.yaml")
    shutil.copyfile(ROOT / "crates/grund-agent/install.sh", DIST / "agent-install.sh")
    (DIST / "release.txt").write_text(REVISION + "\n")


def verify():
    identity()
    for arch, machine in (("amd64", "Advanced Micro Devices X86-64"), ("arm64", "AArch64")):
        binary = DIST / f"grund-linux-{arch}"
        binary.chmod(0o755)
        header = output("readelf", "-h", str(binary))
        if machine not in header:
            fail(f"{binary.name} has the wrong ELF architecture")
        dynamic = output("readelf", "-d", str(binary))
        program = output("readelf", "-l", str(binary))
        if "NEEDED" in dynamic or "INTERP" in program:
            fail(f"{binary.name} must be static and have no ELF interpreter")
        # Check the revision without relying on grep's binary-file heuristics.
        if REVISION not in output("strings", str(binary)):
            fail(f"{binary.name} does not carry the release commit")
        runner = ["qemu-aarch64"] if arch == "arm64" else []
        if output(*runner, str(binary), "--version") != f"grund {TAG}":
            fail(f"{binary.name} does not report the exact release tag")
        for args in (("--help",), ("login", "--help"), ("serve", "--help"), ("join", "--help"), ("agent", "--help")):
            run(*runner, str(binary), *args, stdout=subprocess.DEVNULL)
        context = WORK / f"image-{arch}"
        (context / "var/lib/grund").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(binary, context / "grund")
        (context / "grund").chmod(0o755)
        shutil.copyfile("/etc/ssl/certs/ca-certificates.crt", context / "ca-certificates.crt")
        # COPY metadata must not change an immutable image on a rerun.
        for path in (*context.rglob("*"), context):
            os.utime(path, (0, 0))
    if (DIST / "release.txt").read_text() != REVISION + "\n":
        fail("release.txt does not name this public commit")
    # Detect stale or foreign artifacts instead of accidentally publishing them.
    if set(p.name for p in DIST.iterdir()) - set(FILES) - {"SHA256SUMS"}:
        fail("unexpected files in release staging directory")


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def blob(descriptor):
    algorithm, value = descriptor["digest"].split(":", 1)
    if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", value):
        fail("OCI descriptor is not a SHA-256 digest")
    path = OCI / "blobs/sha256" / value
    if digest(path) != value or path.stat().st_size != descriptor["size"]:
        fail("OCI descriptor content does not match its digest and size")
    return path


def image_manifest(descriptor):
    value = json.loads(blob(descriptor).read_bytes())
    if "manifests" in value:
        if len(value["manifests"]) != 1:
            fail("each architecture archive must contain exactly one image; disable attestations")
        return image_manifest(value["manifests"][0])
    return descriptor, value


def merge_images():
    identity()
    (OCI / "blobs/sha256").mkdir(parents=True, exist_ok=True)
    manifests = []
    for arch in ("amd64", "arm64"):
        with tarfile.open(WORK / f"image-{arch}.tar") as archive:
            index = json.load(archive.extractfile("index.json"))
            for member in archive.getmembers():
                if not member.isfile() or not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name):
                    continue
                destination = OCI / member.name
                with archive.extractfile(member) as source, destination.open("wb") as target:
                    shutil.copyfileobj(source, target)
            if len(index["manifests"]) != 1:
                fail("expected one image per architecture archive")
            descriptor, manifest = image_manifest(index["manifests"][0])
        config = json.loads(blob(manifest["config"]).read_bytes())
        if config["architecture"] != arch or config["os"] != "linux":
            fail("image architecture does not match its staged binary")
        if config["config"].get("Entrypoint") != ["/grund"]:
            fail("image does not run the unified grund binary")
        found = {}
        for layer in manifest["layers"]:
            with tarfile.open(blob(layer)) as contents:
                for member in contents.getmembers():
                    name = member.name.removeprefix("./").lstrip("/")
                    if name in ("grund", "etc/ssl/certs/ca-certificates.crt") and member.isfile():
                        with contents.extractfile(member) as source:
                            found[name] = hashlib.file_digest(source, "sha256").hexdigest()
        if found.get("grund") != digest(DIST / f"grund-linux-{arch}"):
            fail("packaged image does not contain the verified release binary")
        if found.get("etc/ssl/certs/ca-certificates.crt") != digest(WORK / f"image-{arch}/ca-certificates.crt"):
            fail("packaged image does not contain the staged CA bundle")
        manifests.append({"mediaType": descriptor["mediaType"], "digest": descriptor["digest"], "size": descriptor["size"], "platform": {"os": "linux", "architecture": arch}})
    index = json_bytes({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
    index_hash = hashlib.sha256(index).hexdigest()
    (OCI / "blobs/sha256" / index_hash).write_bytes(index)
    (WORK / "image-index.json").write_bytes(index)
    reference = {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + index_hash, "size": len(index), "annotations": {"org.opencontainers.image.ref.name": "release"}}
    (OCI / "index.json").write_bytes(json_bytes({"schemaVersion": 2, "manifests": [reference]}))
    (OCI / "oci-layout").write_bytes(json_bytes({"imageLayoutVersion": "1.0.0"}))
    image_digest = "sha256:" + index_hash
    (DIST / "image-digest.txt").write_text(f"{IMAGE}@{image_digest}\n")
    with (DIST / "SHA256SUMS").open("w") as sums:
        for name in FILES:
            sums.write(f"{digest(DIST / name)}  {name}\n")


def credentials():
    token = os.environ.get("REGISTRY_TOKEN")
    if not token:
        fail("REGISTRY_TOKEN is required (package write and repository release write)")
    return "Basic " + base64.b64encode(f"kjuulh:{token}".encode()).decode()


def request(url, method="GET", data=None, authenticated=False):
    headers = {"Content-Type": "application/octet-stream" if method == "PUT" else "application/json"} if data is not None else {}
    if authenticated:
        headers["Authorization"] = credentials()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    # No redirect may forward credentials to another host.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=300) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def publish_image():
    identity()
    authfile = WORK / "registry-auth.json"
    with open(authfile, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as target:
        json.dump({"auths": {"git.kjuulh.io": {"auth": credentials().removeprefix("Basic ")}}}, target)
    try:
        # list-tags distinguishes an absent tag from authentication/network errors.
        tags = json.loads(output("skopeo", "list-tags", "--authfile", str(authfile), f"docker://{IMAGE}"))["Tags"]
        if TAG not in (tags or []):
            run("skopeo", "copy", "--all", "--preserve-digests", "--authfile", str(authfile), f"oci:{OCI}:release", f"docker://{IMAGE}:{TAG}")
        remote = subprocess.check_output(["skopeo", "inspect", "--raw", "--authfile", str(authfile), f"docker://{IMAGE}:{TAG}"])
        expected = (WORK / "image-index.json").read_bytes()
        if hashlib.sha256(remote).digest() != hashlib.sha256(expected).digest():
            fail("existing/published image tag differs from the verified immutable image")
    finally:
        authfile.unlink(missing_ok=True)


def publish():
    identity()
    credentials()
    expected_sums = "".join(f"{digest(DIST / name)}  {name}\n" for name in FILES)
    if (DIST / "SHA256SUMS").read_text() != expected_sums:
        fail("staged SHA256SUMS does not match all release payloads")
    expected_image = (DIST / "image-digest.txt").read_text().strip()
    remote = subprocess.check_output(["skopeo", "inspect", "--raw", f"docker://{IMAGE}:{TAG}"])
    if expected_image != f"{IMAGE}@sha256:{hashlib.sha256(remote).hexdigest()}":
        fail("public image is not the verified immutable image")
    base = HOST + f"/api/packages/grund/generic/grund/{TAG}/"
    # Payload files first; SHA256SUMS is the package completion marker.
    for name in (*FILES, "SHA256SUMS"):
        path = DIST / name
        data = path.read_bytes()
        status, _ = request(base + name, "PUT", data, authenticated=True)
        if status not in (201, 409):
            fail(f"upload of {name} failed with HTTP {status}")
        status, downloaded = request(base + name)
        if status != 200 or downloaded != data:
            fail(f"public {name} differs from the staged bytes (including on HTTP 409)")
    alpha = "-alpha." in TAG
    stage = "Alpha release. Expect rough edges; not a stability guarantee.\n\n" if alpha else ""
    if TAG == "v0.0.0-alpha.2":
        stage += "v0.0.0-alpha.1 was a failed, unpublished tag; no binaries or Gitea release were published for it. This is the first downloadable alpha.\n\n"
    notes = (f"{stage}Linux downloads for amd64 and arm64 include the command-line client, server and machine commands in one static binary.\n\n"
             f"Downloads and SHA256SUMS: {base}\n\n"
             f"Self-host image: `{IMAGE}:{TAG}`\n\nPublic source commit: `{REVISION}`.\n\n"
             "macOS downloads are not included in this release.")
    payload = {"tag_name": TAG, "target_commitish": REVISION, "name": f"grund {TAG}", "body": notes, "draft": False, "prerelease": alpha}
    status, existing = request(API + f"/releases/tags/{TAG}", authenticated=True)
    if status == 404:
        status, existing = request(API + "/releases", "POST", json_bytes(payload), authenticated=True)
        if status != 201:
            fail(f"release creation failed with HTTP {status}; packages remain immutable and unannounced")
    elif status != 200:
        fail(f"release lookup failed with HTTP {status}")
    release = json.loads(existing)
    for field in ("tag_name", "name", "body", "draft", "prerelease"):
        if release.get(field) != payload[field]:
            fail(f"existing release has different {field}; refusing to mutate it")
    print(f"Verified public release {TAG} at {base}")


def main():
    os.chdir(ROOT)
    commands = {"prepare": prepare, "verify": verify, "merge-images": merge_images, "publish-image": publish_image, "publish": publish}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        fail("usage: tools/release.py {prepare|verify|merge-images|publish-image|publish}")
    commands[sys.argv[1]]()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release failed: {error}", file=sys.stderr)
        sys.exit(1)
