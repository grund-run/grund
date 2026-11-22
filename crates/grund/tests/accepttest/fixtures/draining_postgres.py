import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from urllib.parse import unquote, urlsplit

root = Path(os.environ["GRUND_DRAIN_STATE"])
root.mkdir(parents=True, exist_ok=True)
url = urlsplit(Path(os.environ["GRUND_DRAIN_DATABASE_URL_FILE"]).read_text())
env = os.environ.copy()
env.update(
    PGHOST="db.grund.internal",
    PGPORT="5432",
    PGUSER=unquote(url.username or ""),
    PGPASSWORD=unquote(url.password or ""),
    PGDATABASE=unquote(url.path.lstrip("/")),
    PGSSLMODE="disable",
    PGCONNECT_TIMEOUT="3",
    PGOPTIONS="-c statement_timeout=60000",
    PGAPPNAME=os.environ["GRUND_DRAIN_APPLICATION_NAME"],
)
stopping = threading.Event()


def terminate(signum, frame):
    (root / "sigterm").write_text(str(time.monotonic()))
    stopping.set()


signal.signal(signal.SIGTERM, terminate)


def query(sql):
    result = subprocess.run(
        ["setpriv", "--pdeathsig", "KILL", "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-c", sql],
        env=env,
        capture_output=True,
        text=True,
        timeout=70,
    )
    if result.returncode:
        raise RuntimeError(f"psql failed ({result.returncode}): {result.stderr}")
    return result.stdout.splitlines()


try:
    for attempt in range(30):
        try:
            query("SELECT 1")
            break
        except RuntimeError:
            if attempt == 29:
                raise
            time.sleep(0.2)
    key = int(os.environ["GRUND_DRAIN_LOCK_KEY"])
    result = query(
        f"SELECT pg_advisory_lock({key}); "
        "SELECT 'in-flight-finished'; "
        f"SELECT pg_advisory_unlock({key})"
    )
    if "in-flight-finished" not in result:
        raise RuntimeError(f"in-flight query returned {result!r}")
    (root / "in-flight-finished").touch()
    if not stopping.wait(10):
        raise RuntimeError("query finished before SIGTERM")
    result = query("SELECT 'new-outbound-finished'")
    if result != ["new-outbound-finished"]:
        raise RuntimeError(f"new outbound query returned {result!r}")
    (root / "new-outbound-finished").touch()
    while os.environ["GRUND_DRAIN_EXIT"] != "yes" or not (root / "exit").exists():
        time.sleep(0.05)
    (root / "exited").touch()
except Exception as error:
    (root / "error").write_text(str(error))
    raise
