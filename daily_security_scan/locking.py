"""Exclusive lock bound to PID plus process-start fingerprint."""
import json
import os
from pathlib import Path


class LockHeld(RuntimeError):
    pass


def process_start_fingerprint(pid):
    # Darwin's ps lstart is stable for the lifetime of a PID; no shell is involved.
    import subprocess
    result = subprocess.run(["/bin/ps", "-o", "lstart=", "-p", str(int(pid))],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=2, check=False, env={"PATH":"/usr/bin:/bin", "LC_ALL":"C"})
    value = result.stdout.decode("ascii", "strict").strip()
    return value or None


class RunLock:
    def __init__(self, path, process_probe=process_start_fingerprint):
        self.path = Path(path)
        self.process_probe = process_probe
        self.owned = False

    def acquire(self, pid=None, fingerprint=None):
        pid = os.getpid() if pid is None else int(pid)
        fingerprint = self.process_probe(pid) if fingerprint is None else fingerprint
        if not fingerprint:
            raise LockHeld("cannot establish process fingerprint")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps({"pid":pid, "fingerprint":fingerprint}, sort_keys=True).encode("ascii")
        for attempt in range(2):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.owned = True
                return
            except FileExistsError:
                try:
                    existing = json.loads(self.path.read_text(encoding="ascii"))
                    live = self.process_probe(int(existing["pid"]))
                except (OSError, ValueError, KeyError, json.JSONDecodeError):
                    raise LockHeld("ambiguous lock")
                if live == existing["fingerprint"]:
                    raise LockHeld("scan already running")
                if attempt == 0:
                    stale = self.path.with_name(self.path.name + ".stale")
                    try:
                        os.replace(self.path, stale)
                    except OSError as exc:
                        raise LockHeld("stale lock recovery failed") from exc
                    continue
        raise LockHeld("lock acquisition failed")

    def release(self):
        if self.owned:
            try:
                self.path.unlink()
            finally:
                self.owned = False
