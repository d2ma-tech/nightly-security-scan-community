"""Deterministic states and append-only SHA-256 event chain."""
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path


class InvalidTransition(RuntimeError):
    pass


TRANSITIONS = {
    "PRECHECK": {"RUNNING", "INCOMPLETE", "INTEGRITY_FAILURE", "LOCKED"},
    "RUNNING": {"FINALIZING", "INCOMPLETE", "INTEGRITY_FAILURE"},
    "FINALIZING": {"COMPLETE", "INCOMPLETE", "INTEGRITY_FAILURE"},
    "COMPLETE": set(), "INCOMPLETE": set(), "INTEGRITY_FAILURE": set(), "LOCKED": set(),
}


class StateMachine:
    def __init__(self, initial="PRECHECK"):
        if initial not in TRANSITIONS:
            raise ValueError("unknown state")
        self.current = initial

    def transition(self, target):
        if target not in TRANSITIONS[self.current]:
            raise InvalidTransition("invalid state transition")
        self.current = target


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class HashChainLog:
    def __init__(self, path, event_validator=None):
        self.path = Path(path)
        self.event_validator = event_validator

    def _open_read(self):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise OSError("hash-chain log is not a regular file")
        return os.fdopen(fd, "r", encoding="ascii")

    def _last_hash(self):
        if not self.path.exists():
            return "0" * 64
        last = None
        with self._open_read() as stream:
            for line in stream:
                last = json.loads(line)
        return last["event_hash"] if last else "0" * 64

    def acquire_guard(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        guard = self.path.with_name(self.path.name + ".lock")
        guard_fd = os.open(guard, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        fcntl.flock(guard_fd, fcntl.LOCK_EX)
        return guard_fd

    @staticmethod
    def release_guard(guard_fd):
        fcntl.flock(guard_fd, fcntl.LOCK_UN)
        os.close(guard_fd)

    def append(self, event, guard_fd=None):
        if self.event_validator is not None:
            event = self.event_validator(event)
        owned_guard = guard_fd is None
        if owned_guard:
            guard_fd = self.acquire_guard()
        try:
            previous = self._last_hash()
            body = {"event": event, "previous_hash": previous}
            body["event_hash"] = hashlib.sha256(canonical(body).encode("ascii")).hexdigest()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "a", encoding="ascii") as stream:
                stream.write(canonical(body) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(self.path, 0o600)
            return body["event_hash"]
        finally:
            if owned_guard:
                self.release_guard(guard_fd)

    def verified_snapshot(self):
        previous = "0" * 64
        rows = []
        hashes = []
        if not self.path.exists():
            return {"events": rows, "event_count": 0, "head_hash": previous,
                    "event_hashes": hashes}
        try:
            with self._open_read() as stream:
                for line in stream:
                    record = json.loads(line)
                    if set(record) != {"event", "previous_hash", "event_hash"}:
                        raise ValueError("invalid hash-chain record")
                    event_hash = record["event_hash"]
                    body = {"event": record["event"], "previous_hash": record["previous_hash"]}
                    if body["previous_hash"] != previous:
                        raise ValueError("invalid previous hash")
                    if hashlib.sha256(canonical(body).encode("ascii")).hexdigest() != event_hash:
                        raise ValueError("invalid event hash")
                    event = body["event"]
                    if self.event_validator is not None:
                        event = self.event_validator(event)
                    elif not isinstance(event, dict):
                        raise ValueError("invalid event")
                    rows.append(event)
                    hashes.append(event_hash)
                    previous = event_hash
            return {"events": rows, "event_count": len(rows), "head_hash": previous,
                    "event_hashes": hashes}
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid hash-chain log") from exc

    def verified_events(self):
        return self.verified_snapshot()["events"]

    def events(self):
        return self.verified_events()

    def verify(self):
        try:
            self.verified_events()
            return True
        except ValueError:
            return False
