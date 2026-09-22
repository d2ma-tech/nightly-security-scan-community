"""Pinned Gitleaks adapter, sandbox profile, process-group watchdog and output bounds."""
import json
import os
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path

from . import constants, findings


class ScannerOutputError(RuntimeError):
    pass


class ScannerExecutionError(RuntimeError):
    pass


ALLOWED_FIELDS = {"RuleID", "Description", "StartLine", "EndLine", "StartColumn", "EndColumn",
                  "Match", "Secret", "File", "SymlinkFile", "Commit", "Entropy", "Author",
                  "Email", "Date", "Message", "Tags", "Fingerprint"}


def gitleaks_argv(binary, repository, output):
    return (str(binary), "dir", str(repository), "--redact=100",
            "--report-format=json", "--report-path=" + str(output), "--exit-code=0")


def _literal(path):
    canonical = Path(path).resolve(strict=False)
    return str(canonical).replace("\\", "\\\\").replace('"', '\\"')


def sandbox_profile(repository, scratch, binary):
    """Return the validated macOS profile with canonical, minimal read/write roots."""
    executable = _literal(binary)
    repository_root = _literal(repository)
    scratch_root = _literal(scratch)
    return "\n".join([
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(deny network*)",
        '(deny file-read* (subpath "%s"))' % _literal(Path.home()),
        '(deny file-write* (subpath "%s"))' % _literal(Path.home()),
        '(allow process-exec (literal "%s"))' % executable,
        "(allow process-fork)",
        '(allow file-read* (literal "%s") (subpath "%s") (subpath "%s"))' %
        (executable, repository_root, scratch_root),
        '(allow file-write* (subpath "%s"))' % scratch_root,
        "(allow process-info*)",
        "",
    ])


# No deployment-specific suppressions are distributed.

_GENERATED_COMPONENTS = {".next", ".pytest_cache", ".cache", "cache", "dist", "build",
                         "coverage", "node_modules", "generated"}
_TEST_COMPONENTS = {"test", "tests", "__tests__", "fixture", "fixtures", "testdata",
                    "spec", "specs"}
_DOCUMENT_COMPONENTS = {"doc", "docs", "documentation", "corpus"}
_CONFIG_COMPONENTS = {"config", "configs", "configuration"}
_DOCUMENT_SUFFIXES = {".md", ".rst", ".adoc", ".txt"}
_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
                    ".properties", ".xml"}
_RUNTIME_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java",
                     ".kt", ".kts", ".rb", ".php", ".swift", ".c", ".cc", ".cpp",
                     ".h", ".hpp", ".sh", ".bash", ".zsh", ".fish", ".sql"}


def _source_class(file_path):
    """Derive a closed, privacy-safe source class without retaining the input path."""
    normalized = str(file_path)
    if (not normalized or len(normalized) > 4096 or "\\" in normalized or "\x00" in normalized or
            any(part in (".", "..") for part in normalized.split("/"))):
        return "unknown"
    parts = tuple(part.lower() for part in normalized.split("/") if part)
    if not parts:
        return "unknown"
    components = set(parts[:-1])
    filename = parts[-1]
    suffix = Path(filename).suffix.lower()
    if components & _GENERATED_COMPONENTS:
        return "generated-or-cached"
    if (components & _TEST_COMPONENTS or filename.startswith("test_") or
            filename.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))):
        return "test-or-fixture"
    if components & _DOCUMENT_COMPONENTS or suffix in _DOCUMENT_SUFFIXES:
        return "documentation-or-prose"
    if (components & _CONFIG_COMPONENTS or suffix in _CONFIG_SUFFIXES or
            filename.startswith(".env") or filename in {"dockerfile", "makefile"}):
        return "configuration"
    if suffix in _RUNTIME_SUFFIXES:
        return "runtime-source"
    return "unknown"


def parse_gitleaks(raw, asset_id, run_id):
    if len(raw) > constants.GITLEAKS_OUTPUT_CAP or b"\x00" in raw:
        raise ScannerOutputError("scanner output rejected")
    try:
        text = raw.decode("utf-8", "strict")
        def closed_object(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = item
            return result
        value = json.loads(text, object_pairs_hook=closed_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScannerOutputError("scanner output rejected") from exc
    if not isinstance(value, list) or len(value) > 10000:
        raise ScannerOutputError("scanner schema rejected")
    normalized = {}
    for row in value:
        if not isinstance(row, dict) or not set(row).issubset(ALLOWED_FIELDS):
            raise ScannerOutputError("scanner schema rejected")
        if not isinstance(row.get("RuleID"), str) or not isinstance(row.get("File"), str):
            raise ScannerOutputError("scanner schema rejected")
        if not isinstance(row.get("StartLine", 0), int):
            raise ScannerOutputError("scanner schema rejected")
        rule_token = "".join(c for c in row["RuleID"].lower() if c.isalnum() or c in "-_.")[:96]
        if not rule_token:
            raise ScannerOutputError("scanner rule rejected")
        item = findings.make_finding("gitleaks", asset_id, "secret." + rule_token,
                                     "High", "confirmed", "file:line",
                                     "classify-secret-finding", run_id)
        fingerprint = item["fingerprint"]
        source_class = _source_class(row["File"])
        if fingerprint in normalized:
            normalized[fingerprint]["match_count"] += 1
            counts = normalized[fingerprint]["source_class_counts"]
            counts[source_class] = counts.get(source_class, 0) + 1
        else:
            item["match_count"] = 1
            item["source_class_counts"] = {source_class:1}
            normalized[fingerprint] = item
    return sorted(normalized.values(), key=lambda x: x["fingerprint"])


def _rss_bytes(pid):
    try:
        cp = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(pid)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=1, check=False,
                            env={"PATH":"/usr/bin:/bin", "LC_ALL":"C"})
        value = cp.stdout.decode("ascii", "strict").strip()
        return int(value) * 1024 if value else 0
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return 0


def execute_bounded(argv, profile, timeout=constants.SCANNER_TIMEOUT, cwd=None,
                    global_deadline=None, allowed_returncodes=(0,),
                    output_cap=constants.GITLEAKS_OUTPUT_CAP,
                    rss_limit=constants.RSS_LIMIT_BYTES):
    if (not allowed_returncodes or any(not isinstance(code, int) for code in allowed_returncodes) or
            not isinstance(output_cap, int) or output_cap <= 0 or
            not isinstance(rss_limit, int) or rss_limit <= 0):
        raise ScannerExecutionError("scanner execution contract rejected")
    command = ["/usr/bin/sandbox-exec", "-p", profile, *argv]
    env = {"PATH":"/usr/bin:/bin", "HOME":"/var/empty", "LC_ALL":"C", "LANG":"C",
           "GITLEAKS_ENABLE_UPLOAD":"false"}
    if cwd is not None:
        env["TMPDIR"] = str(Path(cwd).resolve(strict=True))
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, start_new_session=True,
                            cwd=None if cwd is None else str(Path(cwd).resolve(strict=True)))
    started = time.monotonic()
    process_deadline = started + timeout
    effective_deadline = (process_deadline if global_deadline is None else
                          min(process_deadline, global_deadline))
    killed_reason = None
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    while selector.get_map() or proc.poll() is None:
        for key, _ in selector.select(timeout=0.025):
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            captured[key.data].extend(chunk)
            if len(captured["stdout"]) + len(captured["stderr"]) > output_cap:
                killed_reason = "output"
        if time.monotonic() >= effective_deadline:
            killed_reason = "timeout"
        elif proc.poll() is None and _rss_bytes(proc.pid) > rss_limit:
            killed_reason = "rss"
        if killed_reason:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for registered in list(selector.get_map().values()):
                selector.unregister(registered.fileobj)
            break
    selector.close()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        killed_reason = killed_reason or "watchdog"
    if proc.stdout is not None:
        proc.stdout.close()
    if proc.stderr is not None:
        proc.stderr.close()
    stdout = bytes(captured["stdout"])
    stderr = bytes(captured["stderr"])
    if len(stdout) + len(stderr) > output_cap:
        raise ScannerExecutionError("scanner output limit")
    if killed_reason or proc.returncode not in allowed_returncodes:
        raise ScannerExecutionError("scanner failed closed")
    return stdout


class GitleaksScanner:
    def __init__(self, binary, scratch_root):
        self.binary = Path(binary)
        self.scratch_root = Path(scratch_root)

    def scan(self, asset, run_id, global_deadline=None):
        repo = Path(asset["path"])
        scratch = self.scratch_root / (run_id + "-" + asset["asset_id"])
        try:
            scratch.mkdir(mode=0o700, parents=True, exist_ok=False)
            profile = sandbox_profile(repo, scratch, self.binary)
            raw = execute_bounded(gitleaks_argv(self.binary, repo, Path("-")), profile,
                                  cwd=scratch, global_deadline=global_deadline)
            return parse_gitleaks(raw, asset["asset_id"], run_id)
        finally:
            try:
                if scratch.exists():
                    shutil.rmtree(scratch)
            except OSError as exc:
                raise ScannerExecutionError("scanner scratch cleanup failed") from exc
            if scratch.exists():
                raise ScannerExecutionError("scanner scratch cleanup failed")
