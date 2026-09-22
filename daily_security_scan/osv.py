"""Digest-bound, offline-only OSV dependency scanning for approved local lockfiles."""
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import constants, findings, inventory, runner


class OsvOutputError(RuntimeError):
    pass


class OsvCoverageError(RuntimeError):
    pass


class OsvReleaseIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class OsvDatabaseContract:
    ecosystem: str
    relative_path: str
    bytes: int
    sha256: str
    source_url: str
    last_modified: str


@dataclass(frozen=True)
class OsvReleaseContract:
    version: str
    binary_bytes: int
    binary_sha256: str
    databases: tuple


@dataclass(frozen=True)
class ResolvedOsvRelease:
    binary: Path
    database_root: Path
    evidence: dict


@dataclass(frozen=True)
class LockfileSnapshot:
    filename: str
    data: bytes
    device: int
    inode: int


PRODUCTION_CONTRACT = OsvReleaseContract(
    version=constants.OSV_SCANNER_VERSION,
    binary_bytes=constants.OSV_SCANNER_BINARY_BYTES,
    binary_sha256=constants.OSV_SCANNER_BINARY_SHA256,
    databases=(OsvDatabaseContract(
        ecosystem="npm",
        relative_path="osv-scalibr/npm/all.zip",
        bytes=constants.OSV_NPM_DATABASE_BYTES,
        sha256=constants.OSV_NPM_DATABASE_SHA256,
        source_url=constants.OSV_NPM_DATABASE_SOURCE,
        last_modified=constants.OSV_NPM_DATABASE_LAST_MODIFIED,
    ),),
)

_SUPPORTED_LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
_EXCLUDED_DIRECTORIES = {".git", ".local", ".next", ".cache", ".pytest_cache", ".venv",
                         "venv", "node_modules", "dist", "build", "coverage"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def dependency_artifacts(asset):
    """Validate exact artifact roots and digest-bound lockfile declarations."""
    artifacts = asset.get("dependency_artifacts")
    if (not isinstance(artifacts, list) or not artifacts or
            len(artifacts) > constants.MAX_DEPENDENCY_ROOTS):
        raise OsvCoverageError("explicit dependency artifacts required")
    normalized = []
    seen_roots = set()
    try:
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "lockfiles"}:
                raise OsvCoverageError("dependency artifact schema rejected")
            raw_root, declarations = artifact.get("path"), artifact.get("lockfiles")
            if (not isinstance(raw_root, str) or not Path(raw_root).is_absolute() or
                    not isinstance(declarations, list) or not declarations):
                raise OsvCoverageError("dependency artifact binding rejected")
            root = inventory.validate_repository_root(Path(raw_root))
            if str(root) in seen_roots:
                raise OsvCoverageError("duplicate dependency artifact root")
            seen_roots.add(str(root))
            lockfiles = []
            seen_relative = set()
            for declaration in declarations:
                if (not isinstance(declaration, dict) or
                        set(declaration) != {"relative_path", "sha256"}):
                    raise OsvCoverageError("dependency lockfile schema rejected")
                raw_relative, digest = (declaration.get("relative_path"),
                                        declaration.get("sha256"))
                relative = PurePosixPath(raw_relative) if isinstance(raw_relative, str) else PurePosixPath("/")
                if (not isinstance(raw_relative, str) or relative.is_absolute() or
                        ".." in relative.parts or not relative.parts or
                        relative.name not in _SUPPORTED_LOCKFILES or
                        not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest) or
                        raw_relative in seen_relative):
                    raise OsvCoverageError("dependency lockfile binding rejected")
                seen_relative.add(raw_relative)
                lockfiles.append((relative, digest))
            normalized.append((root, tuple(lockfiles)))
    except inventory.CoverageError as exc:
        raise OsvCoverageError("dependency root rejected") from exc
    return normalized


def dependency_roots(asset):
    """Compatibility view of exact artifact roots."""
    return [root for root, _ in dependency_artifacts(asset)]


_ADVISORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_LOCKFILES = 64
_MAX_LOCKFILE_BYTES = 32 * 1024 * 1024


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_manifest(contract):
    return {
        "schema":"daily-security-scan-osv-install-v1",
        "version":contract.version,
        "binary":{"relative_path":"osv-scanner", "bytes":contract.binary_bytes,
                  "sha256":contract.binary_sha256},
        "databases":[{
            "ecosystem":database.ecosystem,
            "relative_path":database.relative_path,
            "bytes":database.bytes,
            "sha256":database.sha256,
            "source_url":database.source_url,
            "last_modified":database.last_modified,
        } for database in contract.databases],
        "network_access":False,
        "runtime_mode":"offline-only",
    }


def _read_small_json(path, maximum=64 * 1024):
    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise OsvReleaseIntegrityError("OSV JSON boundary violation")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum or
                    (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise OsvReleaseIntegrityError("OSV JSON changed during open")
            raw = os.read(fd, maximum + 1)
        finally:
            os.close(fd)
        if len(raw) > maximum:
            raise OsvReleaseIntegrityError("OSV JSON exceeds bound")
        value = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OsvReleaseIntegrityError("invalid OSV JSON") from exc
    if not isinstance(value, dict):
        raise OsvReleaseIntegrityError("OSV JSON root rejected")
    return value


def _verified_regular(path, expected_bytes, expected_sha256, executable=False):
    path = Path(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise OsvReleaseIntegrityError("OSV release file absent") from exc
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or
            before.st_size != expected_bytes or
            (executable and not before.st_mode & stat.S_IXUSR)):
        raise OsvReleaseIntegrityError("OSV release file boundary rejected")
    if _sha256_file(path) != expected_sha256:
        raise OsvReleaseIntegrityError("OSV release digest mismatch")
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size):
        raise OsvReleaseIntegrityError("OSV release changed during verification")
    return path


def resolve_release(locator, contract=PRODUCTION_CONTRACT):
    locator = Path(locator)
    value = _read_small_json(locator)
    if set(value) != {"schema", "release_directory"} or value.get("schema") != "daily-security-scan-osv-release-locator-v1":
        raise OsvReleaseIntegrityError("OSV locator schema rejected")
    token = value.get("release_directory")
    if not isinstance(token, str) or PurePosixPath(token).name != token:
        raise OsvReleaseIntegrityError("OSV locator path rejected")
    release = locator.parent / token
    try:
        mode = release.lstat().st_mode
    except OSError as exc:
        raise OsvReleaseIntegrityError("OSV release absent") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise OsvReleaseIntegrityError("OSV release directory rejected")
    expected_manifest = release_manifest(contract)
    if _read_small_json(release / "installation-manifest.json") != expected_manifest:
        raise OsvReleaseIntegrityError("OSV installation manifest mismatch")
    binary = _verified_regular(release / "osv-scanner", contract.binary_bytes,
                               contract.binary_sha256, executable=True)
    database_root = release / "database"
    evidence = {}
    for database in contract.databases:
        relative = PurePosixPath(database.relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise OsvReleaseIntegrityError("OSV database path rejected")
        current = database_root
        for part in relative.parts[:-1]:
            current = current / part
            try:
                component_mode = current.lstat().st_mode
            except OSError as exc:
                raise OsvReleaseIntegrityError("OSV database directory absent") from exc
            if stat.S_ISLNK(component_mode) or not stat.S_ISDIR(component_mode):
                raise OsvReleaseIntegrityError("OSV database directory rejected")
        _verified_regular(database_root / Path(*relative.parts), database.bytes, database.sha256)
        evidence[database.ecosystem] = {
            "sha256":database.sha256,
            "bytes":database.bytes,
            "last_modified":database.last_modified,
            "source_url":database.source_url,
            "version":"v" + contract.version,
        }
    return ResolvedOsvRelease(binary=binary, database_root=database_root, evidence=evidence)


def discover_lockfiles(repository):
    repository = Path(repository).resolve(strict=True)
    found = []
    for root, directories, files in os.walk(repository, topdown=True, followlinks=False):
        root_path = Path(root)
        kept = []
        for name in sorted(directories):
            candidate = root_path / name
            if name in _EXCLUDED_DIRECTORIES or candidate.is_symlink():
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            if name not in _SUPPORTED_LOCKFILES:
                continue
            candidate = root_path / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or candidate.stat().st_size > _MAX_LOCKFILE_BYTES:
                raise OsvCoverageError("supported lockfile boundary rejected")
            try:
                candidate.resolve(strict=True).relative_to(repository)
            except ValueError as exc:
                raise OsvCoverageError("supported lockfile escaped repository") from exc
            found.append(candidate)
            if len(found) > _MAX_LOCKFILES:
                raise OsvCoverageError("supported lockfile count exceeded")
    return sorted(found, key=lambda path: path.relative_to(repository).as_posix())


def _snapshot_declared_lockfile(repository, relative, expected_sha256):
    """Read one declared lockfile via openat and enforce its immutable content digest."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(repository, flags)
    directory_fd = os.dup(root_fd)
    file_fd = None
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_LOCKFILE_BYTES:
            raise OsvCoverageError("supported lockfile boundary rejected")
        chunks, total = [], 0
        while True:
            chunk = os.read(file_fd, min(1024 * 1024, _MAX_LOCKFILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_LOCKFILE_BYTES:
                raise OsvCoverageError("supported lockfile boundary rejected")
        data = b"".join(chunks)
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise OsvCoverageError("dependency lockfile digest mismatch")
        return LockfileSnapshot(filename=relative.name, data=data,
                                device=metadata.st_dev, inode=metadata.st_ino)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
        os.close(root_fd)


def dependency_lockfile_snapshots(asset):
    """Capture every exact digest-bound lockfile using pinned directory fds."""
    snapshots = []
    try:
        for repository, declarations in dependency_artifacts(asset):
            for relative, digest in declarations:
                snapshots.append(_snapshot_declared_lockfile(repository, relative, digest))
    except OSError as exc:
        raise OsvCoverageError("dependency root changed during snapshot") from exc
    if len(snapshots) > _MAX_LOCKFILES:
        raise OsvCoverageError("combined dependency lockfile bound exceeded")
    identities = [(item.device, item.inode) for item in snapshots]
    if len(identities) != len(set(identities)):
        raise OsvCoverageError("duplicate dependency lockfile binding")
    return snapshots


def _materialize_lockfile(snapshot, scratch):
    scratch.mkdir(mode=0o700, parents=True, exist_ok=False)
    target = scratch / snapshot.filename
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(snapshot.data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return target


def osv_argv(binary, database_root, lockfile):
    return (str(binary), "scan", "source", "--local-db-path", str(database_root),
            "--offline", "--format=json", "--verbosity=error", "--lockfile", str(lockfile))


def _sandbox_literal(path):
    return str(Path(path).resolve(strict=True)).replace("\\", "\\\\").replace('"', '\\"')


def sandbox_profile(binary, database_root, lockfile, scratch):
    executable = _sandbox_literal(binary)
    database = _sandbox_literal(database_root)
    lock = _sandbox_literal(lockfile)
    scratch_path = _sandbox_literal(scratch)
    return "\n".join([
        "(version 1)", "(deny default)", '(import "system.sb")', "(deny network*)",
        '(deny file-read* (subpath "%s"))' % _sandbox_literal(Path.home()),
        '(deny file-write* (subpath "%s"))' % _sandbox_literal(Path.home()),
        '(allow process-exec (literal "%s"))' % executable,
        "(allow process-fork)", "(allow process-info*)",
        '(allow file-read* (literal "%s") (literal "%s") (subpath "%s") (subpath "%s"))' %
        (executable, lock, database, scratch_path),
        '(allow file-write* (subpath "%s"))' % scratch_path,
        "",
    ])


def _closed_string(value, maximum=512):
    return isinstance(value, str) and 0 < len(value) <= maximum and "\x00" not in value


def _severity(vulnerability):
    database_specific = vulnerability.get("database_specific", {})
    raw = database_specific.get("severity", "") if isinstance(database_specific, dict) else ""
    mapping = {"CRITICAL":"Critical", "HIGH":"High", "MODERATE":"Medium",
               "MEDIUM":"Medium", "LOW":"Low"}
    return mapping.get(str(raw).upper(), "Medium")


def parse_osv(raw, asset_id, run_id):
    if len(raw) > constants.OSV_OUTPUT_CAP or b"\x00" in raw:
        raise OsvOutputError("OSV output rejected")
    try:
        def closed_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate key")
                value[key] = item
            return value
        document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=closed_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise OsvOutputError("OSV output rejected") from exc
    if (not isinstance(document, dict) or "results" not in document or
            set(document) - {"results", "experimental_config"} or
            not isinstance(document["results"], list) or len(document["results"]) > 10000):
        raise OsvOutputError("OSV schema rejected")
    normalized = {}
    for result in document["results"]:
        if (not isinstance(result, dict) or set(result) - {"source", "packages"} or
                not isinstance(result.get("packages"), list) or len(result["packages"]) > 10000):
            raise OsvOutputError("OSV result schema rejected")
        for row in result["packages"]:
            if (not isinstance(row, dict) or
                    set(row) - {"package", "groups", "dependency_groups", "vulnerabilities"} or
                    not isinstance(row.get("package"), dict) or
                    set(row["package"]) - {"name", "version", "ecosystem", "commit"} or
                    not isinstance(row.get("dependency_groups", []), list) or
                    len(row.get("dependency_groups", [])) > 1000 or
                    not isinstance(row.get("vulnerabilities"), list) or
                    len(row["vulnerabilities"]) > 1000):
                raise OsvOutputError("OSV package schema rejected")
            package = row["package"]
            name, version, ecosystem = (package.get("name"), package.get("version"),
                                        package.get("ecosystem"))
            if (not _closed_string(name) or not _closed_string(version, 256) or
                    not _closed_string(ecosystem, 64)):
                raise OsvOutputError("OSV package identity rejected")
            for vulnerability in row["vulnerabilities"]:
                if not isinstance(vulnerability, dict):
                    raise OsvOutputError("OSV vulnerability schema rejected")
                advisory = vulnerability.get("id")
                if not isinstance(advisory, str) or not _ADVISORY_RE.fullmatch(advisory):
                    raise OsvOutputError("OSV advisory identity rejected")
                control = "dependency.osv." + advisory.lower()
                identity = hashlib.sha256((ecosystem + "\0" + name + "\0" + version).encode()).hexdigest()[:24]
                item = findings.make_finding(
                    "osv-offline", asset_id, control, _severity(vulnerability), "confirmed",
                    "dependency:" + identity, "upgrade-vulnerable-dependency", run_id,
                )
                # Source-derived package metadata has no approved disclosure contract.
                # Shape validation and token regexes cannot establish non-secret data.
                # Keep it transient for identity correlation, never copy it to findings.
                item.update({"advisory_id":advisory, "manifest_count":1})
                fp = item["fingerprint"]
                if fp in normalized:
                    normalized[fp]["manifest_count"] += 1
                else:
                    normalized[fp] = item
    return sorted(normalized.values(), key=lambda item: item["fingerprint"])


class OsvScanner:
    def __init__(self, release, scratch_root):
        self.release = release
        self.scratch_root = Path(scratch_root)

    def database_evidence(self):
        return {"osv_databases":json.loads(json.dumps(self.release.evidence, sort_keys=True))}

    def scan(self, asset, run_id, global_deadline=None):
        lockfiles = dependency_lockfile_snapshots(asset)
        findings_by_fp = {}
        for index, snapshot in enumerate(lockfiles):
            scratch = self.scratch_root / (run_id + "-" + asset["asset_id"] + "-osv-%d" % index)
            try:
                lockfile = _materialize_lockfile(snapshot, scratch)
                profile = sandbox_profile(self.release.binary, self.release.database_root,
                                          lockfile, scratch)
                raw = runner.execute_bounded(
                    osv_argv(self.release.binary, self.release.database_root, lockfile), profile,
                    timeout=constants.OSV_SCANNER_TIMEOUT, cwd=scratch,
                    global_deadline=global_deadline, allowed_returncodes=(0, 1),
                    output_cap=constants.OSV_OUTPUT_CAP,
                    rss_limit=constants.OSV_RSS_LIMIT_BYTES,
                )
                for item in parse_osv(raw, asset["asset_id"], run_id):
                    fp = item["fingerprint"]
                    if fp in findings_by_fp:
                        findings_by_fp[fp]["manifest_count"] += item.get("manifest_count", 1)
                    else:
                        findings_by_fp[fp] = item
            finally:
                try:
                    if scratch.exists():
                        shutil.rmtree(scratch)
                except OSError as exc:
                    raise OsvCoverageError("dependency scratch cleanup failed") from exc
                if scratch.exists():
                    raise OsvCoverageError("dependency scratch cleanup failed")
        return sorted(findings_by_fp.values(), key=lambda item: item["fingerprint"])
