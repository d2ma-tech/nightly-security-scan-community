"""Offline-only, digest-bound extraction into immutable private releases."""
import hashlib
import json
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import constants


class InstallIntegrityError(RuntimeError):
    pass


JSON_CAP = 16 * 1024
INSTALL_MANIFEST_KEYS = {"schema", "archive_name", "archive_bytes", "archive_sha256",
                         "binary_sha256", "network_access", "regular_files_only"}


def _read_regular_json(path, max_bytes=JSON_CAP):
    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise InstallIntegrityError("JSON file boundary violation")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size > max_bytes or
                    (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise InstallIntegrityError("JSON file changed during open")
            raw = bytearray()
            while len(raw) <= max_bytes:
                chunk = os.read(fd, min(65536, max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        finally:
            os.close(fd)
        if len(raw) > max_bytes:
            raise InstallIntegrityError("JSON file exceeds bound")
        def closed_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate key")
                value[key] = item
            return value
        value = json.loads(bytes(raw).decode("ascii"), object_pairs_hook=closed_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise InstallIntegrityError("invalid bounded JSON file") from exc
    if not isinstance(value, dict):
        raise InstallIntegrityError("JSON root is not an object")
    return value


def _read_install_manifest(release):
    manifest = _read_regular_json(Path(release) / "installation-manifest.json")
    if (set(manifest) != INSTALL_MANIFEST_KEYS or
            manifest.get("schema") != "daily-security-scan-offline-install-v1" or
            manifest.get("archive_name") != constants.GITLEAKS_ARCHIVE or
            manifest.get("archive_bytes") != constants.GITLEAKS_ARCHIVE_BYTES or
            manifest.get("archive_sha256") != constants.GITLEAKS_ARCHIVE_SHA256 or
            manifest.get("network_access") is not False or
            manifest.get("regular_files_only") is not True or
            not isinstance(manifest.get("binary_sha256"), str)):
        raise InstallIntegrityError("installation manifest contract mismatch")
    return manifest


def activate_release(releases_root, release):
    """Atomically point the data-only locator at a verified immutable direct child."""
    root, release = Path(releases_root), Path(release)
    if release.parent != root or release.is_symlink() or not release.is_dir():
        raise InstallIntegrityError("release locator boundary violation")
    manifest = _read_install_manifest(release)
    binary = release / "gitleaks"
    if (manifest.get("archive_sha256") != constants.GITLEAKS_ARCHIVE_SHA256 or
            manifest.get("binary_sha256") != sha256_file(binary) or binary.is_symlink()):
        raise InstallIntegrityError("release verification failed")
    locator = root / "release-locator.json"
    temporary = root / (".release-locator-" + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        json.dump({"schema":"daily-security-scan-release-locator-v1",
                   "release_directory":release.name}, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, locator)
    return locator


def resolve_active_binary(locator):
    locator = Path(locator)
    if locator.is_symlink() or not stat.S_ISREG(locator.lstat().st_mode):
        raise InstallIntegrityError("release locator invalid")
    value = _read_regular_json(locator)
    token = value.get("release_directory")
    if value.get("schema") != "daily-security-scan-release-locator-v1" or not isinstance(token, str):
        raise InstallIntegrityError("release locator schema invalid")
    if PurePosixPath(token).name != token:
        raise InstallIntegrityError("release locator path invalid")
    release = locator.parent / token
    try:
        release_mode = release.lstat().st_mode
    except OSError as exc:
        raise InstallIntegrityError("active release absent") from exc
    if stat.S_ISLNK(release_mode) or not stat.S_ISDIR(release_mode):
        raise InstallIntegrityError("active release directory invalid")
    manifest = _read_install_manifest(release)
    binary = release / "gitleaks"
    if (release.is_symlink() or binary.is_symlink() or not binary.is_file() or
            manifest.get("archive_sha256") != constants.GITLEAKS_ARCHIVE_SHA256 or
            manifest.get("binary_sha256") != sha256_file(binary)):
        raise InstallIntegrityError("active release integrity mismatch")
    return binary


@dataclass(frozen=True)
class ArchiveContract:
    name: str
    size: int
    sha256: str


PRODUCTION_CONTRACT = ArchiveContract(constants.GITLEAKS_ARCHIVE, constants.GITLEAKS_ARCHIVE_BYTES,
                                      constants.GITLEAKS_ARCHIVE_SHA256)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(name):
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and len(p.parts) == 1


def install_offline_archive(archive, releases_root, contract=PRODUCTION_CONTRACT):
    archive = Path(archive)
    if archive.name != contract.name:
        raise InstallIntegrityError("archive name mismatch")
    try:
        size = archive.lstat().st_size
        mode = archive.lstat().st_mode
    except FileNotFoundError as exc:
        raise InstallIntegrityError("archive absent") from exc
    if not stat.S_ISREG(mode) or size != contract.size or sha256_file(archive) != contract.sha256:
        raise InstallIntegrityError("archive integrity mismatch")
    root = Path(releases_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    release = root / ("gitleaks-v" + constants.GITLEAKS_VERSION + "-" + contract.sha256[:16])
    if release.exists():
        raise InstallIntegrityError("immutable release already exists")
    staging = root / (".install-" + contract.sha256[:16])
    staging.mkdir(mode=0o700)
    try:
        with tarfile.open(archive, mode="r:gz") as tf:
            members = tf.getmembers()
            if not members or len(members) > 16:
                raise InstallIntegrityError("archive member count invalid")
            names = set()
            for member in members:
                if not member.isfile() or not _safe_name(member.name) or member.name in names:
                    raise InstallIntegrityError("archive contains unsafe member")
                names.add(member.name)
                source = tf.extractfile(member)
                if source is None:
                    raise InstallIntegrityError("archive member unreadable")
                target = staging / member.name
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as out:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(65536, remaining))
                        if not chunk:
                            raise InstallIntegrityError("truncated member")
                        out.write(chunk)
                        remaining -= len(chunk)
                    if source.read(1):
                        raise InstallIntegrityError("member overflow")
                    out.flush()
                    os.fsync(out.fileno())
            if "gitleaks" not in names:
                raise InstallIntegrityError("gitleaks binary absent")
        os.chmod(staging / "gitleaks", 0o500)
        install_record = {"schema":"daily-security-scan-offline-install-v1",
                          "archive_name":contract.name, "archive_bytes":contract.size,
                          "archive_sha256":contract.sha256,
                          "binary_sha256":sha256_file(staging / "gitleaks"),
                          "network_access":False, "regular_files_only":True}
        manifest_path = staging / "installation-manifest.json"
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o400)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            json.dump(install_record, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for child in staging.iterdir():
            if child.name != "gitleaks":
                os.chmod(child, 0o400)
        os.replace(staging, release)
        os.chmod(release, 0o500)
        return release
    except Exception:
        # Staging contains only verified archive members and remains private evidence on failure.
        raise
