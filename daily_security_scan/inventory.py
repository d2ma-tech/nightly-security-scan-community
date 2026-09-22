"""Exact inventory binding and repository path boundary checks."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from . import constants


class InventoryIntegrityError(RuntimeError):
    pass


class CoverageError(RuntimeError):
    pass


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def load_bound_inventory(path):
    if constants.INVENTORY_SHA256 is None:
        raise InventoryIntegrityError("inventory binding not provisioned")
    path = Path(path)
    data = path.read_bytes()
    if _digest(data) != constants.INVENTORY_SHA256:
        raise InventoryIntegrityError("inventory digest mismatch")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryIntegrityError("invalid inventory encoding") from exc
    assets = value.get("assets")
    if value.get("schema") != constants.INVENTORY_SCHEMA or not isinstance(assets, list):
        raise InventoryIntegrityError("inventory schema mismatch")
    repos = [a for a in assets if a.get("asset_class") == "source-repository-local"]
    hosts = [a for a in assets if a.get("asset_class") == "host"]
    if len(assets) != constants.ASSET_COUNT or len(repos) != constants.REPOSITORY_COUNT or len(hosts) != 1:
        raise InventoryIntegrityError("inventory cardinality mismatch")
    ids = [a.get("asset_id") for a in assets]
    allowed_methods = {
        "host": (["native-read-only-posture", "listener-metadata"],),
        "source-repository-local": (
            ["gitleaks-redacted-no-git"],
            ["gitleaks-redacted-no-git", "osv-offline-lockfiles"],
        ),
    }
    asset_keys = {"asset_id", "asset_class", "path", "methods", "production_enabled"}
    def valid_asset(asset):
        if not isinstance(asset, dict):
            return False
        asset_class = asset.get("asset_class")
        has_dependency_scan = "osv-offline-lockfiles" in asset.get("methods", [])
        expected_keys = (asset_keys | {"dependency_artifacts"}
                         if has_dependency_scan else asset_keys)
        if (set(asset) != expected_keys or asset_class not in allowed_methods or
                asset.get("methods") not in allowed_methods[asset_class]):
            return False
        if has_dependency_scan:
            artifacts = asset.get("dependency_artifacts")
            if (not isinstance(artifacts, list) or not artifacts or
                    len(artifacts) > constants.MAX_DEPENDENCY_ROOTS):
                return False
            paths = []
            for artifact in artifacts:
                if not isinstance(artifact, dict) or set(artifact) != {"path", "lockfiles"}:
                    return False
                path, lockfiles = artifact.get("path"), artifact.get("lockfiles")
                if not isinstance(path, str) or not Path(path).is_absolute():
                    return False
                if not isinstance(lockfiles, list) or not lockfiles:
                    return False
                relative_paths = []
                for lockfile in lockfiles:
                    if (not isinstance(lockfile, dict) or
                            set(lockfile) != {"relative_path", "sha256"}):
                        return False
                    relative, digest = lockfile.get("relative_path"), lockfile.get("sha256")
                    relative_path = Path(relative) if isinstance(relative, str) else Path("/")
                    if (not isinstance(relative, str) or relative_path.is_absolute() or
                            ".." in relative_path.parts or not relative_path.parts or
                            not isinstance(digest, str) or
                            not re.fullmatch(r"[0-9a-f]{64}", digest)):
                        return False
                    relative_paths.append(relative)
                if len(relative_paths) != len(set(relative_paths)):
                    return False
                paths.append(path)
            if len(paths) != len(set(paths)):
                return False
        return True
    if (len(set(ids)) != len(ids) or not all(a.get("production_enabled") is True for a in assets) or
            any(not valid_asset(a) for a in assets)):
        raise InventoryIntegrityError("inventory asset binding mismatch")
    return value


def validate_repository_root(path):
    path = Path(path)
    if not path.is_absolute():
        raise CoverageError("repository root is not absolute")
    # Check every existing component with lstat; realpath alone is vulnerable to hidden links.
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise CoverageError("repository root missing") from exc
        if stat.S_ISLNK(mode):
            raise CoverageError("repository path contains symlink")
    if not stat.S_ISDIR(path.stat().st_mode):
        raise CoverageError("repository root is not a directory")
    if os.path.realpath(str(path)) != str(path):
        raise CoverageError("repository root is not canonical")
    return path
