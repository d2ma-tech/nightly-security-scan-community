"""Deterministic orchestration; scanners supply content only inside this envelope."""
import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import collectors, constants, findings, inventory, locking, reports, state

NO_AGENT = True
GLOBAL_DEADLINE_SECONDS = constants.GLOBAL_TIMEOUT
NO_NEW_WORK_HOUR = (3, 15)
KILL_HOUR = (3, 20)


class FakeScanner:
    """Synthetic-test scanner. Never accesses repository contents."""
    def __init__(self, results):
        self.results = results
        self.calls = []

    def scan(self, asset, run_id, global_deadline=None):
        self.calls.append(asset["asset_id"])
        return [dict(item) for item in self.results.get(asset["asset_id"], [])]


def _utc(now):
    value = now() if callable(now) else datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _run_id(value):
    return value.strftime("%Y%m%dT%H%M%S.%fZ")


def _read_previous(path):
    try:
        value = json.loads(Path(path).read_text(encoding="ascii"))
        return {item["fingerprint"]: item for item in value.get("findings", [])}
    except FileNotFoundError:
        return {}


def _read_lifecycle_anchor(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("invalid lifecycle anchor")
        with os.fdopen(fd, "r", encoding="ascii") as stream:
            fd = None
            value = json.load(stream)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid lifecycle anchor") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if (not isinstance(value, dict) or set(value) != {"schema", "event_count", "head_hash"} or
            value.get("schema") != "daily-security-scan-lifecycle-anchor-v1" or
            not isinstance(value.get("event_count"), int) or isinstance(value.get("event_count"), bool) or
            value["event_count"] < 0 or not isinstance(value.get("head_hash"), str) or
            len(value["head_hash"]) != 64 or
            any(c not in "0123456789abcdef" for c in value["head_hash"])):
        raise ValueError("invalid lifecycle anchor")
    return value


def _anchor_matches(anchor, snapshot):
    if anchor is None:
        return True
    count = anchor["event_count"]
    if count > snapshot["event_count"]:
        return False
    anchored_head = "0" * 64 if count == 0 else snapshot["event_hashes"][count - 1]
    return anchored_head == anchor["head_hash"]


def _cutoff_allows(value):
    local = value.astimezone(ZoneInfo("UTC"))
    return (local.hour, local.minute) < NO_NEW_WORK_HOUR


def _absolute_deadline(started_dt, started_mono, enforce_schedule):
    deadline = started_mono + GLOBAL_DEADLINE_SECONDS
    if enforce_schedule:
        local = started_dt.astimezone(ZoneInfo("UTC"))
        kill = local.replace(hour=KILL_HOUR[0], minute=KILL_HOUR[1], second=0, microsecond=0)
        deadline = min(deadline, started_mono + max(0.0, (kill - local).total_seconds()))
    return deadline


def run(inv, state_root, scanner, dependency_scanner=None,
        host_collector=collectors.collect_host, now=None,
        enforce_schedule=False, lifecycle_eligible=True, run_type="eligible-run",
        lock_factory=locking.RunLock):
    allowed_modes = {"eligible-run": True, "natural-scheduled": True,
                     "manual-verification": False}
    if (not isinstance(lifecycle_eligible, bool) or run_type not in allowed_modes or
            allowed_modes[run_type] is not lifecycle_eligible):
        raise ValueError("run lifecycle mode contract rejected")
    os.umask(0o077)
    started_dt = _utc(now)
    started_mono = time.monotonic()
    global_deadline = _absolute_deadline(started_dt, started_mono, enforce_schedule)
    run_id = _run_id(started_dt)
    root = Path(state_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    lock = lock_factory(root / "scan.lock")
    try:
        lock.acquire()
    except locking.LockHeld:
        locked = state.StateMachine()
        locked.transition("LOCKED")
        attempts = state.HashChainLog(root / "lock-attempts.jsonl")
        attempts.append({"type":"state", "run_id":run_id, "state":locked.current})
        if not attempts.verify():
            return {"status":"INTEGRITY_FAILURE", "asset_count":0, "run_id":run_id,
                    "stdout":""}
        return {"status":locked.current, "asset_count":0, "run_id":run_id, "stdout":""}
    sm = state.StateMachine()
    events = state.HashChainLog(root / "events.jsonl")
    run_dir = None
    lifecycle_guard = None
    try:
        events.append({"type":"state", "run_id":run_id, "state":"PRECHECK"})
        if not events.verify():
            sm.transition("INTEGRITY_FAILURE")
            return {"status":sm.current, "asset_count":0, "run_id":run_id, "stdout":""}
        if enforce_schedule and not _cutoff_allows(started_dt):
            sm.transition("INCOMPLETE")
            events.append({"type":"state", "run_id":run_id, "state":sm.current,
                           "reason":"no-new-work-cutoff"})
            return {"status":sm.current, "asset_count":0, "run_id":run_id, "stdout":""}
        assets = inv.get("assets")
        if not isinstance(assets, list):
            sm.transition("INTEGRITY_FAILURE")
            return {"status":sm.current, "asset_count":0, "run_id":run_id, "stdout":""}
        run_dir = reports.create_run_dir(root / "runs", run_id)
        sm.transition("RUNNING")
        events.append({"type":"state", "run_id":run_id, "state":sm.current})
        observed, coverage, failures = [], [], []
        host_assets = [a for a in assets if a.get("asset_class") == "host"]
        if len(host_assets) != 1:
            failures.append("host-inventory")
            host_data = {}
        else:
            try:
                host_data, host_failures = host_collector()
                observed.extend(collectors.posture_findings(host_data, host_assets[0]["asset_id"], run_id))
                coverage.append({"asset_id":host_assets[0]["asset_id"],
                                 "status":"complete" if not host_failures else "incomplete"})
                failures.extend("host:" + str(item) for item in host_failures)
            except Exception:
                host_data = {}
                coverage.append({"asset_id":host_assets[0]["asset_id"], "status":"incomplete"})
                failures.append("host:collector")
        repos = [a for a in assets if a.get("asset_class") == "source-repository-local"]
        for asset in repos:
            if enforce_schedule and not _cutoff_allows(_utc(now)):
                failures.append(asset.get("asset_id", "unknown") + ":no-new-work-cutoff")
                coverage.append({"asset_id":asset.get("asset_id", "unknown"), "status":"incomplete"})
                continue
            if time.monotonic() >= global_deadline:
                failures.append(asset.get("asset_id", "unknown") + ":global-deadline")
                coverage.append({"asset_id":asset.get("asset_id", "unknown"), "status":"incomplete"})
                continue
            asset_id = asset.get("asset_id", "unknown")
            try:
                inventory.validate_repository_root(Path(asset["path"]))
                batch = scanner.scan(asset, run_id, global_deadline)
                if not isinstance(batch, list):
                    raise ValueError("scanner contract")
                observed.extend(batch)
                if "osv-offline-lockfiles" in asset.get("methods", []):
                    if dependency_scanner is None:
                        raise ValueError("required dependency scanner absent")
                    for dependency_artifact in asset.get("dependency_artifacts", []):
                        inventory.validate_repository_root(Path(dependency_artifact["path"]))
                    dependency_batch = dependency_scanner.scan(asset, run_id, global_deadline)
                    if not isinstance(dependency_batch, list):
                        raise ValueError("dependency scanner contract")
                    observed.extend(dependency_batch)
                coverage.append({"asset_id":asset_id, "status":"complete"})
            except Exception:
                failures.append(asset_id + ":scanner-or-coverage")
                coverage.append({"asset_id":asset_id, "status":"incomplete"})
        if len(coverage) != len(assets):
            failures.append("asset-accounting")
        sm.transition("FINALIZING")
        events.append({"type":"state", "run_id":run_id, "state":sm.current})
        previous = _read_previous(root / "findings-snapshot.json")
        lifecycle_log = state.HashChainLog(root / "finding-lifecycle-events.jsonl",
                                           event_validator=findings.validate_event)
        lifecycle_guard = lifecycle_log.acquire_guard()
        try:
            lifecycle_snapshot = lifecycle_log.verified_snapshot()
            lifecycle_before = lifecycle_snapshot["events"]
            lifecycle_anchor = _read_lifecycle_anchor(root / "finding-lifecycle-anchor.json")
            if not _anchor_matches(lifecycle_anchor, lifecycle_snapshot):
                raise ValueError("lifecycle history rollback detected")
        except ValueError:
            sm.transition("INTEGRITY_FAILURE")
            events.append({"type":"state", "run_id":run_id, "state":sm.current,
                           "reason":"finding-lifecycle-integrity"})
            return {"status":sm.current, "asset_count":len(assets), "run_id":run_id,
                    "stdout":""}
        existing_event_keys = {findings.event_identity(event) for event in lifecycle_before}
        committed_count = lifecycle_anchor["event_count"] if lifecycle_anchor is not None else 0
        uncommitted_tail = lifecycle_before[committed_count:]
        tail_episode_types = {(event["fingerprint"], event["event_type"],
                               event["recurrence_number"]) for event in uncommitted_tail}
        lifecycle_run_eligible = bool(not failures and lifecycle_eligible)
        bootstrap = (findings.bootstrap_events(previous, existing_event_keys, run_id)
                     if lifecycle_run_eligible else [])
        if lifecycle_run_eligible:
            current = findings.apply_lifecycle(previous, observed, run_id, eligible=True)
            transitions = findings.transition_events(previous, current, observed, run_id,
                                                     eligible=True)
        elif not failures and run_type == "manual-verification":
            current = findings.preview_lifecycle(previous, observed, run_id)
            transitions = []
        else:
            current = findings.apply_lifecycle(previous, observed, run_id, eligible=False)
            transitions = []
        pending_events = []
        for event in bootstrap + transitions:
            key = findings.event_identity(event)
            episode_type = (event["fingerprint"], event["event_type"],
                            event["recurrence_number"])
            if key not in existing_event_keys and episode_type not in tail_episode_types:
                pending_events.append(event)
                existing_event_keys.add(key)
                tail_episode_types.add(episode_type)
        for event in pending_events:
            lifecycle_log.append(event, guard_fd=lifecycle_guard)
        try:
            lifecycle_after = lifecycle_log.verified_snapshot()
            if not _anchor_matches(lifecycle_anchor, lifecycle_after):
                raise ValueError("lifecycle history changed below committed prefix")
            lifecycle_current = lifecycle_after["events"]
        except ValueError:
            sm.transition("INTEGRITY_FAILURE")
            events.append({"type":"state", "run_id":run_id, "state":sm.current,
                           "reason":"finding-lifecycle-write-integrity"})
            return {"status":sm.current, "asset_count":len(assets), "run_id":run_id,
                    "stdout":""}
        final = "COMPLETE" if not failures else "INCOMPLETE"
        sm.transition(final)
        ended = _utc(now)
        ended_text = ended.isoformat().replace("+00:00", "Z")
        report_token = "runs/%s/report.html" % run_id
        module_evidence = (dependency_scanner.database_evidence()
                           if dependency_scanner is not None else None)
        summary = reports.make_summary(run_id, final, ended_text, list(current.values()), failures,
                                       report_token, run_type=run_type,
                                       lifecycle_eligible=lifecycle_eligible,
                                       module_evidence=module_evidence)
        reports.atomic_json(run_dir / "run.json", {"schema_version":constants.SCHEMA_VERSION,
                            "run_id":run_id, "state":final, "started_at":started_dt.isoformat(),
                            "ended_at":ended_text, "run_type":run_type,
                            "lifecycle_eligible":lifecycle_eligible})
        reports.atomic_json(run_dir / "coverage.json", {"assets":coverage, "failures":sorted(failures),
                            "expected_asset_count":len(assets)})
        reports.atomic_json(run_dir / "findings.json", {"findings":sorted(current.values(), key=lambda x:x["fingerprint"])})
        reports.atomic_json(run_dir / "summary.json", summary)
        reports.atomic_json(run_dir / "receipts.json", {"production_access":False,
                            "network_access":False, "credentials_used":False,
                            "mutation_performed":False, "raw_output_persisted":False,
                            "host_posture_collected":bool(host_data), "event_chain_verified":events.verify(),
                            "run_type":run_type, "lifecycle_eligible":lifecycle_eligible})
        reports.write_html(run_dir / "report.html", summary,
                           sorted(current.values(), key=lambda x:x["fingerprint"]), coverage,
                           lifecycle_events=lifecycle_current)
        events.append({"type":"state", "run_id":run_id, "state":final})
        if not events.verify():
            return {"status":"INTEGRITY_FAILURE", "asset_count":len(assets), "run_id":run_id, "stdout":""}
        if lifecycle_run_eligible:
            reports.atomic_json(root / "findings-snapshot.json",
                                {"findings":sorted(current.values(), key=lambda x:x["fingerprint"])})
        if final == "COMPLETE" and lifecycle_eligible:
            reports.atomic_json(root / "finding-lifecycle-anchor.json",
                                {"schema":"daily-security-scan-lifecycle-anchor-v1",
                                 "event_count":lifecycle_after["event_count"],
                                 "head_hash":lifecycle_after["head_hash"]})
            reports.atomic_json(root / "latest-successful.json", {"run_id":run_id,
                                "summary_token":report_token.replace("report.html", "summary.json")})
        known = set(previous)
        stdout = reports.alert_stdout(list(current.values()), known) if final == "COMPLETE" else ""
        return {"status":final, "asset_count":len(assets), "run_id":run_id, "stdout":stdout,
                "test_findings_count":len(observed)}
    finally:
        if lifecycle_guard is not None:
            state.HashChainLog.release_guard(lifecycle_guard)
        lock.release()


def run_bound(inventory_path, state_root, scanner, dependency_scanner=None, now=None):
    inv = inventory.load_bound_inventory(inventory_path)
    return run(inv, state_root, scanner, dependency_scanner=dependency_scanner,
               now=now, enforce_schedule=True,
               lifecycle_eligible=True, run_type="natural-scheduled")


def run_manual_verification(inventory_path, state_root, scanner, dependency_scanner=None, now=None):
    inv = inventory.load_bound_inventory(inventory_path)
    return run(inv, state_root, scanner, dependency_scanner=dependency_scanner,
               now=now, enforce_schedule=False,
               lifecycle_eligible=False, run_type="manual-verification")
