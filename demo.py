"""SYNTHETIC OFFLINE DEMO. No host inspection or external scanner execution."""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from daily_security_scan import engine, findings, locking


def synthetic_host():
    """Invented posture, not measurements of the running machine."""
    return {"sip": "enabled", "gatekeeper": "enabled", "filevault": "enabled",
            "firewall": "disabled", "stealth": "enabled", "listeners": []}, []


class SyntheticScanner:
    def scan(self, asset, run_id, global_deadline=None):
        return [findings.make_finding(
            "synthetic-demo", asset["asset_id"], "synthetic.example", "High",
            "confirmed", "synthetic-only", "review-synthetic-example", run_id)]


class synthetic_lock(locking.RunLock):
    # Uses the real exclusive lock and file controls, never the live process probe.
    # Safe ONLY inside a newly created, single-process synthetic demo directory.
    def __init__(self, path):
        super().__init__(path, process_probe=lambda pid: "synthetic-process")


def run_demo(parent=None):
    """Create a fresh isolated demo; parent chooses only where that directory lives."""
    root = Path(tempfile.mkdtemp(prefix="synthetic-security-demo-", dir=parent)).resolve()
    repo = root / "synthetic-repository"
    repo.mkdir()
    inv = {"assets": [
        {"asset_id": "synthetic-host", "asset_class": "host"},
        {"asset_id": "synthetic-repository", "asset_class": "source-repository-local",
         "path": str(repo)},
    ]}
    result = engine.run(
        inv, root / "synthetic-state", SyntheticScanner(),
        host_collector=synthetic_host, lock_factory=synthetic_lock,
        now=lambda: datetime(2000, 1, 1, tzinfo=timezone.utc),
        enforce_schedule=False, lifecycle_eligible=False, run_type="manual-verification",
    )
    run_dir = root / "synthetic-state/runs" / result["run_id"]
    report = run_dir / "report.html"
    # Make every standalone generated artifact visibly synthetic without changing
    # the production report renderer or fabricating an engine result.
    if report.exists():
        from daily_security_scan import reports
        document = report.read_text()
        document = document.replace("<h1>Security scan report</h1>",
            "<h1>SYNTHETIC DEMO — NOT A HOST SCAN</h1>")
        reports.atomic_bytes(report, document.encode())
        for name in ("run.json", "coverage.json", "findings.json", "summary.json", "receipts.json"):
            path = run_dir / name
            value = json.loads(path.read_text())
            value["synthetic_demo"] = True
            reports.atomic_json(path, value)
    return {"synthetic_demo": True, "status": result["status"],
            "asset_count": result["asset_count"], "report": str(report), "root": str(root)}


if __name__ == "__main__":
    result = run_demo()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "COMPLETE" else 1)
