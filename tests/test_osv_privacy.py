"""B1 synthetic metadata counterexamples through real persistence/reporting."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import demo
from daily_security_scan import engine, osv


class OsvMetadataPrivacyTests(unittest.TestCase):
    def check_metadata(self, field, canary):
        with tempfile.TemporaryDirectory(prefix="synthetic-osv-privacy-") as directory:
            root = Path(directory).resolve()
            repo = root / "synthetic-repository"
            repo.mkdir()
            package = {"name": "synthetic-package", "version": "1.0.0", "ecosystem": "npm"}
            package[field] = canary
            raw = json.dumps({"results": [{"source": {}, "packages": [{
                "package": package, "vulnerabilities": [{"id": "GHSA-35JH-R3H4-6JHM"}]
            }]}]}).encode()

            class EmptyScanner:
                def scan(self, *args):
                    return []

            class SyntheticOsvScanner:
                def scan(self, asset, run_id, global_deadline=None):
                    return osv.parse_osv(raw, asset["asset_id"], run_id)

                def database_evidence(self):
                    return {}

            result = engine.run(
                {"assets": [{"asset_id": "synthetic-host", "asset_class": "host"},
                            {"asset_id": "synthetic-repository",
                             "asset_class": "source-repository-local", "path": str(repo),
                             "methods": ["osv-offline-lockfiles"]}]},
                root / "state", EmptyScanner(), dependency_scanner=SyntheticOsvScanner(),
                host_collector=demo.synthetic_host, lock_factory=demo.synthetic_lock,
                now=lambda: datetime(2000, 1, 1, tzinfo=timezone.utc),
                enforce_schedule=False, lifecycle_eligible=True,
            )
            self.assertEqual(result["status"], "COMPLETE")
            run_dir = root / "state/runs" / result["run_id"]
            persisted = json.loads((run_dir / "findings.json").read_text())["findings"]
            persisted = [item for item in persisted if item["module_id"] == "osv-offline"]
            self.assertEqual(len(persisted), 1)
            self.assertEqual(persisted[0]["advisory_id"], "GHSA-35JH-R3H4-6JHM")
            # Separate subtests ensure both JSON and HTML are checked even on failure.
            for suffix in (".json", ".html"):
                with self.subTest(field=field, canary=canary, artifact=suffix):
                    paths = sorted((root / "state").rglob("*" + suffix))
                    self.assertTrue(paths)
                    text = "\n".join(path.read_text() for path in paths)
                    self.assertIn("GHSA-35JH-R3H4-6JHM", text)
                    self.assertNotIn(canary, text)
                    for key in ("package_name", "package_version", "package_ecosystem"):
                        self.assertNotIn(key, text)


def _case(field, canary):
    def test(self):
        self.check_metadata(field, canary)
    return test


for _field in ("name", "version", "ecosystem"):
    for _kind, _canary in (
        ("path", "file:/private/synthetic-canary/package"),
        ("credential", "SYNTHETIC-CREDENTIAL-CANARY-NOT-A-SECRET"),
    ):
        setattr(OsvMetadataPrivacyTests, "test_" + _field + "_" + _kind, _case(_field, _canary))
