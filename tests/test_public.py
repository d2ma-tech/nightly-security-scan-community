"""Isolated synthetic acceptance checks; subprocess and sockets forbidden."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack

import demo
from daily_security_scan import constants, findings, inventory, locking, reports, runner, state


class PublicSyntheticTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket", "os.system"):
            self.stack.enter_context(mock.patch(target, side_effect=AssertionError("external operation forbidden")))

    def test_demo_real_engine_report_and_private_permissions(self):
        result = demo.run_demo(self.root)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["asset_count"], 2)
        report = Path(result["report"])
        text = report.read_text()
        self.assertIn("SYNTHETIC DEMO", text)
        self.assertIn("Content-Security-Policy", text)
        self.assertNotIn("<script", text)
        summary = json.loads(report.with_name("summary.json").read_text())
        self.assertTrue(summary["synthetic_demo"])
        self.assertEqual(summary["counts_by_severity"]["High"], 1)
        self.assertEqual(summary["counts_by_severity"]["Medium"], 1)
        self.assertFalse(summary["lifecycle_eligible"])
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertFalse((report.parents[2] / "latest-successful.json").exists())
        self.assertTrue(state.HashChainLog(report.parents[2] / "events.jsonl").verify())

    def test_inventory_unconfigured_fails_before_read(self):
        with self.assertRaisesRegex(inventory.InventoryIntegrityError, "not provisioned"):
            inventory.load_bound_inventory(self.root / "absent.json")

    def test_synthetic_exact_binding_rejects_changed_bytes(self):
        value = {"schema": constants.INVENTORY_SCHEMA, "assets": [
            {"asset_id": "synthetic-host", "asset_class": "host", "path": "/",
             "methods": ["native-read-only-posture", "listener-metadata"], "production_enabled": True},
            {"asset_id": "synthetic-repo", "asset_class": "source-repository-local", "path": str(self.root),
             "methods": ["gitleaks-redacted-no-git"], "production_enabled": True}]}
        raw = json.dumps(value).encode()
        path = self.root / "synthetic-inventory.json"
        path.write_bytes(raw)
        with mock.patch.multiple(constants, INVENTORY_SHA256=hashlib.sha256(raw).hexdigest(),
                                 ASSET_COUNT=2, REPOSITORY_COUNT=1):
            self.assertEqual(inventory.load_bound_inventory(path), value)
            path.write_bytes(raw + b" ")
            with self.assertRaises(inventory.InventoryIntegrityError):
                inventory.load_bound_inventory(path)

    def test_symlink_repository_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(inventory.CoverageError):
            inventory.validate_repository_root(link)

    def test_secret_parser_strips_synthetic_canary_and_path(self):
        raw = json.dumps([{"RuleID": "generic-api-key", "File": "/synthetic/repo/config.json",
                           "Secret": "SYNTHETIC-CANARY-NOT-A-SECRET", "StartLine": 1}]).encode()
        value = runner.parse_gitleaks(raw, "synthetic-repo", "run-1")
        self.assertEqual(len(value), 1)
        self.assertNotIn("SYNTHETIC-CANARY", json.dumps(value))
        self.assertNotIn("/synthetic/repo", json.dumps(value))
        with self.assertRaises(runner.ScannerOutputError):
            runner.parse_gitleaks(b'[{"RuleID":"a","RuleID":"b","File":"f"}]', "repo", "run")

    def test_sandbox_preserves_denies_and_escapes_home(self):
        with mock.patch.object(Path, "home", return_value=Path('/synthetic/user"quoted')):
            profile = runner.sandbox_profile(self.root, self.root, self.root / "binary")
        self.assertIn('(deny network*)', profile)
        self.assertIn('(deny default)', profile)
        self.assertIn('user\\"quoted', profile)
        self.assertIn('(allow file-write* (subpath', profile)

    def test_hash_chain_rejects_tamper(self):
        path = self.root / "events.jsonl"
        log = state.HashChainLog(path)
        log.append({"synthetic": True})
        self.assertTrue(log.verify())
        path.write_text(path.read_text().replace('true', 'false'))
        self.assertFalse(log.verify())

    def test_live_lock_and_terminal_state_fail_closed(self):
        first = demo.synthetic_lock(self.root / "scan.lock")
        second = demo.synthetic_lock(self.root / "scan.lock")
        first.acquire()
        try:
            with self.assertRaises(locking.LockHeld):
                second.acquire()
        finally:
            first.release()
        machine = state.StateMachine()
        machine.transition("INCOMPLETE")
        with self.assertRaises(state.InvalidTransition):
            machine.transition("COMPLETE")

    def test_seven_absences_and_recurrence(self):
        item = findings.make_finding("synthetic", "repo", "example", "High", "confirmed", "none", "review", "run-1")
        fp = item["fingerprint"]
        current = findings.apply_lifecycle({}, [item], "run-1", True)
        for index in range(6):
            current = findings.apply_lifecycle(current, [], "clean-%d" % index, True)
        self.assertEqual(current[fp]["status"], "open")
        current = findings.apply_lifecycle(current, [], "clean-7", True)
        self.assertEqual(current[fp]["status"], "resolved")
        current = findings.apply_lifecycle(current, [item], "recurred", True)
        self.assertEqual(current[fp]["recurrence_count"], 1)


if __name__ == "__main__":
    unittest.main()
