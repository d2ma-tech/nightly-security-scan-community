import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from daily_security_scan import constants, findings, osv, reports


class TempCase(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()

    def tearDown(self):
        self.td.cleanup()


class OsvReleaseTests(TempCase):
    def test_resolve_release_is_digest_bound_and_symlink_safe(self):
        binary_data = b"synthetic-osv-binary"
        database_data = b"synthetic-osv-database"
        contract = osv.OsvReleaseContract(
            version="test-1",
            binary_bytes=len(binary_data),
            binary_sha256=hashlib.sha256(binary_data).hexdigest(),
            databases=(osv.OsvDatabaseContract(
                ecosystem="npm", relative_path="osv-scalibr/npm/all.zip",
                bytes=len(database_data), sha256=hashlib.sha256(database_data).hexdigest(),
                source_url="https://example.invalid/npm/all.zip",
                last_modified="2026-08-25T04:33:55Z",
            ),),
        )
        releases = self.root / "releases"
        release = releases / "osv-test-release"
        database = release / "database" / "osv-scalibr" / "npm"
        database.mkdir(parents=True)
        (release / "osv-scanner").write_bytes(binary_data)
        os.chmod(release / "osv-scanner", 0o500)
        (database / "all.zip").write_bytes(database_data)
        manifest = osv.release_manifest(contract)
        (release / "installation-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        releases.mkdir(exist_ok=True)
        locator = releases / "osv-release-locator.json"
        locator.write_text(json.dumps({
            "schema":"daily-security-scan-osv-release-locator-v1",
            "release_directory":release.name,
        }), encoding="ascii")
        resolved = osv.resolve_release(locator, contract=contract)
        self.assertEqual(resolved.binary, release / "osv-scanner")
        self.assertEqual(resolved.database_root, release / "database")
        self.assertEqual(resolved.evidence["npm"]["sha256"], contract.databases[0].sha256)
        (database / "all.zip").unlink()
        (database / "all.zip").symlink_to(self.root / "outside.zip")
        with self.assertRaises(osv.OsvReleaseIntegrityError):
            osv.resolve_release(locator, contract=contract)


class OsvParserTests(TempCase):
    def _raw(self, severity="HIGH"):
        return json.dumps({
            "experimental_config":{},
            "results":[{
                "source":{"path":"/private/repository/package-lock.json"},
                "packages":[{
                    "package":{"name":"lodash", "version":"4.17.20", "ecosystem":"npm"},
                    "groups":[],
                    "vulnerabilities":[{
                        "id":"GHSA-35JH-R3H4-6JHM",
                        "database_specific":{"severity":severity},
                        "severity":[],
                    }],
                }],
            }],
        }).encode()

    def test_parser_retains_advisory_but_omits_unapproved_package_metadata(self):
        items = osv.parse_osv(self._raw(), "repo-one", "run-1")
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["module_id"], "osv-offline")
        self.assertEqual(item["severity"], "High")
        self.assertEqual(item["advisory_id"], "GHSA-35JH-R3H4-6JHM")
        for key in ("package_name", "package_version", "package_ecosystem"):
            self.assertNotIn(key, item)
        persisted = json.dumps(items)
        self.assertNotIn("/private/repository", persisted)
        self.assertNotIn("source", persisted)

    def test_parser_accepts_v251_dependency_groups_without_persisting_them(self):
        value = json.loads(self._raw())
        value["results"][0]["packages"][0]["dependency_groups"] = ["dev"]
        items = osv.parse_osv(json.dumps(value).encode(), "repo", "run")
        self.assertEqual(len(items), 1)
        self.assertNotIn("dependency_groups", json.dumps(items))

    def test_parser_maps_closed_severity_and_rejects_unknown_schema(self):
        expected = {"CRITICAL":"Critical", "HIGH":"High", "MODERATE":"Medium",
                    "MEDIUM":"Medium", "LOW":"Low", "UNKNOWN":"Medium"}
        for raw_value, normalized in expected.items():
            with self.subTest(raw_value=raw_value):
                self.assertEqual(osv.parse_osv(self._raw(raw_value), "repo", "run")[0]["severity"],
                                 normalized)
        value = json.loads(self._raw())
        value["results"][0]["packages"][0]["mystery"] = True
        with self.assertRaises(osv.OsvOutputError):
            osv.parse_osv(json.dumps(value).encode(), "repo", "run")

    def test_clean_output_has_no_findings(self):
        raw = json.dumps({"experimental_config":{}, "results":[]}).encode()
        self.assertEqual(osv.parse_osv(raw, "repo", "run"), [])


class OsvDiscoveryAndCommandTests(TempCase):
    @staticmethod
    def _artifact(path, digest=None):
        lockfile = path / "package-lock.json"
        if digest is None:
            digest = hashlib.sha256(lockfile.read_bytes()).hexdigest()
        return {"path":str(path), "lockfiles":[{
            "relative_path":"package-lock.json", "sha256":digest,
        }]}

    def test_dependency_roots_use_explicit_deployed_inputs_instead_of_source_checkout(self):
        source = self.root / "source"
        deployed_primary = self.root / "deployed-primary"
        deployed_secondary = self.root / "deployed-secondary"
        for path in (source, deployed_primary, deployed_secondary):
            path.mkdir()
        (deployed_primary / "package-lock.json").write_text("{}", encoding="ascii")
        (deployed_secondary / "package-lock.json").write_text("{}", encoding="ascii")
        asset = {
            "path": str(source),
            "dependency_artifacts": [self._artifact(deployed_primary),
                                     self._artifact(deployed_secondary)],
        }
        self.assertEqual(
            osv.dependency_roots(asset),
            [deployed_primary, deployed_secondary],
        )

    def test_dependency_roots_do_not_fall_back_to_source_checkout(self):
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_roots({"path": str(self.root)})

    def test_dependency_roots_reject_symlinks_and_unbounded_lists(self):
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_roots({"dependency_artifacts":[{
                "path":str(link), "lockfiles":[{
                    "relative_path":"package-lock.json", "sha256":"0" * 64,
                }],
            }]})
        roots = []
        for index in range(constants.MAX_DEPENDENCY_ROOTS + 1):
            path = self.root / ("root-%d" % index)
            path.mkdir()
            roots.append({"path":str(path), "lockfiles":[{
                "relative_path":"package-lock.json", "sha256":"0" * 64,
            }]})
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_roots({"dependency_artifacts": roots})

    def test_every_dependency_root_must_contain_a_supported_lockfile(self):
        first = self.root / "first"
        second = self.root / "second"
        first.mkdir()
        second.mkdir()
        asset = {"dependency_artifacts": [
            self._artifact(first, "0" * 64), self._artifact(second, "0" * 64),
        ]}
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_lockfile_snapshots(asset)
        lockfile = first / "package-lock.json"
        lockfile.write_text("{}", encoding="ascii")
        asset["dependency_artifacts"][0] = self._artifact(first)
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_lockfile_snapshots(asset)

    def test_dependency_snapshot_rejects_root_swap_after_validation(self):
        root = self.root / "root"
        outside = self.root / "outside"
        root.mkdir()
        outside.mkdir()
        (root / "package-lock.json").write_text("{}", encoding="ascii")
        (outside / "package-lock.json").write_text('{"outside":true}', encoding="ascii")
        asset = {"dependency_artifacts":[self._artifact(root)]}
        original = osv.inventory.validate_repository_root

        def swap_after_validation(path):
            validated = original(path)
            validated.rename(self.root / "original")
            validated.symlink_to(outside, target_is_directory=True)
            return validated

        with mock.patch.object(osv.inventory, "validate_repository_root",
                               side_effect=swap_after_validation):
            with self.assertRaises(osv.OsvCoverageError):
                osv.dependency_lockfile_snapshots(asset)

    def test_dependency_snapshot_rejects_nonsymlink_root_replacement_and_digest_drift(self):
        root = self.root / "root"
        replacement = self.root / "replacement"
        root.mkdir()
        replacement.mkdir()
        (root / "package-lock.json").write_text("{}", encoding="ascii")
        (replacement / "package-lock.json").write_text('{"replacement":true}', encoding="ascii")
        asset = {"dependency_artifacts":[self._artifact(root)]}
        original = osv.inventory.validate_repository_root

        def replace_after_validation(path):
            validated = original(path)
            validated.rename(self.root / "original")
            replacement.rename(validated)
            return validated

        with mock.patch.object(osv.inventory, "validate_repository_root",
                               side_effect=replace_after_validation):
            with self.assertRaises(osv.OsvCoverageError):
                osv.dependency_lockfile_snapshots(asset)

        restored = self.root / "original"
        drift_asset = {"dependency_artifacts":[self._artifact(restored)]}
        (restored / "package-lock.json").write_text('{"drift":true}', encoding="ascii")
        with self.assertRaises(osv.OsvCoverageError):
            osv.dependency_lockfile_snapshots(drift_asset)

    def test_discovery_is_bounded_and_excludes_unapproved_generated_roots(self):
        (self.root / "package-lock.json").write_text("{}", encoding="ascii")
        nested = self.root / "web"
        nested.mkdir()
        (nested / "pnpm-lock.yaml").write_text("lockfileVersion: 9", encoding="ascii")
        for excluded in (".local", "node_modules", ".next", "build"):
            path = self.root / excluded
            path.mkdir()
            (path / "package-lock.json").write_text("{}", encoding="ascii")
        found = osv.discover_lockfiles(self.root)
        self.assertEqual([path.relative_to(self.root).as_posix() for path in found],
                         ["package-lock.json", "web/pnpm-lock.yaml"])

    def test_discovery_rejects_supported_lockfile_symlink(self):
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="ascii")
        repo = self.root / "repo"
        repo.mkdir()
        (repo / "package-lock.json").symlink_to(outside)
        with self.assertRaises(osv.OsvCoverageError):
            osv.discover_lockfiles(repo)

    def test_argv_is_strictly_offline_and_lockfile_bounded(self):
        argv = osv.osv_argv(Path("/scanner"), Path("/database"), Path("/repo/package-lock.json"))
        self.assertIn("--offline", argv)
        self.assertIn("--lockfile", argv)
        self.assertIn("--format=json", argv)
        self.assertIn("--local-db-path", argv)
        self.assertNotIn("--download-offline-databases", argv)
        self.assertNotIn("--recursive", argv)


class OsvReportTests(TempCase):
    def test_report_shows_dependency_and_digest_bound_database_freshness(self):
        item = findings.make_finding("osv-offline", "repo-one", "dependency.osv.ghsa-test",
                                     "High", "confirmed", "dependency:0123456789abcdef",
                                     "upgrade-vulnerable-dependency", "run-1")
        item.update({"advisory_id":"GHSA-TEST", "package_name":"lodash",
                     "package_version":"4.17.20", "package_ecosystem":"npm"})
        evidence = {"osv_databases":{"npm":{
            "sha256":"abcdef0123456789" * 4,
            "last_modified":"2026-08-25T04:33:55Z",
            "version":"v2.5.1",
        }}}
        summary = reports.make_summary(
            "run-1", "COMPLETE", "2026-08-25T05:33:55Z", [item], [],
            "runs/run-1/report.html", module_evidence=evidence,
        )
        path = self.root / "report.html"
        reports.write_html(path, summary, [item], [{"asset_id":"repo-one", "status":"complete"}])
        text = path.read_text()
        self.assertIn("Known vulnerable dependency", text)
        self.assertIn("Omitted by disclosure policy", text)
        self.assertNotIn("lodash", text)
        self.assertNotIn("4.17.20", text)
        self.assertIn("Implementation boundaries", text)
        self.assertIn("not independent attestations", text)
        self.assertNotIn("No mutations performed", text)
        self.assertNotIn("Safety evidence", text)
        self.assertIn("Advisory <b>GHSA-TEST</b>", text)
        self.assertIn("OSV npm database", text)
        self.assertIn("age 1h", text)
        self.assertIn("abcdef012345", text)
        self.assertNotIn("dependency:0123456789abcdef", text)


if __name__ == "__main__":
    unittest.main()
