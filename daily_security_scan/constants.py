"""Resource bounds and historical scanner pins; operational inventory is unprovisioned."""

SPEC_SHA256 = None  # No private specification exported.
INVENTORY_SHA256 = None  # Provision an independently reviewed exact-byte binding.
INVENTORY_SCHEMA = "daily-security-scan-local-first-mvp-inventory-v1"
ASSET_COUNT = 0  # Unprovisioned; not a wildcard.
REPOSITORY_COUNT = 0
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_ARCHIVE = "gitleaks_8.30.1_darwin_arm64.tar.gz"
GITLEAKS_ARCHIVE_BYTES = 7_897_593
GITLEAKS_ARCHIVE_SHA256 = "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
NATIVE_OUTPUT_CAP = 2 * 1024 * 1024
GITLEAKS_OUTPUT_CAP = 8 * 1024 * 1024
OSV_OUTPUT_CAP = 8 * 1024 * 1024
OSV_SCANNER_VERSION = "2.5.1"
OSV_SCANNER_BINARY_BYTES = 55_484_002
OSV_SCANNER_BINARY_SHA256 = "75c44d6332f892a1e56286f4105a98ed751ae28d215ca0a8b65cc00d84103054"
OSV_NPM_DATABASE_BYTES = 220_228_167
OSV_NPM_DATABASE_SHA256 = "2f010f4cec04a10fb2e2c45a087761bfb2010c700f1b8347f938d13a2344e390"
OSV_NPM_DATABASE_LAST_MODIFIED = "2026-08-25T04:33:55Z"
OSV_NPM_DATABASE_SOURCE = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
OSV_SCANNER_TIMEOUT = 180
OSV_RSS_LIMIT_BYTES = 1024 * 1024 * 1024
MAX_DEPENDENCY_ROOTS = 8
# Backward-compatible report/native bound. Scanner code must use GITLEAKS_OUTPUT_CAP.
OUTPUT_CAP = NATIVE_OUTPUT_CAP
ALERT_CAP = 2048
RSS_LIMIT_BYTES = 384 * 1024 * 1024
SCANNER_TIMEOUT = 90
GLOBAL_TIMEOUT = 30 * 60
SCHEMA_VERSION = "daily-security-scan-local-first-mvp-v1"
