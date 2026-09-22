# Daily Security Scan — community/shareable edition

A source-only reference implementation with an **offline synthetic preview**, not a turnkey security product. No security guarantee is provided. A completed demo does not mean your computer or repositories are safe.

## Try the synthetic preview

Requires Python 3.11+ on macOS or a compatible POSIX platform (uses `fcntl`, directory descriptors and filesystem permissions). No third-party Python dependencies, network, scanner binaries, credentials, service or scheduler are required for the demo.

From this directory:

```sh
python3 -B demo.py
python3 -B -m unittest discover -s tests -v
```

The demo prints a report path in a newly created temporary directory. Open that HTML file locally. It uses invented host posture and an explicit synthetic scanner through the real deterministic engine, exclusive lock, hash-chain and HTML/JSON report path. Its lock uses an explicitly synthetic process fingerprint in a fresh isolated directory, not a host process probe. Generated artifacts are marked synthetic. Two synthetic assets and two findings are expected; no repository content is scanned. The report is a manual-verification preview: it does not advance the persistent finding lifecycle. Delete its temporary directory when finished. Demo output is not bundled with source.

## Included source

The engine provides bounded orchestration, coverage accounting, hash-linked events, atomic private report files, escaped inert HTML, seven-clean-scan resolution and recurrence tracking. Adapters include redacted Gitleaks parsing, offline OSV parsing and digest-bound dependency inputs. Tests use invented fixtures and temporary files; they do not run scanner binaries or native host collectors. Existing host/scanner integration tests were intentionally not exported.

## OSV metadata disclosure boundary

The included OSV parser **omits source-derived package name, version and ecosystem before persistence**, even for ordinary-looking public package values. There is no approved public provenance contract for those fields. Length/type checks, character allowlists and HTML escaping do not establish that a string is non-secret. Reports show the omission rather than package details, including when handed older findings containing those fields.

Advisory identifiers remain under the existing bounded advisory syntax validation, alongside severity, manifest count and deterministic finding/location fingerprints. Advisory syntax is not independent provenance or secret-redaction proof. Package metadata is used transiently to derive the existing identity hash for correlation; those hashes are not anonymization and can permit dictionary matching. The output is less actionable: identify the affected package locally under a separately reviewed disclosure policy.

This change does not migrate or sanitize prior persisted state, arbitrary trusted-caller findings, inventory identifiers or database evidence. Use fresh private state for this reference edition and review any real report before sharing. Standalone HTML describes implementation boundaries, not independent privacy, network, credential-use or mutation attestation. Local report/state writes occur. Synthetic regression tests exercise invented path and credential canaries in each omitted field through the real engine's persisted JSON (including lifecycle snapshot) and HTML; they do not certify native scanner behavior or production integration.

## Operational provisioning is separate

**Do not call `engine.run` with its default host collector expecting a demo:** that collector runs real read-only macOS posture commands. Use `demo.py` for the safe preview. The production command-line wrapper, schedules, synchronization, private inventory, state/history and scanner releases are excluded.

Real scanning is an unvalidated integration task, not a documented one-command install:

1. Independently review the inventory schema in `inventory.py`. Build an explicit local inventory, including exact deployed dependency roots and SHA-256 bindings for every approved lockfile. Provision `INVENTORY_SHA256`, `ASSET_COUNT` and `REPOSITORY_COUNT` in a reviewed local build. The distributed binding is **unprovisioned and fails closed**; counts are not wildcards. Never replace comparison with runtime self-approval or omit path checks. Bound entry points reject changed inventory bytes. The lower-level engine assumes a trusted caller; the demo alone intentionally supplies invented in-memory inventory.
2. Independently obtain and verify compatible Gitleaks and OSV releases and offline database snapshots. No third-party binaries or databases are redistributed. `installer.py` provides digest-bound offline extraction/locator support; OSV requires its exact installation manifest and locator schema. Provision them under private, operator-controlled directories. Consult source contracts before use.
3. Constants retain historical scanner pins (Gitleaks 8.30.1, OSV 2.5.1 and an npm database timestamp from 2026-08-25), **not a claim of latest versions, fresh coverage or compatibility with your machine**. Refresh through a separate reviewed digest-bound release, not by bypassing checks. Only explicitly supported npm lockfile inputs are represented. Other ecosystems are not covered by the supplied contract.
4. Real adapters require macOS `sandbox-exec`, native tools and reviewed permissions/architecture. They retain deny-default/network sandboxing and escaped current-home deny rules with narrowly scoped read/write allowances. These profiles have only string-level synthetic tests here, not live sandbox certification. Private deployment-specific secret suppressions were removed; review resulting detections locally. The inherited Lima listener exception remains narrowly version/process-attested to its named Homebrew path; it is not general listener safety proof.
5. Provide fresh private state/scratch directories, review retention and lifecycle behavior, and run your own authorized integration validation before operational use. Report safety fields are application assertions, not independent network or mutation attestations. Local state writes occur even though scanner-target mutation flags say false. Do not share real reports without review.

No scheduling is installed. The optional inherited schedule enforcement uses **UTC** with no-new-work at 03:15 and a 03:20 kill deadline; these are invocation cutoffs, not a scheduler. Review/change them explicitly before using bound scheduled entry points. Manual verification disables those cutoffs, not resource bounds.

## Scope and licensing

MIT licensed; copyright 2026 D2MA. See `LICENSE`. This edition preserves the underlying source authorship without exporting private Git history. Third-party scanner tools/databases must be acquired separately under their own licenses; this package grants no rights to them. No third-party distribution is included. No automatic remediation, publishing, synchronization or scheduling is provided.
