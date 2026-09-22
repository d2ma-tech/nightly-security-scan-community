# Daily Security Scan

**Check macOS security settings, detect exposed secrets in local repositories, and track vulnerable dependencies in one local report.**

Daily Security Scan brings host checks and repository scanner results into a single reporting engine. It records what was checked, groups findings by severity, and tracks whether issues are new, recurring or resolved across scans.

This community edition includes the Python engine, macOS collectors, Gitleaks and offline OSV adapters, HTML/JSON reporting, and an offline demo. Start with the demo below; connecting it to real projects requires the setup described in [Integration notes](docs/integration.md).

## What it checks

- **Mac security settings:** System Integrity Protection (SIP), Gatekeeper, FileVault, the application firewall and stealth mode.
- **Network listeners:** listener metadata and wildcard bindings that deserve attention.
- **Exposed secrets:** integrates Gitleaks results from local repositories, discarding raw secret values and file paths from its parsed findings.
- **Vulnerable dependencies:** integrates offline OSV results for explicitly configured npm dependency inputs, with digest checks tying scans to the intended lockfiles and database snapshot.

The engine coordinates these checks and turns their results into a consistent report. It does not automatically fix findings or change the settings it checks.

## What you get

- **A local HTML report** for reviewing findings and severity without a hosted dashboard.
- **Structured JSON output** for your own tooling and analysis.
- **Coverage accounting** that distinguishes completed checks from incomplete scans.
- **Finding history:** recurrence tracking and resolution after seven eligible clean scans.
- **Bounded execution:** exclusive scan locking, execution limits and hash-linked event records.

Reports keep raw scanner output out of the normal findings flow. OSV package names and versions are omitted; advisory IDs and correlation fingerprints remain. Keep real reports private unless you have reviewed their contents.

## Try it in a minute

You need **Python 3.11+** on macOS or a compatible POSIX system. The demo uses only the Python standard library—no API keys, scanner downloads or network access.

```sh
git clone https://github.com/d2ma-tech/nightly-security-scan-community.git
cd nightly-security-scan-community
python3 -B demo.py
```

The command prints the path to a generated HTML report. Open that file in your browser.

The demo feeds **two example assets and two example findings** through the real scan engine and report generator. It writes to a fresh temporary directory and does not scan your computer or repositories. This lets you explore the report before configuring real checks.

## Run the tests

```sh
python3 -B -m unittest discover -s tests -v
```

The synthetic test suite covers reporting, inventory integrity, locking, finding lifecycle, dependency input validation and privacy regressions.

## Use it with your own projects

The demo works out of the box. Real scanning is currently a source-level integration, rather than a packaged command-line installation:

1. **Define the scope:** configure an explicit inventory of repositories, dependency inputs and host checks.
2. **Supply the scanners:** obtain compatible Gitleaks and OSV tools and an offline vulnerability database, then configure their expected digests.
3. **Connect local storage:** provide private report, state and scratch directories.
4. **Validate your setup:** run the checks against your intended inputs before adding them to a daily workflow.

The real host collectors and scanner sandbox integrations target **macOS**. Scanner binaries, vulnerability databases and automatic scheduling are not included. The supplied version/database pins are historical examples and need reviewing for a current deployment.

See **[Integration notes](docs/integration.md)** for the inventory bindings, scanner contracts, platform requirements and output details.

## Project layout

```text
demo.py                 Offline example using the real engine
daily_security_scan/    Engine, collectors, adapters and reporting
tests/                  Synthetic regression tests
docs/integration.md     Real-scanning setup and technical notes
```

## License

[MIT](LICENSE) · Copyright 2026 D2MA. Gitleaks, OSV and their databases are acquired separately under their respective licences.
