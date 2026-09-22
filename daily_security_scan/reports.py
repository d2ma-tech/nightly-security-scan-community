"""Private atomic JSON, inert HTML, summary contract and Critical-only stdout."""
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from . import constants


def create_run_dir(root, run_id):
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    run_dir = root / run_id
    run_dir.mkdir(mode=0o700)
    os.chmod(run_dir, 0o700)
    return run_dir


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def atomic_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name("." + path.name + ".tmp-" + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path, value):
    atomic_bytes(path, _canonical(value))


def _normalize_module_evidence(value):
    normalized = {"osv_databases":{}}
    if not isinstance(value, dict) or set(value) - {"osv_databases"}:
        return normalized
    databases = value.get("osv_databases", {})
    if not isinstance(databases, dict):
        return normalized
    for ecosystem, row in sorted(databases.items()):
        if (ecosystem not in {"npm"} or not isinstance(row, dict) or
                not isinstance(row.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or
                not isinstance(row.get("last_modified"), str) or
                not isinstance(row.get("version"), str)):
            continue
        normalized["osv_databases"][ecosystem] = {
            "sha256":row["sha256"], "last_modified":row["last_modified"],
            "version":row["version"],
        }
    return normalized


def make_summary(run_id, status, run_time, current_findings, coverage_failures, report_token,
                 run_type="eligible-run", lifecycle_eligible=True, module_evidence=None):
    severities = {name:0 for name in ("Critical", "High", "Medium", "Low", "Info")}
    states = {"open":0, "resolved":0}
    confirmation_count = 0
    recurrence_count = 0
    for item in current_findings:
        states[item["status"]] = states.get(item["status"], 0) + 1
        absences = item.get("eligible_absences", 0)
        confirming = (item.get("status") == "open" and isinstance(absences, int) and
                      not isinstance(absences, bool) and 0 < absences < 7)
        if item.get("status") == "open" and int(item.get("recurrence_count", 0)) > 0:
            recurrence_count += 1
        if confirming:
            confirmation_count += 1
        elif item.get("status") == "open":
            severities[item["severity"]] += 1
    return {"schema_version":constants.SCHEMA_VERSION, "run_id":run_id, "status":status,
            "run_time":run_time, "counts_by_severity":severities, "counts_by_state":states,
            "confirmation_count":confirmation_count, "recurrence_count":recurrence_count,
            "coverage_failures":sorted(coverage_failures),
            "action_required":bool(coverage_failures or severities["Critical"] or severities["High"]),
            "report_token":report_token, "production_access":False, "mutation_performed":False,
            "raw_output_persisted":False, "run_type":run_type,
            "lifecycle_eligible":lifecycle_eligible,
            "module_evidence":_normalize_module_evidence(module_evidence)}


def _finding_label(token):
    if str(token).startswith("dependency.osv."):
        return "Known vulnerable dependency"
    labels = {
        "secret.generic-api-key":"Generic API key",
        "secret.aws-access-token":"AWS access token",
        "secret.jwt":"JSON Web Token",
        "posture.filevault":"FileVault disabled",
        "posture.firewall":"Firewall disabled",
        "posture.stealth":"Stealth mode disabled",
        "listener.wildcard":"Wildcard network listener",
        "disk.low-capacity":"Low disk capacity",
    }
    return labels.get(str(token), str(token).replace(".", " · ").replace("-", " ").title())


def _recommendation_label(token):
    labels = {
        "classify-secret-finding":"Classify locally; rotate only if confirmed active",
        "review-and-rotate-secret":"Review and rotate the exposed secret",
        "enable-host-control":"Enable this macOS security control",
        "review-listener-exposure":"Review whether this listener must bind to all interfaces",
        "free-disk-capacity":"Free disk capacity and verify healthy headroom",
        "upgrade-vulnerable-dependency":"Upgrade the affected dependency to a fixed version",
    }
    return labels.get(str(token), str(token).replace("-", " ").capitalize())


_SOURCE_CLASS_LABELS = (
    ("runtime-source", "Runtime source"),
    ("configuration", "Configuration"),
    ("test-or-fixture", "Test or fixture"),
    ("documentation-or-prose", "Documentation or prose"),
    ("generated-or-cached", "Generated or cached"),
    ("unknown", "Unknown"),
)


def _source_class_summary(value, match_count):
    allowed = {token for token, _ in _SOURCE_CLASS_LABELS}
    if (not isinstance(value, dict) or not value or set(value) - allowed or
            not isinstance(match_count, int) or isinstance(match_count, bool) or
            not 1 <= match_count <= 10000):
        return "Unavailable for earlier runs"
    if any(not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10000
           for count in value.values()):
        return "Unavailable for earlier runs"
    if sum(value.values()) != match_count:
        return "Unavailable for earlier runs"
    return " · ".join("%s %d" % (label, value[token])
                      for token, label in _SOURCE_CLASS_LABELS if token in value)


def _display_state(item):
    """Return deterministic human state without changing the seven-scan lifecycle."""
    absences = item.get("eligible_absences", 0)
    recurrence_count = int(item.get("recurrence_count", 0))
    if item.get("status") == "open" and recurrence_count > 0 and absences == 0:
        previous = item.get("previous_resolution_run_id", "unknown")
        return ("RECURRENCE DETECTED · #%d" % recurrence_count, "",
                "Previously resolved in %s. The finding has returned and requires attention." % previous,
                False)
    if (item.get("status") == "open" and isinstance(absences, int) and
            not isinstance(absences, bool) and 0 < absences < 7):
        label = "FIXED · VERIFYING"
        remaining = 7 - absences
        progress = "%d/7 clean scans" % absences
        if item.get("module_id") == "native-posture":
            detail = ("The control is currently enabled. Waiting for %d more consecutive clean scan%s "
                      "before this finding is fully resolved and removed." %
                      (remaining, "" if remaining == 1 else "s"))
        else:
            detail = ("The finding is not currently observed. Waiting for %d more consecutive clean scan%s "
                      "before it is fully resolved and removed." %
                      (remaining, "" if remaining == 1 else "s"))
        return label, progress, detail, True
    return str(item.get("status", "open")).upper(), "", "", False


def _display_finding_label(item, confirming):
    label = _finding_label(item.get("category_control_id", "unknown"))
    if confirming and item.get("module_id") == "native-posture" and label.endswith(" disabled"):
        return label[:-9] + " enabled"
    return label


def _history_event_label(event_type):
    return {"detected":"Detected", "fix_observed":"Fix first observed",
            "resolved":"Resolved", "recurred":"Recurrence detected"}.get(
                str(event_type), str(event_type).replace("_", " ").title())


def _history_age_class(run_id, report_time):
    try:
        event_time = datetime.strptime(str(run_id)[:15], "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
        current = datetime.fromisoformat(str(report_time).replace("Z", "+00:00"))
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return "recent" if (current.astimezone(timezone.utc) - event_time).days <= 90 else "older"
    except (ValueError, TypeError):
        return "unknown-age"


def _osv_database_safety_html(summary, escape):
    evidence = summary.get("module_evidence", {})
    databases = evidence.get("osv_databases", {}) if isinstance(evidence, dict) else {}
    rows = []
    for ecosystem, item in sorted(databases.items() if isinstance(databases, dict) else []):
        try:
            modified = datetime.fromisoformat(str(item["last_modified"]).replace("Z", "+00:00"))
            current = datetime.fromisoformat(str(summary.get("run_time", "")).replace("Z", "+00:00"))
            if modified.tzinfo is None:
                modified = modified.replace(tzinfo=timezone.utc)
            if current.tzinfo is None:
                current = current.replace(tzinfo=timezone.utc)
            age_hours = max(0, int((current - modified).total_seconds() // 3600))
            age = "%dh" % age_hours if age_hours < 48 else "%dd" % (age_hours // 24)
            digest = str(item["sha256"])
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            rows.append("<li>OSV %s database · age %s · digest %s</li>" %
                        (escape(ecosystem), escape(age), escape(digest[:12])))
        except (KeyError, TypeError, ValueError):
            continue
    return "".join(rows)


def write_html(path, summary, current_findings=None, coverage=None, lifecycle_events=None):
    current_findings = list(current_findings or [])
    coverage = list(coverage or [])
    lifecycle_events = list(lifecycle_events or [])
    e = lambda value: html.escape(str(value), quote=True)
    module_safety_html = _osv_database_safety_html(summary, e)
    counts = summary.get("counts_by_severity", {})
    severity_order = {"Critical":0, "High":1, "Medium":2, "Low":3, "Info":4}
    ordered = sorted((item for item in current_findings if item.get("status") != "resolved"),
                     key=lambda item: (severity_order.get(item.get("severity"), 9),
                                       item.get("asset_id", ""),
                                       item.get("category_control_id", "")))
    complete = sum(1 for item in coverage if item.get("status") == "complete")
    total = len(coverage)
    failure_rows = summary.get("coverage_failures", [])
    finding_cards = []
    for item in ordered:
        severity = str(item.get("severity", "Info"))
        css_severity = severity.lower() if severity in severity_order else "info"
        display_state, progress, detail, confirming = _display_state(item)
        is_recurrence = display_state.startswith("RECURRENCE DETECTED")
        if confirming:
            action_heading = "Resolution confirmation"
            action_text = detail
            state_text = "%s · %s" % (display_state, progress)
        elif is_recurrence:
            action_heading = "Recurrence detected"
            action_text = detail
            state_text = display_state
        else:
            action_heading = "Recommended action"
            action_text = _recommendation_label(item.get("recommendation_token", "review"))
            state_text = display_state
        is_secret_detector = (item.get("module_id") == "gitleaks" and
                              str(item.get("category_control_id", "")).startswith("secret."))
        is_osv_dependency = (item.get("module_id") == "osv-offline" and
                             str(item.get("category_control_id", "")).startswith("dependency.osv."))
        match_count = item.get("match_count")
        match_count_text = (str(match_count) if isinstance(match_count, int) and
                            not isinstance(match_count, bool) and 1 <= match_count <= 10000
                            else "Unavailable for earlier runs")
        source_class_text = _source_class_summary(item.get("source_class_counts"), match_count)
        if is_secret_detector:
            metadata_html = ('<span>Detector result <b>Pattern matched</b></span>'
                             '<span>Credential status <b>Unverified</b></span>'
                             '<span>Matches observed <b>%s</b></span>' % e(match_count_text) +
                             '<span>Source classes <b>%s</b></span>' % e(source_class_text))
            location_html = '<span>Location <b>%s</b></span>' % e(item.get("location_token", "redacted"))
        elif is_osv_dependency:
            metadata_html = ('<span>Package metadata <b>Omitted by disclosure policy</b></span>' +
                             '<span>Advisory <b>%s</b></span>' % e(item.get("advisory_id", "unknown")) +
                             '<span>Confidence <b>%s</b></span>' % e(item.get("confidence", "unknown")))
            location_html = ""
        else:
            metadata_html = '<span>Confidence <b>%s</b></span>' % e(item.get("confidence", "unknown"))
            location_html = '<span>Location <b>%s</b></span>' % e(item.get("location_token", "redacted"))
        finding_cards.append(
            '<article class="finding %s%s"><div class="finding-top"><span class="severity">%s</span>'
            '<span class="state">%s</span></div><h3>%s</h3><p class="asset">%s</p>'
            '<div class="meta"><span>Module <b>%s</b></span>%s%s</div>'
            '<div class="action"><b>%s</b><p>%s</p></div></article>' %
            (css_severity, " confirming" if confirming else "", e(severity), e(state_text),
             e(_display_finding_label(item, confirming)), e(item.get("asset_id", "unknown")),
             e(item.get("module_id", "unknown")), metadata_html, location_html,
             e(action_heading), e(action_text))
        )
    if not finding_cards:
        finding_cards.append('<div class="empty"><strong>No open findings</strong><p>No normalized security findings were present in this eligible run.</p></div>')
    current_by_fp = {item.get("fingerprint"): item for item in current_findings}
    grouped_events = {}
    for event in lifecycle_events:
        fp = event.get("fingerprint", "unknown")
        grouped_events.setdefault(fp, []).append(event)
    history_groups = []
    for fp, event_rows in grouped_events.items():
        event_rows = sorted(event_rows, key=lambda row: str(row.get("run_id", "")), reverse=True)
        newest = event_rows[0]
        current_item = current_by_fp.get(fp, {})
        recurrence_number = max([int(row.get("recurrence_number", 0)) for row in event_rows] or [0])
        current_state = str(current_item.get("status", "historical")).upper()
        if (current_item.get("status") == "open" and
              isinstance(current_item.get("eligible_absences"), int) and
              not isinstance(current_item.get("eligible_absences"), bool) and
              0 < current_item.get("eligible_absences") < 7):
            current_state = "FIXED · VERIFYING %d/7" % current_item.get("eligible_absences")
        elif current_item.get("status") == "open" and recurrence_number:
            current_state = "OPEN · RECURRENCE #%d" % recurrence_number
        elif current_item.get("status") == "resolved":
            current_state = "RESOLVED"
        rows_html = ''.join(
            '<li class="history-event %s %s"><b>%s</b><span>Run %s%s</span></li>' %
            (e(row.get("event_type", "event")),
             e(_history_age_class(row.get("run_id"), summary.get("run_time"))),
             e(_history_event_label(row.get("event_type"))),
             e(row.get("run_id", "unknown")),
             e(" · recurrence #%d" % int(row.get("recurrence_number", 0))
               if row.get("event_type") == "recurred" else ""))
            for row in event_rows)
        history_groups.append((str(newest.get("run_id", "")),
            '<article class="history-group"><div class="history-head"><div><h3>%s</h3><p class="asset">%s</p></div>'
            '<span class="history-state">%s</span></div><p class="history-meta">Module %s · %d lifecycle event%s%s</p>'
            '<ol>%s</ol></article>' %
            (e(_finding_label(newest.get("category_control_id", "unknown"))),
             e(newest.get("asset_id", "unknown")), e(current_state),
             e(newest.get("module_id", "unknown")), len(event_rows),
             "" if len(event_rows) == 1 else "s",
             e(" · %d recurrence%s" % (recurrence_number, "" if recurrence_number == 1 else "s")
               if recurrence_number else ""), rows_html)))
    history_groups.sort(key=lambda row: row[0], reverse=True)
    history_html = ''.join(row[1] for row in history_groups)
    if not history_html:
        history_html = '<div class="empty"><strong>No fix history yet</strong><p>Resolved findings and recurrences will appear here after eligible scans establish them.</p></div>'
    coverage_html = ''.join('<li><span>%s</span><b class="%s">%s</b></li>' %
                            (e(item.get("asset_id", "unknown")),
                             "ok" if item.get("status") == "complete" else "warn",
                             e(item.get("status", "unknown"))) for item in coverage)
    failures_html = ''.join('<li>%s</li>' % e(item) for item in failure_rows) or '<li>None</li>'
    status = str(summary.get("status", "INCOMPLETE"))
    run_id = str(summary.get("run_id", "unknown"))
    run_time = str(summary.get("run_time", "unknown"))
    run_type = str(summary.get("run_type", "eligible-run"))
    if run_type == "manual-verification":
        run_type_label = "Manual verification"
        lifecycle_label = "Lifecycle not advanced"
    elif run_type == "natural-scheduled":
        run_type_label = "Natural scheduled run"
        lifecycle_label = "Lifecycle eligible"
    else:
        run_type_label = "Eligible run"
        lifecycle_label = "Lifecycle eligible"
    action_text = "Review the prioritized findings below." if summary.get("action_required") else "No immediate action required."
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'">
<title>Local Security Scan · {e(run_id)}</title><style>
:root{{--bg:#08090a;--panel:#0f1011;--surface:#191a1b;--border:rgba(255,255,255,.08);--text:#f7f8f8;--muted:#8a8f98;--violet:#7170ff;--green:#27a644;--red:#ff5c5c;--orange:#ff9f43;--yellow:#e8c547;--blue:#58a6ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 75% -10%,#25254d 0,transparent 30%),var(--bg);color:var(--text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.5}}main{{max-width:1120px;margin:auto;padding:32px 20px 64px}}header{{padding:24px 0 28px;border-bottom:1px solid var(--border)}}.eyebrow{{font:600 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;color:#a8a8ff}}h1{{font-size:clamp(34px,7vw,58px);line-height:1.02;letter-spacing:-.045em;margin:10px 0}}.lede{{color:var(--muted);max-width:720px;font-size:17px}}.pill{{display:inline-flex;border:1px solid var(--border);background:rgba(255,255,255,.04);border-radius:999px;padding:5px 10px;font-size:12px;margin:4px 5px 0 0}}.pill.ok{{color:#7ee2a8}}.grid{{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:18px}}.card{{background:rgba(255,255,255,.025);border:1px solid var(--border);border-radius:12px;padding:20px}}.summary{{grid-column:span 8}}.safety{{grid-column:span 4}}h2{{font-size:20px;margin:0 0 14px;letter-spacing:-.02em}}.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}.stat{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px}}.stat b{{display:block;font-size:24px}}.stat span{{color:var(--muted);font-size:12px}}.critical b{{color:var(--red)}}.high b{{color:var(--orange)}}.medium b{{color:var(--yellow)}}.low b{{color:var(--blue)}}.safety ul,.coverage-list{{list-style:none;margin:0;padding:0}}.safety li{{padding:7px 0;border-bottom:1px solid var(--border);font-size:13px;color:#d0d6e0}}.section{{margin-top:30px}}.findings{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.finding{{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:10px;padding:17px}}.finding.confirming{{border-left-color:var(--green);background:linear-gradient(135deg,rgba(39,166,68,.09),var(--panel) 42%)}}.finding.confirming .state{{color:#7ee2a8;font-weight:700}}.finding.confirming .action{{background:rgba(39,166,68,.10)}}.finding.confirming .action b{{color:#7ee2a8}}.finding.critical{{border-left-color:var(--red)}}.finding.high{{border-left-color:var(--orange)}}.finding.medium{{border-left-color:var(--yellow)}}.finding.low{{border-left-color:var(--blue)}}.finding-top{{display:flex;justify-content:space-between;gap:10px}}.severity,.state{{font-size:11px;text-transform:uppercase;letter-spacing:.08em}}.state{{color:var(--muted)}}.finding h3{{font-size:18px;margin:10px 0 2px}}.asset{{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#b5b7ff;margin:0 0 14px;word-break:break-word}}.meta{{display:flex;flex-wrap:wrap;gap:8px 14px;color:var(--muted);font-size:12px}}.meta b{{color:#d0d6e0;font-weight:500}}.action{{margin-top:14px;padding:12px;background:rgba(113,112,255,.08);border-radius:8px}}.action b{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#b5b7ff}}.action p{{margin:5px 0 0}}.coverage{{display:grid;grid-template-columns:2fr 1fr;gap:14px}}.coverage-list li{{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px}}.coverage-list b.ok{{color:#7ee2a8}}.coverage-list b.warn{{color:var(--orange)}}.empty{{padding:24px;border:1px solid var(--border);border-radius:10px;color:var(--muted)}}.tab-radio{{position:absolute;opacity:0;pointer-events:none}}.tabs{{display:flex;gap:8px;margin-top:22px;border-bottom:1px solid var(--border)}}.tabs label{{padding:10px 15px;color:var(--muted);font-weight:700;font-size:13px;cursor:pointer;border-bottom:2px solid transparent}}#tab-current:checked~.tabs label[for="tab-current"],#tab-history:checked~.tabs label[for="tab-history"]{{color:var(--text);border-bottom-color:var(--violet)}}.tab-panel{{display:none}}#tab-current:checked~#panel-current,#tab-history:checked~#panel-history{{display:block}}.history-list{{display:grid;gap:12px}}.history-group{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:17px}}.history-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}.history-head h3{{margin:0 0 2px;font-size:18px}}.history-state{{font-size:11px;letter-spacing:.08em;color:#7ee2a8;font-weight:700}}.history-meta{{color:var(--muted);font-size:12px}}.history-group ol{{list-style:none;margin:14px 0 0;padding:0;border-left:1px solid var(--border)}}.history-event{{position:relative;display:flex;justify-content:space-between;gap:14px;padding:8px 0 8px 18px;font-size:13px}}.history-event:before{{content:"";position:absolute;left:-5px;top:14px;width:9px;height:9px;border-radius:50%;background:var(--blue)}}.history-event.resolved:before{{background:var(--green)}}.history-event.recurred:before{{background:var(--red)}}.history-event.recent{{background:rgba(88,166,255,.035)}}.history-event.older{{opacity:.62}}.history-event span{{color:var(--muted);font:11px ui-monospace,SFMono-Regular,Menlo,monospace}}footer{{margin-top:34px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:18px}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#c3c4ff}}@media(max-width:760px){{.summary,.safety{{grid-column:1/-1}}.stats{{grid-template-columns:repeat(2,1fr)}}.findings,.coverage{{grid-template-columns:1fr}}main{{padding:22px 14px 48px}}}}
</style></head><body><main><header><div class="eyebrow">Community edition · Local security scan</div><h1>Security scan report</h1><p class="lede">{e(action_text)} Included adapters minimize retained data; OSV package name, version and ecosystem are omitted. These are implementation boundaries, not independent privacy or safety attestations. Trusted caller inputs and existing state require separate review before sharing.</p><span class="pill ok">{e(status)}</span><span class="pill">{e(run_type_label)}</span><span class="pill">{e(lifecycle_label)}</span><span class="pill">Run {e(run_id)}</span><span class="pill">{e(run_time)}</span></header>
<input class="tab-radio" type="radio" name="report-tab" id="tab-current" checked><input class="tab-radio" type="radio" name="report-tab" id="tab-history"><nav class="tabs" aria-label="Report sections"><label for="tab-current">Current</label><label for="tab-history">Fix History</label></nav>
<div class="tab-panel" id="panel-current"><section class="grid"><div class="card summary"><h2>Executive summary</h2><div class="stats">{''.join('<div class="stat %s"><b>%s</b><span>%s</span></div>' % (name.lower(),e(counts.get(name,0)),e(name)) for name in ('Critical','High','Medium','Low','Info'))}</div><p><b>{e(complete)} of {e(total)} assets completed</b> · {e(len(failure_rows))} coverage failures · {e(sum(counts.values()))} active findings · {e(summary.get('confirmation_count',0))} fixes under confirmation · {e(summary.get('recurrence_count',0))} current recurrences</p></div><aside class="card safety"><h2>Implementation boundaries</h2><ul><li>Application assertions, not independent attestations</li><li>Included adapters are designed for offline, credential-free scanning</li><li>No automatic target remediation; local state and report writes occur</li><li>Included parsers discard raw scanner output</li><li>OSV source-derived package metadata omitted; Gitleaks secret and file fields discarded</li><li>HTML escaping is not secret redaction; review reports before sharing</li>{module_safety_html}</ul></aside></section>
<section class="section"><h2>Prioritized findings</h2><div class="findings">{''.join(finding_cards)}</div></section>
<section class="section coverage"><div class="card"><h2>Coverage · {e(complete)} of {e(total)} assets completed</h2><ul class="coverage-list">{coverage_html}</ul></div><div class="card"><h2>Coverage failures</h2><ul>{failures_html}</ul></div></section></div>
<div class="tab-panel" id="panel-history"><section class="section"><h2>Fix History</h2><p class="lede">Resolved findings remain visible here. If a resolved finding returns, its recurrence is preserved as a new lifecycle episode and promoted back to Current.</p><div class="history-list">{history_html}</div></section></div>
<footer>Generated by the deterministic Daily Local Security Scan. No automatic remediation is implemented by the included engine. Caller integrations and prior state are outside this report renderer's assurance boundary.</footer></main></body></html>'''
    atomic_bytes(path, document.encode("utf-8"))


def alert_stdout(current_findings, known_fingerprints):
    rows = [f for f in current_findings if f["severity"] == "Critical" and
            f["confidence"] == "confirmed" and f["fingerprint"] not in known_fingerprints and
            f["status"] == "open"]
    if not rows:
        return ""
    messages = []
    for item in sorted(rows, key=lambda x: x["fingerprint"]):
        messages.append("Critical security finding: asset %s; category %s; private report available." %
                        (item["asset_id"], item["category_control_id"]))
    encoded = "\n".join(messages).encode("utf-8")[:constants.ALERT_CAP]
    return encoded.decode("utf-8", "ignore")
