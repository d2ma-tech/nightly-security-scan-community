"""Normalized finding creation, lifecycle, recurrence and private event contracts."""
import copy
import hashlib
import json
import re
from . import constants

_EVENT_TYPES = {"detected", "fix_observed", "resolved", "recurred"}
_EVENT_KEYS = {"schema_version", "event_type", "fingerprint", "asset_id",
               "category_control_id", "module_id", "run_id", "recurrence_number",
               "bootstrap"}
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
CONFIDENCES = {"confirmed", "high", "medium", "low"}


def _fingerprint(parts):
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def make_finding(module_id, asset_id, control_id, severity, confidence, location_token,
                 recommendation_token, run_id):
    if severity not in SEVERITIES or confidence not in CONFIDENCES:
        raise ValueError("closed finding enum violation")
    fp = _fingerprint([module_id, asset_id, control_id, location_token])
    return {"schema_version": constants.SCHEMA_VERSION, "module_id": module_id,
            "asset_id": asset_id, "category_control_id": control_id, "severity": severity,
            "confidence": confidence, "location_token": location_token, "fingerprint": fp,
            "status": "open", "first_observed_run_id": run_id, "last_observed_run_id": run_id,
            "recommendation_token": recommendation_token, "eligible_absences": 0}


def apply_lifecycle(previous, observed, run_id, eligible):
    if not eligible:
        return copy.deepcopy(previous)
    result = copy.deepcopy(previous)
    seen = set()
    for item in observed:
        fp = item["fingerprint"]
        seen.add(fp)
        if fp in result:
            old = result[fp]
            item = copy.deepcopy(item)
            item["first_observed_run_id"] = old["first_observed_run_id"]
            recurrence_count = int(old.get("recurrence_count", 0))
            if old.get("status") == "resolved":
                recurrence_count += 1
                item["previous_resolution_run_id"] = old.get(
                    "resolution_run_id", old.get("last_observed_run_id", "unknown"))
            elif old.get("previous_resolution_run_id"):
                item["previous_resolution_run_id"] = old["previous_resolution_run_id"]
            if recurrence_count:
                item["recurrence_count"] = recurrence_count
        item["last_observed_run_id"] = run_id
        item["status"] = "open"
        item["eligible_absences"] = 0
        result[fp] = item
    if eligible:
        for fp, item in result.items():
            if fp not in seen and item["status"] != "resolved":
                item["eligible_absences"] = item.get("eligible_absences", 0) + 1
                if item["eligible_absences"] >= 7:
                    item["status"] = "resolved"
                    item["resolution_run_id"] = run_id
    return result


def preview_lifecycle(previous, observed, run_id):
    """Merge current observations without advancing or resolving stored lifecycle state."""
    result = apply_lifecycle(previous, observed, run_id, eligible=True)
    observed_fps = {item["fingerprint"] for item in observed}
    for fp, item in previous.items():
        if fp not in observed_fps:
            result[fp] = copy.deepcopy(item)
    return result


def validate_event(event):
    if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
        raise ValueError("lifecycle event schema rejected")
    if event.get("schema_version") != constants.SCHEMA_VERSION:
        raise ValueError("lifecycle event version rejected")
    if event.get("event_type") not in _EVENT_TYPES:
        raise ValueError("lifecycle event type rejected")
    if not isinstance(event.get("fingerprint"), str) or not _FINGERPRINT_RE.fullmatch(event["fingerprint"]):
        raise ValueError("lifecycle fingerprint rejected")
    for key in ("asset_id", "category_control_id", "module_id", "run_id"):
        value = event.get(key)
        if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
            raise ValueError("lifecycle token rejected")
    recurrence = event.get("recurrence_number")
    if not isinstance(recurrence, int) or isinstance(recurrence, bool) or not 0 <= recurrence <= 1000000:
        raise ValueError("lifecycle recurrence rejected")
    if not isinstance(event.get("bootstrap"), bool):
        raise ValueError("lifecycle bootstrap rejected")
    return copy.deepcopy(event)


def event_identity(event):
    valid = validate_event(event)
    transition_run = valid["run_id"] if valid["event_type"] == "fix_observed" else ""
    return (valid["fingerprint"], valid["event_type"], valid["recurrence_number"],
            transition_run)


def _event(item, event_type, run_id, bootstrap=False):
    event = {"schema_version": constants.SCHEMA_VERSION, "event_type": event_type,
             "fingerprint": item["fingerprint"], "asset_id": item["asset_id"],
             "category_control_id": item["category_control_id"],
             "module_id": item["module_id"], "run_id": run_id,
             "recurrence_number": (0 if event_type == "detected" else
                                   int(item.get("recurrence_count", 0))),
             "bootstrap": bool(bootstrap)}
    return validate_event(event)


def transition_events(previous, current, observed, run_id, eligible):
    if not eligible:
        return []
    observed_fps = {item["fingerprint"] for item in observed}
    events = []
    for fp, item in sorted(current.items()):
        old = previous.get(fp)
        if old is None and fp in observed_fps:
            events.append(_event(item, "detected", run_id))
            continue
        if old is None:
            continue
        if old.get("status") == "resolved" and item.get("status") == "open":
            events.append(_event(item, "recurred", run_id))
        elif (old.get("status") == "open" and old.get("eligible_absences", 0) == 0 and
              item.get("status") == "open" and item.get("eligible_absences") == 1):
            events.append(_event(item, "fix_observed", run_id))
        elif old.get("status") != "resolved" and item.get("status") == "resolved":
            events.append(_event(item, "resolved", run_id))
    return events


def bootstrap_events(snapshot, existing_keys, run_id):
    events = []
    existing_episode_types = {(fp, event_type, recurrence)
                              for fp, event_type, recurrence, _event_run in existing_keys}
    for fp, item in sorted(snapshot.items()):
        detected = _event(item, "detected", item.get("first_observed_run_id", run_id), True)
        if (fp, "detected", 0) not in existing_episode_types:
            events.append(detected)
        recurrence_number = int(item.get("recurrence_count", 0))
        absences = item.get("eligible_absences", 0)
        if item.get("status") == "resolved":
            resolved = _event(item, "resolved",
                              item.get("resolution_run_id", item.get("last_observed_run_id", run_id)),
                              True)
            if (fp, "resolved", recurrence_number) not in existing_episode_types:
                events.append(resolved)
        elif isinstance(absences, int) and not isinstance(absences, bool) and 0 < absences < 7:
            fixed = _event(item, "fix_observed", run_id, True)
            if (fp, "fix_observed", recurrence_number) not in existing_episode_types:
                events.append(fixed)
    return events
