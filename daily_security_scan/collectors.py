"""Bounded native macOS posture and listener metadata collectors."""
import os
import pwd
import re
import subprocess
from pathlib import Path

from .constants import NATIVE_OUTPUT_CAP
from . import findings

COMMAND_TIMEOUT = 5
REVIEWED_LIMA_VERSION = "2.1.1"
REVIEWED_LIMA_PATH = "/opt/homebrew/bin/limactl"
COMMANDS = {
    "sip": ("/usr/bin/csrutil", "status"),
    "gatekeeper": ("/usr/sbin/spctl", "--status"),
    "filevault": ("/usr/bin/fdesetup", "status"),
    "firewall": ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"),
    "stealth": ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"),
    "listeners": ("/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"),
}
ENV = {"PATH":"/usr/bin:/usr/sbin:/bin", "LC_ALL":"C", "LANG":"C", "HOME":"/var/empty"}


def _enabled_disabled(text, enabled, disabled):
    value = text.strip().lower()
    if re.fullmatch(enabled, value):
        return "enabled"
    if re.fullmatch(disabled, value):
        return "disabled"
    return "incomplete"


def parse_sip(text):
    return _enabled_disabled(text, r"system integrity protection status: enabled\.",
                            r"system integrity protection status: disabled\.")


def parse_gatekeeper(text):
    return _enabled_disabled(text, r"assessments enabled", r"assessments disabled")


def parse_filevault(text):
    return _enabled_disabled(text, r"filevault is on\.", r"filevault is off\.")


def parse_firewall(text):
    return _enabled_disabled(text, r"firewall is enabled\. \(state = 1\)",
                            r"firewall is disabled\. \(state = 0\)")


def parse_stealth(text):
    return _enabled_disabled(text,
                            r"(?:stealth mode enabled|firewall stealth mode is on)",
                            r"(?:stealth mode disabled|firewall stealth mode is off)")


def parse_lima_version(text):
    match = re.fullmatch(r"limactl version (\d+\.\d+\.\d+)\s*", text)
    if not match:
        return "unknown"
    return match.group(1) if match.group(1) == REVIEWED_LIMA_VERSION else "other"


def _lima_pseudoloopback_signature(listener):
    return (listener.get("address_class") == "wildcard"
            and listener.get("protocol") == "tcp6"
            and listener.get("port") == 53
            and listener.get("owner_token") == "user"
            and listener.get("executable_token") == "limactl")


def _address_class(value):
    host = value.rsplit(":", 1)[0].strip("[]")
    if host in {"127.0.0.1", "::1", "localhost"}:
        return "loopback"
    if host in {"*", "0.0.0.0", "::"}:
        return "wildcard"
    if host.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.2", "172.30.", "172.31.", "100.")):
        return "private"
    return "other"


def _parse_listener_records(text):
    rows = []
    lines = text.splitlines()
    if not lines or not lines[0].startswith("COMMAND "):
        return None
    current_user = pwd.getpwuid(os.getuid()).pw_name
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 9 or fields[-1] != "(LISTEN)" or fields[-3] != "TCP":
            return None
        name = fields[-2]
        try:
            pid = int(fields[1])
            port = int(name.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return None
        proto = "tcp6" if "IPv6" in fields else "tcp4"
        executable = Path(fields[0]).name[:64]
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", executable):
            executable = "other"
        rows.append({"_pid":pid, "protocol":proto, "address_class":_address_class(name),
                     "port":port, "owner_token":"user" if fields[2] == current_user else "other",
                     "executable_token":executable})
    return sorted(rows, key=lambda x: (x["port"], x["protocol"], x["executable_token"], x["_pid"]))


def _public_listener(record):
    return {key:value for key, value in record.items() if not key.startswith("_")}


def parse_listeners(text):
    records = _parse_listener_records(text)
    return None if records is None else [_public_listener(row) for row in records]


def _attest_lima_record(record):
    if not _lima_pseudoloopback_signature(record):
        return False
    pid = record.get("_pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    process = _command(("/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "comm="))
    match = None if process is None else re.fullmatch(r"\s*(\d+)\s+(\S+)\s*", process)
    if not match or int(match.group(1)) != os.getuid() or match.group(2) != REVIEWED_LIMA_PATH:
        return False
    version = _command((match.group(2), "--version"))
    return version is not None and parse_lima_version(version) == REVIEWED_LIMA_VERSION


def _command(argv):
    try:
        cp = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=COMMAND_TIMEOUT, env=ENV, check=False)
        if len(cp.stdout) > NATIVE_OUTPUT_CAP or cp.returncode != 0:
            return None
        return cp.stdout.decode("utf-8", "strict")
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None


def collect_host():
    parsers = {"sip":parse_sip, "gatekeeper":parse_gatekeeper, "filevault":parse_filevault,
               "firewall":parse_firewall, "stealth":parse_stealth}
    posture, failures = {}, []
    for key, parser in parsers.items():
        raw = _command(COMMANDS[key])
        value = "incomplete" if raw is None else parser(raw)
        posture[key] = value
        if value == "incomplete":
            failures.append(key)
    raw = _command(COMMANDS["listeners"])
    records = None if raw is None else _parse_listener_records(raw)
    if records is None:
        posture["listeners"] = []
        failures.append("listeners")
    else:
        candidates = [row for row in records if _lima_pseudoloopback_signature(row)]
        if len(candidates) == 1 and _attest_lima_record(candidates[0]):
            candidates[0]["pseudoloopback_reviewed"] = True
            posture["lima_version"] = REVIEWED_LIMA_VERSION
        else:
            posture["lima_version"] = "unknown"
        posture["listeners"] = [_public_listener(row) for row in records]
    try:
        fs = os.statvfs("/")
        posture["disk"] = {"capacity_bytes":fs.f_blocks * fs.f_frsize,
                           "available_bytes":fs.f_bavail * fs.f_frsize}
    except OSError:
        posture["disk"] = {"status":"incomplete"}
        failures.append("disk")
    return posture, failures


def posture_findings(posture, asset_id, run_id):
    """Map only closed posture states to content-free canonical findings."""
    rows = []
    severity = {"sip":"High", "gatekeeper":"High", "filevault":"High",
                "firewall":"Medium", "stealth":"Low"}
    for control, level in severity.items():
        if posture.get(control) == "disabled":
            rows.append(findings.make_finding("native-posture", asset_id, "posture." + control,
                                              level, "confirmed", "host-control",
                                              "enable-host-control", run_id))
    listeners = posture.get("listeners", [])
    reviewed_lima = [row for row in listeners
                     if _lima_pseudoloopback_signature(row)
                     and row.get("pseudoloopback_reviewed") is True]
    for listener in listeners:
        if listener.get("address_class") == "wildcard":
            if len(reviewed_lima) == 1 and listener is reviewed_lima[0]:
                continue
            rows.append(findings.make_finding("native-listeners", asset_id, "listener.wildcard",
                                              "Medium", "confirmed", "listener-metadata",
                                              "review-listener-exposure", run_id))
    disk = posture.get("disk", {})
    capacity, available = disk.get("capacity_bytes"), disk.get("available_bytes")
    if isinstance(capacity, int) and capacity > 0 and isinstance(available, int) and available * 10 < capacity:
        rows.append(findings.make_finding("native-disk", asset_id, "disk.low-capacity", "Low",
                                          "confirmed", "root-volume", "free-disk-capacity", run_id))
    return sorted(rows, key=lambda item: item["fingerprint"])
