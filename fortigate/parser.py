"""Parse synthetic FortiGate JSON, CEF, and key=value syslog records."""

import json
import re
from typing import Any


class FortiGateParseError(ValueError):
    """Raised for malformed or unsupported FortiGate log records."""


def parse_log(line: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(line, dict):
        record = dict(line)
    elif not isinstance(line, str) or not line.strip():
        raise FortiGateParseError("Log record must be a non-empty string or object")
    else:
        raw = line.strip()
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise FortiGateParseError("JSON log must be an object")
            record = value
        except json.JSONDecodeError:
            if raw.startswith("CEF:") or " CEF:" in raw:
                record = _parse_cef(raw)
            else:
                record = _parse_syslog(raw)
    if not record or not any(key in record for key in ("type", "subtype", "eventtype", "logid", "action")):
        raise FortiGateParseError("Log record has no recognizable FortiGate event fields")
    return record


def _parse_cef(raw: str) -> dict[str, Any]:
    match = re.search(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)$", raw)
    if not match:
        raise FortiGateParseError("Malformed CEF record")
    version, vendor, product, device_version, signature, name, severity, extension = match.groups()
    fields = {key: value for key, value in re.findall(r"([A-Za-z][\w.]*)=(.*?)(?=\s+[A-Za-z][\w.]*=|$)", extension)}
    fields.update({"type": fields.get("type", "traffic"), "subtype": fields.get("subtype", "forward"),
                   "logid": fields.get("logid", signature), "event_name": name,
                   "cef": {"version": version, "vendor": vendor, "product": product,
                           "device_version": device_version, "severity": severity}})
    fields.setdefault("action", fields.get("act", "unknown"))
    fields.setdefault("srcip", fields.get("src", ""))
    fields.setdefault("dstip", fields.get("dst", ""))
    return fields


def _parse_syslog(raw: str) -> dict[str, Any]:
    # Accept both a bare FortiGate key=value record and a syslog-prefixed one.
    start = raw.find("date=")
    if start < 0:
        start = raw.find("type=")
    if start < 0:
        raise FortiGateParseError("Syslog record contains no FortiGate key=value fields")
    fields = dict(re.findall(r'([A-Za-z][\w]*)=("(?:[^"\\]|\\.)*"|\S+)', raw[start:]))
    if not fields:
        raise FortiGateParseError("Malformed FortiGate syslog fields")
    for key, value in fields.items():
        if value.startswith('"'):
            try:
                fields[key] = json.loads(value)
            except json.JSONDecodeError:
                fields[key] = value[1:-1]
    fields.setdefault("action", fields.get("act", "unknown"))
    return fields
