"""Map FortiGate records onto the established SentinelOT event schema."""

from datetime import datetime, timezone
from typing import Any

from telemetry.schemas.asset import AssetSummary, AssetType, PurdueLevel
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


def _asset(address: str, label: str) -> AssetSummary:
    known = {"192.168.10.11": ("PLC-001", "plc01.water.ot.local", AssetType.PLC, 1),
             "192.168.10.12": ("PLC-002", "plc02.chem.ot.local", AssetType.PLC, 1),
             "192.168.20.21": ("HMI-001", "hmi01.controlroom.ot.local", AssetType.HMI, 2),
             "192.168.30.31": ("SCADA-001", "scada01.central.ot.local", AssetType.SCADA, 3),
             "192.168.30.41": ("ENGINEERING-001", "eng01.maint.ot.local", AssetType.ENGINEERING_WORKSTATION, 3)}
    asset_id, hostname, kind, level = known.get(address, (f"FG-{address}", address or label, AssetType.FIREWALL, PurdueLevel.LEVEL_4.value))
    return AssetSummary(asset_id=asset_id, hostname=hostname, ip_address=address or "0.0.0.0",
                        asset_type=kind, purdue_level=level)


def normalize(record: dict[str, Any]) -> TelemetryEvent:
    kind = str(record.get("type", "traffic")).lower()
    subtype = str(record.get("subtype", "")).lower()
    action = str(record.get("action", record.get("eventtype", "unknown"))).lower()
    category = "traffic"
    event_type = EventType.NETWORK_CONNECTION
    if kind in {"event", "user", "auth"} or subtype in {"system", "admin", "vpn", "login"} or "login" in action:
        category = "vpn" if "vpn" in subtype or "vpn" in action else "authentication"
        event_type = EventType.AUTH_EVENT
    elif kind in {"utm", "ips"} and subtype in {"ips", "anomaly"}:
        category = "ips"
    elif kind in {"utm", "webfilter"} or subtype in {"webfilter", "virus", "app-ctrl"}:
        category = "web_filter"
    elif kind in {"utm", "ips"}:
        category = "security"
    severity_value = str(record.get("severity", "INFO")).upper()
    severity = (EventSeverity.CRITICAL if severity_value in {"CRITICAL", "EMERGENCY", "ALERT"} else
                EventSeverity.HIGH if severity_value in {"HIGH", "ERROR", "5"} else
                EventSeverity.MEDIUM if severity_value in {"MEDIUM", "WARNING", "4", "3"} else
                EventSeverity.LOW if action in {"deny", "blocked", "failed", "failure"} else EventSeverity.INFO)
    source_ip = str(record.get("srcip", record.get("src", "0.0.0.0")))
    destination_ip = str(record.get("dstip", record.get("dst", "")))
    timestamp = record.get("timestamp")
    if not timestamp and record.get("date"):
        timestamp = f"{record['date']}T{record.get('time', '00:00:00')}Z"
    if timestamp:
        try:
            parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            timestamp = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            timestamp = datetime.now(timezone.utc)
    metadata = {"vendor": "FortiGate", "integration": "fortigate", "fortigate": dict(record),
                "fortigate_event_id": str(record.get("logid", record.get("eventid", record.get("id", "")))),
                "category": category, "action": action, "policy_id": record.get("policyid"),
                "interface": record.get("srcintf"), "destination_interface": record.get("dstintf"),
                "service": record.get("service"), "source_ip": source_ip,
                "destination_ip": destination_ip, "security_profile": record.get("profile", record.get("profiletype")),
                "user": record.get("user", record.get("unauthuser", "")),
                "result": (str(record.get("result", "")).upper() if record.get("result") else
                           "FAILURE" if action in {"deny", "failed", "failure", "blocked"} else
                           "SUCCESS" if event_type == EventType.AUTH_EVENT else action.upper())}
    values = dict(source_asset=_asset(source_ip, "source"),
                          destination_asset=_asset(destination_ip, "destination") if destination_ip else None,
                          event_type=event_type, severity=severity,
                          message=f"FortiGate {category}: {action} {source_ip}" + (f" to {destination_ip}" if destination_ip else ""),
                          metadata=metadata)
    if timestamp is not None:
        values["timestamp"] = timestamp
    if metadata["fortigate_event_id"]:
        values["event_id"] = f"fortigate-{metadata['fortigate_event_id']}"
    return TelemetryEvent(**values)
