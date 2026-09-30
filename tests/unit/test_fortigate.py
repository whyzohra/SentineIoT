import json
from pathlib import Path

import pytest

from fortigate import FortiGateParseError, normalize, parse_log, process_logs
from incident_management import IncidentService, SQLiteIncidentRepository

FIXTURES = Path(__file__).parents[2] / "fortigate" / "fixtures"


def test_parse_json_cef_and_syslog_formats():
    rows = json.loads((FIXTURES / "formats.json").read_text())
    parsed = [parse_log(row) for row in rows]
    assert [row["logid"] for row in parsed] == ["0000000013", "0000000013", "0101039944"]
    assert parsed[1]["srcip"] == "198.51.100.25"
    assert parsed[2]["user"] == "labuser"


@pytest.mark.parametrize("line", ["", "not a log", "[]", "CEF:garbage", "<134>no fields here"])
def test_malformed_logs_raise_helpful_error(line):
    with pytest.raises(FortiGateParseError):
        parse_log(line)


def test_normalization_preserves_raw_fields_and_maps_event_types():
    rows = json.loads((FIXTURES / "formats.json").read_text())
    traffic = normalize(parse_log(rows[0]))
    vpn = normalize(parse_log(rows[2]))
    assert traffic.event_type.value == "NETWORK_CONNECTION"
    assert traffic.event_id == "fortigate-0000000013"
    assert traffic.metadata["policy_id"] == "17"
    assert traffic.metadata["fortigate"]["dstip"] == "192.168.10.11"
    assert vpn.event_type.value == "AUTH_EVENT"
    assert vpn.metadata["category"] == "vpn"
    assert vpn.metadata["result"] == "SUCCESS"


@pytest.mark.parametrize(("record", "category", "event_type"), [
    ({"type": "event", "subtype": "user", "action": "login", "result": "failed"}, "authentication", "AUTH_EVENT"),
    ({"type": "event", "subtype": "vpn", "action": "tunnel-up"}, "vpn", "AUTH_EVENT"),
    ({"type": "utm", "subtype": "ips", "action": "detected"}, "ips", "NETWORK_CONNECTION"),
    ({"type": "utm", "subtype": "webfilter", "action": "blocked"}, "web_filter", "NETWORK_CONNECTION"),
])
def test_supported_security_categories(record, category, event_type):
    event = normalize(record)
    assert event.metadata["category"] == category
    assert event.event_type.value == event_type


def test_demo_fixtures_flow_through_alert_risk_and_incident(tmp_path):
    records = (FIXTURES / "demo.jsonl").read_text().splitlines()
    repo = SQLiteIncidentRepository(str(tmp_path / "fg.sqlite3"))
    try:
        result = process_logs(records, incident_service=IncidentService(repo))
    finally:
        repo.close()
    assert len(result["events"]) == 2
    assert any(alert.rule_id == "DET-006-FORTIGATE-IPS" for alert in result["alerts"])
    assert result["assessments"] and result["incidents"]
    assert result["incidents"][0].event_ids


def test_repeated_denials_rule_requires_five_supported_events():
    from detection_engine import DetectionEngine
    record = {"logid": "denied", "type": "traffic", "subtype": "forward",
              "srcip": "198.51.100.25", "dstip": "192.168.10.11", "action": "deny"}
    assert not [alert for alert in DetectionEngine().detect([normalize(record)] * 4)
                if alert.rule_id == "DET-007-FORTIGATE-DENIED-BURST"]
    assert [alert for alert in DetectionEngine().detect([normalize({**record, "logid": str(i)}) for i in range(5)])
            if alert.rule_id == "DET-007-FORTIGATE-DENIED-BURST"]
