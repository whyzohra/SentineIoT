import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detection_engine import AlertSeverity, DetectionConfig, DetectionEngine, SecurityAlert
from detection_engine.rules import (
    BruteForceRule,
    InsiderBehaviorRule,
    NetworkReconRule,
    PLCCommandFrequencyRule,
    UnauthorizedPLCAccessRule,
)
from telemetry.assets import AssetRegistry
from telemetry.schemas.event import EventType, TelemetryEvent


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = AssetRegistry()
BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def event(event_id, source, target, event_type, offset=0, metadata=None):
    return TelemetryEvent(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=offset),
        source_asset=REGISTRY.get_summary(source),
        destination_asset=REGISTRY.get_summary(target) if target else None,
        event_type=event_type,
        message=f"synthetic {event_type.value}",
        metadata=metadata or {},
    )


def verify_alert(alert, input_events, rule_id):
    assert isinstance(alert, SecurityAlert)
    dumped = alert.model_dump(mode="json")
    assert {"alert_id", "rule_id", "timestamp", "severity", "confidence", "title",
            "description", "source_assets", "target_assets", "evidence", "metadata"} <= dumped.keys()
    assert alert.rule_id == rule_id
    assert 0 <= alert.confidence <= 1
    assert set(alert.evidence["event_ids"]) <= {item.event_id for item in input_events}
    assert SecurityAlert.model_validate(dumped).alert_id == alert.alert_id


def test_detection_001_network_recon_positive_negative_boundary_and_determinism():
    rule = NetworkReconRule()
    config = DetectionConfig(network_recon_unique_target_threshold=3, network_recon_window_seconds=60)
    negative = [event(f"n{i}", "ENGINEERING-001", target, EventType.NETWORK_CONNECTION, i)
                for i, target in enumerate(("PLC-001", "HMI-001"))]
    assert rule.evaluate(negative, config) == []
    boundary = negative + [event("n2", "ENGINEERING-001", "PLC-002", EventType.NETWORK_CONNECTION, 60)]
    alerts = rule.evaluate(boundary, config)
    assert len(alerts) == 1
    verify_alert(alerts[0], boundary, "DET-001-NETWORK-RECON")
    assert alerts[0].severity == AlertSeverity.MEDIUM
    assert alerts[0].metadata["affected_assets"]
    assert rule.evaluate(boundary, config)[0].model_dump(mode="json") == alerts[0].model_dump(mode="json")
    too_late = boundary[:2] + [event("n2", "ENGINEERING-001", "PLC-002", EventType.NETWORK_CONNECTION, 61)]
    assert rule.evaluate(too_late, config) == []


def test_detection_002_brute_force_failures_success_and_threshold():
    rule = BruteForceRule()
    config = DetectionConfig(auth_failure_threshold=3, auth_window_seconds=300)
    def auth_events(count, with_success=False):
        rows = [event(f"auth-{index}", "ENGINEERING-001", "HMI-001", EventType.AUTH_EVENT,
                      index * 10, {"account": "operator-a", "result": "FAILURE"})
                for index in range(count)]
        if with_success:
            rows.append(event("auth-ok", "ENGINEERING-001", "HMI-001", EventType.AUTH_EVENT,
                              count * 10, {"account": "operator-a", "result": "SUCCESS"}))
        return rows
    assert rule.evaluate(auth_events(2), config) == []
    at_threshold = auth_events(3)
    alerts = rule.evaluate(at_threshold, config)
    assert len(alerts) == 1
    verify_alert(alerts[0], at_threshold, "DET-002-AUTH-BRUTE-FORCE")
    assert alerts[0].severity == AlertSeverity.MEDIUM
    assert alerts[0].metadata["failed_attempt_count"] == 3
    with_success = auth_events(3, with_success=True)
    success_alert = rule.evaluate(with_success, config)[0]
    verify_alert(success_alert, with_success, "DET-002-AUTH-BRUTE-FORCE")
    assert success_alert.metadata["success_after_failures"] is True
    assert success_alert.severity == AlertSeverity.HIGH
    assert rule.evaluate(with_success, config)[0].model_dump(mode="json") == success_alert.model_dump(mode="json")


def test_detection_003_unauthorized_plc_policy_positive_negative_and_allowlist_boundary():
    rule = UnauthorizedPLCAccessRule()
    config = DetectionConfig()
    unauthorized = event("plc-denied", "ENGINEERING-001", "PLC-001", EventType.CONFIG_CHANGE)
    alerts = rule.evaluate([unauthorized], config)
    assert len(alerts) == 1
    verify_alert(alerts[0], [unauthorized], "DET-003-UNAUTHORIZED-PLC-ACCESS")
    assert alerts[0].severity == AlertSeverity.HIGH
    allowed = event("plc-allowed", "ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE,
                    metadata={"authorization_ticket": "CHG-SIM-1234"})
    assert rule.evaluate([allowed], config) == []
    widened = DetectionConfig(authorized_plc_sources={
        "PLC-001": frozenset({"HMI-001", "SCADA-001", "ENGINEERING-001"}),
        "PLC-002": frozenset({"HMI-001", "SCADA-001", "ENGINEERING-001"}),
    })
    assert rule.evaluate([unauthorized], widened) == []
    denied = event("explicit-denial", "HMI-001", "PLC-001", EventType.SCADA_COMMAND,
                   metadata={"authorization_status": "DENIED_SIMULATED"})
    assert rule.evaluate([denied], config)[0].evidence["authorization_status"] == "DENIED_SIMULATED"
    assert rule.evaluate([unauthorized], config)[0].model_dump(mode="json") == alerts[0].model_dump(mode="json")


def test_detection_004_command_frequency_negative_boundary_and_above_threshold():
    rule = PLCCommandFrequencyRule()
    config = DetectionConfig(plc_command_window_seconds=60,
                             plc_command_baseline_per_minute=2,
                             plc_command_baseline_multiplier=2)
    def commands(count):
        return [event(f"cmd-{index}", "HMI-001", "PLC-001", EventType.SCADA_COMMAND,
                      index, {"command_type": "SIMULATED"}) for index in range(count)]
    assert rule.evaluate(commands(3), config) == []
    assert rule.evaluate(commands(4), config) == []  # exactly baseline × multiplier
    above = commands(5)
    alerts = rule.evaluate(above, config)
    assert len(alerts) == 1
    verify_alert(alerts[0], above, "DET-004-PLC-COMMAND-FREQUENCY")
    assert alerts[0].severity == AlertSeverity.HIGH
    assert alerts[0].metadata["observed_frequency"] == pytest.approx(5.0)
    assert alerts[0].metadata["baseline_frequency"] == 2
    assert rule.evaluate(above, config)[0].model_dump(mode="json") == alerts[0].model_dump(mode="json")


def test_detection_005_insider_anomaly_context_and_maintenance_boundary():
    rule = InsiderBehaviorRule()
    config = DetectionConfig(maintenance_start_hour_utc=6, maintenance_end_hour_utc=18)
    clean = event("clean-change", "ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE,
                  metadata={"engineer": "eng_chen", "authorization_ticket": "CHG-SIM-1234"})
    assert rule.evaluate([clean], config) == []
    boundary = event("boundary-change", "ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE,
                     offset=-6 * 3600, metadata={"engineer": "eng_chen"})
    assert rule.evaluate([boundary], config) == []  # maintenance start is inclusive
    suspicious = event("insider-change", "ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE,
                       offset=-12 * 3600,
                       metadata={"user_alias": "unknown_engineer", "authorization_status": "UNAPPROVED_SIMULATED"})
    alerts = rule.evaluate([suspicious], config)
    assert len(alerts) == 1
    verify_alert(alerts[0], [suspicious], "DET-005-INSIDER-BEHAVIOR-ANOMALY")
    assert alerts[0].severity == AlertSeverity.HIGH
    assert "outside_maintenance_window" in alerts[0].metadata["indicators"]
    assert rule.evaluate([suspicious], config)[0].model_dump(mode="json") == alerts[0].model_dump(mode="json")

    routine = [event(f"routine-{index}", "ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE,
                     offset=index, metadata={"engineer": "eng_chen", "authorization_ticket": "CHG-SIM-1234"})
               for index in range(7)]
    assert rule.evaluate(routine[:6], config) == []  # exactly baseline × multiplier
    rate_alerts = rule.evaluate(routine, config)
    assert len(rate_alerts) == 1
    verify_alert(rate_alerts[0], routine, "DET-005-INSIDER-BEHAVIOR-ANOMALY")
    assert "activity_frequency_above_baseline" in rate_alerts[0].metadata["indicators"]
    assert rate_alerts[0].evidence["activity_count_in_window"] == 7


def test_engine_consumes_generator_and_combines_rules_without_changing_event_schema():
    inputs = [event(f"scan-{index}", "ENGINEERING-001", target, EventType.NETWORK_CONNECTION, index)
              for index, target in enumerate(("PLC-001", "PLC-002", "HMI-001"))]
    alerts = DetectionEngine().detect(iter(inputs))
    recon_alert = next(alert for alert in alerts if alert.rule_id == "DET-001-NETWORK-RECON")
    assert len(alerts) == 2  # discovery plus the unapproved PLC-001 connection
    assert recon_alert.metadata["detection_id"] == "DETECTION-001"
    assert set(recon_alert.evidence["event_ids"]) == {item.event_id for item in inputs}
    assert inputs[0].event_type == EventType.NETWORK_CONNECTION


def test_detection_cli_accepts_existing_event_jsonl_from_stdin():
    from attack_simulator import AttackSimulation

    simulated = AttackSimulation().run("network_recon", seed=7, count=3)
    event_jsonl = "\n".join(event.to_json() for event in simulated.generated_events) + "\n"
    result = subprocess.run(
        [sys.executable, "-m", "detection_engine", "detect"],
        cwd=ROOT, input=event_jsonl, capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    assert report["event_count"] == 3
    assert report["alert_count"] == 1
    assert report["alerts"][0]["rule_id"] == "DET-001-NETWORK-RECON"


def test_detection_cli_demo_runs_phase2_scenario_end_to_end():
    result = subprocess.run(
        [sys.executable, "-m", "detection_engine", "demo", "unauthorized_plc", "--seed", "7"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    assert report["event_count"] == 1
    assert len(report["events"]) == report["event_count"]
    assert report["alert_count"] >= 1
    assert any(alert["rule_id"] == "DET-003-UNAUTHORIZED-PLC-ACCESS" for alert in report["alerts"])


def test_phase2_unauthorized_command_burst_drives_frequency_detection():
    from attack_simulator import AttackSimulation

    simulated = AttackSimulation().run("unauthorized_plc", seed=21, count=5)
    alerts = DetectionEngine().detect(simulated.generated_events)
    frequency_alert = next(alert for alert in alerts if alert.rule_id == "DET-004-PLC-COMMAND-FREQUENCY")
    verify_alert(frequency_alert, simulated.generated_events, "DET-004-PLC-COMMAND-FREQUENCY")
    assert frequency_alert.evidence["observed_frequency"] == pytest.approx(5.0)
