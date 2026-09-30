import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, SecurityAlert
from detection_engine.mitre import MITREMapper
from detection_engine.models.alert import MITREMappingStatus, MITREDomain
from telemetry.assets import AssetRegistry
from telemetry.schemas.event import EventType, TelemetryEvent


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = AssetRegistry()
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(event_id, source, target, event_type, offset=0, metadata=None):
    return TelemetryEvent(
        event_id=event_id,
        timestamp=NOW + timedelta(seconds=offset),
        source_asset=REGISTRY.get_summary(source),
        destination_asset=REGISTRY.get_summary(target) if target else None,
        event_type=event_type,
        message=f"synthetic {event_type.value}",
        metadata=metadata or {},
    )


def _alert_for(scenario_id, *, count=None):
    result = AttackSimulation().run(scenario_id, seed=31, count=count)
    alerts = DetectionEngine().detect(result.generated_events)
    return result.generated_events, alerts


def _verify_mapping_preserves_alert(alert, enriched):
    assert alert is not enriched
    before = alert.model_dump(mode="json")
    after = enriched.model_dump(mode="json")
    for field_name in SecurityAlert.model_fields:
        if field_name not in {"mitre_mapping_status", "mitre_mappings", "mitre_unmapped_reason"}:
            assert after[field_name] == before[field_name]
    assert enriched.evidence["event_ids"] == alert.evidence["event_ids"]


def test_maps_network_recon_to_ics_remote_system_discovery():
    events, alerts = _alert_for("network_recon")
    alert = next(item for item in alerts if item.rule_id == "DET-001-NETWORK-RECON")
    enriched = MITREMapper().enrich(alert)
    _verify_mapping_preserves_alert(alert, enriched)
    assert enriched.mitre_mapping_status == MITREMappingStatus.MAPPED
    mapping = enriched.mitre_mappings[0]
    assert (mapping.technique_id, mapping.name, mapping.domain) == (
        "T0846", "Remote System Discovery", MITREDomain.ICS
    )
    assert [(tactic.tactic_id, tactic.name) for tactic in mapping.tactics] == [("TA0102", "Discovery")]
    assert set(enriched.evidence["event_ids"]) <= {event.event_id for event in events}


def test_maps_brute_force_to_enterprise_brute_force():
    events, alerts = _alert_for("brute_force", count=12)
    alert = next(item for item in alerts if item.rule_id == "DET-002-AUTH-BRUTE-FORCE")
    enriched = MITREMapper().enrich(alert)
    _verify_mapping_preserves_alert(alert, enriched)
    mapping = enriched.mitre_mappings[0]
    assert enriched.mitre_mapping_status == MITREMappingStatus.MAPPED
    assert (mapping.technique_id, mapping.name, mapping.domain) == (
        "T1110", "Brute Force", MITREDomain.ENTERPRISE
    )
    assert [(tactic.tactic_id, tactic.name) for tactic in mapping.tactics] == [("TA0006", "Credential Access")]
    assert set(enriched.evidence["event_ids"]) <= {event.event_id for event in events}


def test_maps_unauthorized_plc_command_only_when_evidence_supports_command_message():
    events, alerts = _alert_for("unauthorized_plc")
    alert = next(item for item in alerts if item.rule_id == "DET-003-UNAUTHORIZED-PLC-ACCESS")
    enriched = MITREMapper().enrich(alert)
    _verify_mapping_preserves_alert(alert, enriched)
    mapping = enriched.mitre_mappings[0]
    assert enriched.mitre_mapping_status == MITREMappingStatus.MAPPED
    assert mapping.technique_id == "T1692.001"
    assert mapping.name == "Unauthorized Message: Command Message"
    assert mapping.domain == MITREDomain.ICS
    assert {(item.tactic_id, item.name) for item in mapping.tactics} == {
        ("TA0103", "Evasion"), ("TA0106", "Impair Process Control")
    }
    assert set(enriched.evidence["event_ids"]) <= {event.event_id for event in events}

    generic_access = _event("generic-access", "ENGINEERING-001", "PLC-001", EventType.NETWORK_CONNECTION)
    generic_alert = next(item for item in DetectionEngine().detect([generic_access])
                         if item.rule_id == "DET-003-UNAUTHORIZED-PLC-ACCESS")
    unmapped = MITREMapper().enrich(generic_alert)
    assert unmapped.mitre_mapping_status == MITREMappingStatus.UNMAPPED
    assert unmapped.mitre_mappings == []
    assert "does not identify command-message" in unmapped.mitre_unmapped_reason
    _verify_mapping_preserves_alert(generic_alert, unmapped)


def test_command_frequency_and_insider_detections_remain_intentionally_unmapped():
    _, command_alerts = _alert_for("unauthorized_plc", count=5)
    _, insider_alerts = _alert_for("insider_anomaly")
    selected = [
        next(item for item in command_alerts if item.rule_id == "DET-004-PLC-COMMAND-FREQUENCY"),
        next(item for item in insider_alerts if item.rule_id == "DET-005-INSIDER-BEHAVIOR-ANOMALY"),
    ]
    enriched_alerts = MITREMapper().enrich_many(selected)
    assert [alert.mitre_mapping_status for alert in enriched_alerts] == [
        MITREMappingStatus.UNMAPPED, MITREMappingStatus.UNMAPPED
    ]
    assert all(alert.mitre_mappings == [] for alert in enriched_alerts)
    assert "does not establish" in enriched_alerts[0].mitre_unmapped_reason
    assert "do not establish" in enriched_alerts[1].mitre_unmapped_reason
    for original, enriched in zip(selected, enriched_alerts):
        _verify_mapping_preserves_alert(original, enriched)


def test_mapper_marks_unknown_detection_unmapped_without_changing_existing_alert():
    event = _event("unknown-rule-event", "ENGINEERING-001", "PLC-001", EventType.NETWORK_CONNECTION)
    base = DetectionEngine().detect([event])
    alert = next(item for item in base if item.rule_id == "DET-003-UNAUTHORIZED-PLC-ACCESS")
    unknown = alert.model_copy(update={"rule_id": "DET-999-UNKNOWN"})
    enriched = MITREMapper().enrich(unknown)
    assert enriched.mitre_mapping_status == MITREMappingStatus.UNMAPPED
    assert "No ATT&CK mapping" in enriched.mitre_unmapped_reason
    assert unknown.mitre_mapping_status == MITREMappingStatus.NOT_EVALUATED


def test_detection_demo_cli_prints_structured_mitre_enrichment():
    result = subprocess.run(
        [sys.executable, "-m", "detection_engine", "demo", "network_recon", "--seed", "7"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    alert = next(item for item in report["alerts"] if item["rule_id"] == "DET-001-NETWORK-RECON")
    assert alert["mitre_mapping_status"] == "MAPPED"
    assert alert["mitre_mappings"][0]["technique_id"] == "T0846"
    assert alert["mitre_mappings"][0]["domain"] == "ICS"
    assert alert["evidence"]["event_ids"]
