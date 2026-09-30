"""Unit and integration coverage for incident grouping and analyst workflows."""

import json
import subprocess
import sys
from datetime import timedelta

import pytest

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from detection_engine.models.alert import AlertSeverity
from incident_management import (
    CorrelationConfig, IncidentService, IncidentStatus, SQLiteIncidentRepository,
)
from incident_management.correlation import IncidentCorrelationEngine
from risk_engine import RiskEngine
from risk_engine.models.assessment import RiskLevel


def _flow(scenario="network_recon"):
    simulation = AttackSimulation().run(scenario, seed=7)
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(simulation.generated_events))
    assessments = RiskEngine().assess_many(alerts)
    assert alerts
    return alerts, assessments


def _related_alert(alert, *, alert_id="alert-second", event_id="event-second", severity=AlertSeverity.CRITICAL):
    return alert.model_copy(update={
        "alert_id": alert_id,
        "detection_id": f"detection-{alert_id}",
        "timestamp": alert.timestamp + timedelta(seconds=30),
        "severity": severity,
        "evidence": {**alert.evidence, "event_ids": [event_id]},
    })


def _assessment(alert, score=90.0):
    risk = RiskEngine().assess(alert)
    return risk.model_copy(update={
        "risk_score": score,
        "risk_level": RiskLevel.CRITICAL if score >= 80 else RiskLevel.HIGH,
        "explanation": f"Test assessment explains score {score}",
    })


def test_ingest_deduplicates_alert_and_preserves_models_and_event_ids(tmp_path):
    alerts, assessments = _flow()
    repository = SQLiteIncidentRepository(tmp_path / "incidents.sqlite3")
    service = IncidentService(repository)
    first = service.ingest(alerts[0], assessments[0])
    before = service.get(first.incident.incident_id)
    repeated = service.ingest(alerts[0], assessments[0])
    after = service.get(first.incident.incident_id)
    assert not first.duplicate
    assert repeated.duplicate
    assert repeated.incident.incident_id == first.incident.incident_id
    assert len(after.alert_records) == len(before.alert_records) == 1
    assert len(after.timeline) == len(before.timeline)
    assert after.alert_records[0].alert == alerts[0]
    assert after.alert_records[0].risk_assessment == assessments[0]
    assert after.event_ids == sorted(set(alerts[0].evidence["event_ids"]))
    repository.close()


def test_correlates_shared_asset_and_recalculates_severity_and_risk(tmp_path):
    alerts, assessments = _flow()
    second = _related_alert(alerts[0])
    second_risk = _assessment(second)
    with SQLiteIncidentRepository(tmp_path / "incidents.sqlite3") as repository:
        service = IncidentService(repository)
        incident = service.ingest(alerts[0], assessments[0]).incident
        updated = service.ingest(second, second_risk).incident
        assert updated.incident_id == incident.incident_id
        assert updated.severity == AlertSeverity.CRITICAL
        assert updated.risk_score == 90.0
        assert updated.risk_level == RiskLevel.CRITICAL
        assert len(updated.alert_records) == 2
        assert set(updated.event_ids) == set(alerts[0].evidence["event_ids"]) | {"event-second"}
        assert updated.alert_records[0].alert.mitre_mappings == alerts[0].mitre_mappings
        assert updated.alert_records[1].risk_assessment.explanation == second_risk.explanation
        assert [entry.timestamp for entry in updated.timeline] == sorted(entry.timestamp for entry in updated.timeline)


def test_correlation_matches_accounts_or_techniques_and_respects_window(tmp_path):
    alerts, assessments = _flow()
    first = alerts[0]
    repository = SQLiteIncidentRepository(tmp_path / "incidents.sqlite3")
    service = IncidentService(repository, config=CorrelationConfig(time_window_seconds=60))
    original = service.ingest(first, assessments[0]).incident
    # Use unrelated assets, but retain the mapped technique to exercise technique correlation.
    unrelated = first.model_copy(update={
        "alert_id": "technique-related", "timestamp": first.timestamp + timedelta(seconds=2),
        "source_assets": [], "target_assets": [], "evidence": {"event_ids": ["other-event"]},
    })
    match = IncidentCorrelationEngine().match(unrelated, original, CorrelationConfig())
    assert match and "shared_technique" in match.signals
    # The repository window is configured; a far future alert becomes its own incident.
    outside = _related_alert(unrelated, alert_id="outside", event_id="outside-event")
    outside = outside.model_copy(update={"timestamp": first.timestamp + timedelta(seconds=61)})
    new_incident = service.ingest(outside, _assessment(outside)).incident
    assert new_incident.incident_id != original.incident_id
    repository.close()


def test_nonmatching_assets_accounts_techniques_and_boundary(tmp_path):
    alerts, assessments = _flow()
    original = alerts[0]
    with SQLiteIncidentRepository(tmp_path / "incidents.sqlite3") as repository:
        service = IncidentService(repository, config=CorrelationConfig(time_window_seconds=60))
        incident = service.ingest(original, assessments[0]).incident
        boundary = _related_alert(original, alert_id="at-boundary", event_id="boundary")
        boundary = boundary.model_copy(update={"timestamp": original.timestamp + timedelta(seconds=60)})
        assert service.ingest(boundary, _assessment(boundary)).incident.incident_id == incident.incident_id
        unrelated = boundary.model_copy(update={
            "alert_id": "unrelated", "timestamp": original.timestamp + timedelta(seconds=61),
            "source_assets": [], "target_assets": [], "mitre_mappings": [],
            "evidence": {"event_ids": ["unrelated-event"]}, "metadata": {},
        })
        new = service.ingest(unrelated, _assessment(unrelated)).incident
        assert new.incident_id != incident.incident_id


def test_status_transitions_notes_attachments_and_audit(tmp_path):
    alerts, assessments = _flow()
    with SQLiteIncidentRepository(tmp_path / "incidents.sqlite3") as repository:
        service = IncidentService(repository)
        incident = service.ingest(alerts[0], assessments[0]).incident
        with pytest.raises(ValueError, match="not allowed"):
            service.update_status(incident.incident_id, IncidentStatus.CONTAINED)
        investigation = service.investigate(incident.incident_id, "Review command history", actor="analyst-1")
        assert investigation.status == IncidentStatus.INVESTIGATING
        contained = service.update_status(incident.incident_id, IncidentStatus.CONTAINED,
                                          actor="analyst-1", reason="Lab access isolated")
        assert contained.status == IncidentStatus.CONTAINED
        noted = service.add_note(incident.incident_id, "Compare PLC setpoints", actor="analyst-2")
        attached = service.attach_evidence(
            incident.incident_id, "ticket reference", {"ticket": "LAB-42"}, actor="analyst-2"
        )
        assert len(noted.analyst_notes) == 2
        assert attached.evidence_attachments[0].metadata == {"ticket": "LAB-42"}
        assert not hasattr(attached.evidence_attachments[0], "content")
        with pytest.raises(ValueError, match="file payload"):
            service.attach_evidence(incident.incident_id, "not metadata", {"content": "raw bytes"})
        changes = [entry for entry in attached.audit_trail if entry.action == "STATUS_CHANGED"]
        assert [(change.old_status, change.new_status) for change in changes] == [
            (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING),
            (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED),
        ]
        resolved = service.update_status(incident.incident_id, IncidentStatus.RESOLVED)
        assert resolved.status == IncidentStatus.RESOLVED
        with pytest.raises(ValueError, match="not allowed"):
            service.update_status(incident.incident_id, IncidentStatus.FALSE_POSITIVE)


def test_database_persists_across_repository_instances(tmp_path):
    alerts, assessments = _flow()
    database = tmp_path / "persist.sqlite3"
    with SQLiteIncidentRepository(database) as repository:
        incident = IncidentService(repository).ingest(alerts[0], assessments[0]).incident
        incident_id = incident.incident_id
    with SQLiteIncidentRepository(database) as repository:
        loaded = IncidentService(repository).get(incident_id)
        assert loaded.alert_records[0].alert.alert_id == alerts[0].alert_id
        assert loaded.event_ids == sorted(alerts[0].evidence["event_ids"])


def test_end_to_end_cli_demo_then_list_in_separate_processes(tmp_path):
    database = tmp_path / "cli.sqlite3"
    command = [sys.executable, "-m", "incident_management"]
    demo = subprocess.run(
        [*command, "demo", "network_recon", "--seed", "7", "--db", str(database)],
        check=True, capture_output=True, text=True,
    )
    report = json.loads(demo.stdout)
    assert report["flow"] == ["attack_simulation", "detection", "mitre_mapping", "risk_assessment", "incident_creation"]
    assert report["alerts"][0]["mitre_mappings"]
    assert report["risk_assessments"][0]["explanation"]
    incident_id = report["incidents"][0]["incident_id"]
    listed = subprocess.run([*command, "list", "--db", str(database)], check=True, capture_output=True, text=True)
    assert json.loads(listed.stdout)[0]["incident_id"] == incident_id
    viewed = subprocess.run([*command, "view", incident_id, "--db", str(database)], check=True,
                            capture_output=True, text=True)
    assert json.loads(viewed.stdout)["alert_records"][0]["alert"]["mitre_mapping_status"] == "MAPPED"
