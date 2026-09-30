import pytest

pytest.importorskip("sklearn", reason="Install ml_detection/requirements.txt to run ML tests")

from detection_engine import DetectionEngine
from incident_management import IncidentService, SQLiteIncidentRepository
from ml_detection.features import FEATURE_NAMES, OTFeatureExtractor
from ml_detection.fixtures import anomalous_batch, normal_baseline
from ml_detection.model import IsolationForestModel
from ml_detection.pipeline import process_with_ml


def test_features_are_named_repeatable_and_capture_rate_and_relationship_deviation():
    baseline = normal_baseline()
    candidates = anomalous_batch()
    extractor = OTFeatureExtractor()
    first = extractor.extract(candidates, reference_events=baseline)
    second = extractor.extract(candidates, reference_events=baseline)
    assert first == second
    assert tuple(first[0]) == FEATURE_NAMES
    assert first[8]["commands_from_source_to_target_60s"] > first[0]["commands_from_source_to_target_60s"]
    assert first[-1]["historical_relationship_count"] == 0


def test_isolation_forest_is_reproducible_and_emits_explainable_findings():
    baseline, candidates = normal_baseline(), anomalous_batch()
    left = IsolationForestModel(random_state=19).fit(baseline).predict(candidates)
    right = IsolationForestModel(random_state=19).fit(baseline).predict(candidates)
    assert [finding.event.event_id for finding in left] == [finding.event.event_id for finding in right]
    assert [finding.anomaly_score for finding in left] == [finding.anomaly_score for finding in right]
    by_event = {finding.event.event_id: finding for finding in left}
    assert "commands_from_source_to_target_60s" in by_event["burst-009"].unusual_features
    assert "historical_relationship_count" in by_event["relationship-novel-001"].unusual_features
    alert = by_event["relationship-novel-001"].to_alert()
    assert alert.metadata["ml_generated"] is True
    assert alert.metadata["detection_source"] == "ML"
    assert alert.evidence["feature_evidence"]["historical_relationship_count"]["value"] == 0


def test_model_artifact_round_trip_preserves_predictions(tmp_path):
    model = IsolationForestModel(random_state=7).fit(normal_baseline())
    path = tmp_path / "model.joblib"
    model.save(str(path))
    assert [(item.event.event_id, item.anomaly_score) for item in model.predict(anomalous_batch())] == [
        (item.event.event_id, item.anomaly_score)
        for item in IsolationForestModel.load(str(path)).predict(anomalous_batch())
    ]


def test_ml_pipeline_flows_through_existing_alert_risk_and_incident_services(tmp_path):
    baseline, candidates = normal_baseline(), anomalous_batch()
    existing = DetectionEngine().detect(candidates)
    assert all(not alert.rule_id.startswith("ML-") for alert in existing)
    repo = SQLiteIncidentRepository(str(tmp_path / "ml-incidents.sqlite3"))
    try:
        result = process_with_ml(candidates, baseline, incident_service=IncidentService(repo), random_state=7)
        ml_alerts = [alert for alert in result["alerts"] if alert.metadata.get("ml_generated")]
        assert ml_alerts
        assert result["assessments"]
        assert result["incidents"]
        assert all(alert.evidence.get("feature_evidence") for alert in ml_alerts)
        assert {incident.incident_id for incident in result["incidents"]} <= {
            incident.incident_id for incident in repo.list()
        }
    finally:
        repo.close()


def test_fit_requires_sufficient_normal_baseline_and_predict_requires_fit():
    model = IsolationForestModel()
    with pytest.raises(RuntimeError, match="fit"):
        model.predict(anomalous_batch())
    with pytest.raises(ValueError, match="10"):
        model.fit(normal_baseline(9))
