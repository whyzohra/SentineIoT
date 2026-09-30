"""Compose ML findings with SentinelOT's existing alert-to-incident services."""

from collections.abc import Iterable

from detection_engine import DetectionEngine, MITREMapper
from incident_management import IncidentService
from ml_detection.model import IsolationForestModel
from risk_engine import RiskEngine
from telemetry.schemas.event import TelemetryEvent


class MLDetectionPipeline:
    def __init__(self, *, random_state: int = 7, contamination: float = 0.08):
        self.model = IsolationForestModel(random_state=random_state, contamination=contamination)

    def fit(self, normal_events: Iterable[TelemetryEvent]) -> "MLDetectionPipeline":
        self.model.fit(list(normal_events))
        return self

    def predict(self, events: Iterable[TelemetryEvent]):
        return self.model.predict(list(events))


def process_with_ml(events: Iterable[TelemetryEvent], baseline: Iterable[TelemetryEvent], *,
                    incident_service: IncidentService | None = None,
                    random_state: int = 7, contamination: float | str = "auto"):
    event_batch, baseline_batch = list(events), list(baseline)
    model = IsolationForestModel(random_state=random_state, contamination=contamination).fit(baseline_batch)
    findings = model.predict(event_batch)
    rule_alerts = DetectionEngine().detect(event_batch)
    alerts = MITREMapper().enrich_many([*rule_alerts, *(finding.to_alert() for finding in findings)])
    assessments = RiskEngine().assess_many(alerts)
    incidents = ([incident_service.ingest(alert, assessment).incident
                  for alert, assessment in zip(alerts, assessments)] if incident_service else [])
    return {"events": event_batch, "findings": findings, "alerts": alerts,
            "assessments": assessments, "incidents": incidents}
