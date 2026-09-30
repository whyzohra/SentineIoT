"""Run synthetic FortiGate records through the established SentinelOT pipeline."""

from collections.abc import Iterable
from typing import Any

from detection_engine import DetectionEngine, MITREMapper
from fortigate.normalizer import normalize
from fortigate.parser import parse_log
from incident_management import IncidentService
from risk_engine import RiskEngine


def process_logs(records: Iterable[str | dict[str, Any]], *, incident_service: IncidentService | None = None):
    events = [normalize(parse_log(record)) for record in records]
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(events))
    assessments = RiskEngine().assess_many(alerts)
    incidents = ([incident_service.ingest(alert, assessment).incident
                  for alert, assessment in zip(alerts, assessments)] if incident_service else [])
    return {"events": events, "alerts": alerts, "assessments": assessments, "incidents": incidents}
