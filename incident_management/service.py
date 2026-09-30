"""Application service for correlation and incident workflow operations."""

from dataclasses import dataclass
from typing import Any

from detection_engine.models.alert import SecurityAlert
from incident_management.correlation import IncidentCorrelationEngine
from incident_management.models import CorrelationConfig, Incident, IncidentStatus
from incident_management.repository import SQLiteIncidentRepository
from risk_engine.models.assessment import RiskAssessment


ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.OPEN, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}


@dataclass(frozen=True)
class IngestionResult:
    incident: Incident
    duplicate: bool


class IncidentService:
    def __init__(
        self,
        repository: SQLiteIncidentRepository,
        *,
        config: CorrelationConfig | None = None,
        correlator: IncidentCorrelationEngine | None = None,
    ) -> None:
        self.repository = repository
        self.config = config or CorrelationConfig()
        self.correlator = correlator or IncidentCorrelationEngine()

    def ingest(self, alert: SecurityAlert, assessment: RiskAssessment) -> IngestionResult:
        incident, duplicate = self.repository.ingest_alert(alert, assessment, self.correlator, self.config)
        return IngestionResult(incident=incident, duplicate=duplicate)

    def get(self, incident_id: str) -> Incident:
        incident = self.repository.get(incident_id)
        if incident is None:
            raise KeyError(f"Incident not found: {incident_id}")
        return incident

    def list(self, status: IncidentStatus | None = None) -> list[Incident]:
        return self.repository.list(status)

    def update_status(
        self, incident_id: str, status: IncidentStatus, *, actor: str = "analyst", reason: str | None = None
    ) -> Incident:
        current = self.get(incident_id)
        if status not in ALLOWED_TRANSITIONS[current.status]:
            allowed = ", ".join(sorted(value.value for value in ALLOWED_TRANSITIONS[current.status])) or "none"
            raise ValueError(f"Transition {current.status.value} -> {status.value} is not allowed (allowed: {allowed})")
        return self.repository.transition(incident_id, status, actor=actor, reason=reason)

    def investigate(self, incident_id: str, note: str, *, actor: str = "analyst") -> Incident:
        return self.repository.investigate(incident_id, note, actor=actor)

    def add_note(self, incident_id: str, note: str, *, actor: str = "analyst") -> Incident:
        return self.repository.add_note(incident_id, note, actor=actor)

    def attach_evidence(
        self, incident_id: str, label: str, metadata: dict[str, Any], *, actor: str = "analyst"
    ) -> Incident:
        return self.repository.attach_evidence(incident_id, label, metadata, actor=actor)
