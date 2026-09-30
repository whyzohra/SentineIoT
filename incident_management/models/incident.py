"""Incident workflow models retaining the original alert and risk records."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from detection_engine.models.alert import AlertSeverity, SecurityAlert
from risk_engine.models.assessment import RiskAssessment, RiskLevel


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentAlertRecord(BaseModel):
    alert: SecurityAlert
    risk_assessment: RiskAssessment


class TimelineEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    kind: str
    summary: str
    actor: str = "system"
    alert_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentNote(BaseModel):
    note_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    actor: str
    text: str


class EvidenceAttachment(BaseModel):
    """Attachment metadata only; this model intentionally has no content/blob field."""

    attachment_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    actor: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    actor: str
    action: str
    old_status: IncidentStatus | None = None
    new_status: IncidentStatus | None = None
    reason: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: datetime
    updated_at: datetime
    last_alert_timestamp: datetime
    severity: AlertSeverity
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    alert_records: list[IncidentAlertRecord] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    analyst_notes: list[IncidentNote] = Field(default_factory=list)
    evidence_attachments: list[EvidenceAttachment] = Field(default_factory=list)
    audit_trail: list[AuditRecord] = Field(default_factory=list)

    @staticmethod
    def utc_now() -> datetime:
        return datetime.now(timezone.utc)
