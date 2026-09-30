"""Structured, deterministic security alerts derived from telemetry evidence."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field

from telemetry.schemas.asset import AssetSummary


class AlertSeverity(str, Enum):
    """Alert levels used by the rule engine (INFO is intentionally excluded)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MITREDomain(str, Enum):
    """MITRE ATT&CK matrix domain containing a technique."""

    ICS = "ICS"
    ENTERPRISE = "ENTERPRISE"


class MITREMappingStatus(str, Enum):
    """Whether an alert's behavior supports a configured ATT&CK mapping."""

    NOT_EVALUATED = "NOT_EVALUATED"
    MAPPED = "MAPPED"
    UNMAPPED = "UNMAPPED"


class MITRETactic(BaseModel):
    tactic_id: str
    name: str
    url: str


class MITRETechniqueMapping(BaseModel):
    technique_id: str
    name: str
    domain: MITREDomain
    url: str
    tactics: list[MITRETactic]
    mapping_basis: str


class SecurityAlert(BaseModel):
    """Normalized detection result that retains traceable source event IDs."""

    alert_id: str
    detection_id: str
    rule_id: str
    timestamp: datetime
    severity: AlertSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    source_assets: list[AssetSummary]
    target_assets: list[AssetSummary]
    evidence: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
    mitre_mapping_status: MITREMappingStatus = MITREMappingStatus.NOT_EVALUATED
    mitre_mappings: list[MITRETechniqueMapping] = Field(default_factory=list)
    mitre_unmapped_reason: str | None = None

    @classmethod
    def from_rule(
        cls,
        *,
        rule_id: str,
        timestamp: datetime,
        severity: AlertSeverity,
        confidence: float,
        title: str,
        description: str,
        source_assets: list[AssetSummary],
        target_assets: list[AssetSummary],
        evidence: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> "SecurityAlert":
        """Construct stable alert and detection IDs from the rule and evidence."""
        event_ids = sorted(set(evidence.get("event_ids", [])))
        identity = f"{rule_id}:{'|'.join(event_ids)}"
        detection_id = str(uuid5(NAMESPACE_URL, f"sentinelot:detection:{identity}"))
        return cls(
            alert_id=str(uuid5(NAMESPACE_URL, f"sentinelot:alert:{identity}")),
            detection_id=detection_id,
            rule_id=rule_id,
            timestamp=timestamp,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            source_assets=source_assets,
            target_assets=target_assets,
            evidence=evidence,
            metadata=metadata or {},
        )


def utc_timestamp(value: datetime) -> datetime:
    """Normalize naive event timestamps as UTC and aware timestamps to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
