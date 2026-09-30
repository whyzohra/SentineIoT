"""Typed output for transparent alert risk calculations."""

from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactor(BaseModel):
    """Normalized 0–100 input and its weighted contribution to a score."""

    value: float = Field(ge=0.0, le=100.0)
    weight: float = Field(ge=0.0, le=1.0)
    contribution: float = Field(ge=0.0, le=100.0)
    rationale: str


class RiskAssessment(BaseModel):
    """Risk result linked to, but separate from, the alert input."""

    alert_id: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    factors: dict[str, RiskFactor]
    formula: str
    explanation: str
