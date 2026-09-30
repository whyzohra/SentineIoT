"""Configuration for the explainable weighted risk model."""

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class RiskConfig:
    """Weights, normalization limits, and score boundaries for risk assessment.

    The six weights must sum to 1. Evidence subscores saturate at their configured
    unique-event and structured-detail counts. Criticality is sourced from the
    asset registry; unknown assets use ``unknown_asset_criticality``.
    """

    severity_weight: float = 0.30
    confidence_weight: float = 0.20
    asset_criticality_weight: float = 0.20
    evidence_quantity_weight: float = 0.15
    evidence_quality_weight: float = 0.10
    mitre_mapping_weight: float = 0.05
    evidence_event_saturation: int = 5
    evidence_detail_saturation: int = 4
    maximum_asset_criticality: int = 5
    unknown_asset_criticality: int = 3
    medium_threshold: float = 25.0
    high_threshold: float = 50.0
    critical_threshold: float = 75.0

    def __post_init__(self) -> None:
        weights = (
            self.severity_weight,
            self.confidence_weight,
            self.asset_criticality_weight,
            self.evidence_quantity_weight,
            self.evidence_quality_weight,
            self.mitre_mapping_weight,
        )
        if any(not math.isfinite(weight) or weight < 0 for weight in weights):
            raise ValueError("risk weights must be finite and non-negative")
        if not math.isclose(sum(weights), 1.0, abs_tol=1e-9):
            raise ValueError("risk weights must sum to 1.0")
        if self.evidence_event_saturation < 1 or self.evidence_detail_saturation < 1:
            raise ValueError("evidence saturation counts must be positive")
        if self.maximum_asset_criticality < 1:
            raise ValueError("maximum asset criticality must be positive")
        if not 1 <= self.unknown_asset_criticality <= self.maximum_asset_criticality:
            raise ValueError("unknown asset criticality must be within the configured criticality scale")
        if not (0 < self.medium_threshold < self.high_threshold < self.critical_threshold <= 100):
            raise ValueError("risk thresholds must satisfy 0 < medium < high < critical <= 100")
