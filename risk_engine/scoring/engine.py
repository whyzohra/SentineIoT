"""Rule-independent, deterministic scoring of SecurityAlert objects."""

from collections.abc import Iterable

from telemetry.assets import AssetRegistry
from detection_engine.models.alert import AlertSeverity, MITREMappingStatus, SecurityAlert
from risk_engine.models.assessment import RiskAssessment, RiskFactor, RiskLevel
from risk_engine.models.config import RiskConfig


SEVERITY_VALUES = {
    AlertSeverity.LOW: 0.0,
    AlertSeverity.MEDIUM: 33.33,
    AlertSeverity.HIGH: 66.67,
    AlertSeverity.CRITICAL: 100.0,
}


class RiskEngine:
    """Calculate weighted, explainable risk assessments without mutating alerts."""

    _factor_order = (
        "severity", "confidence", "asset_criticality", "evidence_quantity",
        "evidence_quality", "mitre_mapping",
    )

    def __init__(self, config: RiskConfig | None = None,
                 registry: AssetRegistry | None = None) -> None:
        self.config = config or RiskConfig()
        self.registry = registry or AssetRegistry()

    def assess(self, alert: SecurityAlert) -> RiskAssessment:
        """Return a component breakdown and risk level for one alert."""
        config = self.config
        evidence_ids = {
            str(event_id) for event_id in alert.evidence.get("event_ids", [])
            if event_id is not None and str(event_id)
        }
        evidence_details = [
            (key, value) for key, value in alert.evidence.items()
            if key != "event_ids" and value is not None and value != "" and value != [] and value != {}
        ]

        asset_summaries = [*alert.source_assets, *alert.target_assets]
        criticality_by_asset = {}
        for summary in asset_summaries:
            asset = self.registry.get_asset(summary.asset_id)
            criticality_by_asset[summary.asset_id] = (
                asset.criticality if asset is not None else config.unknown_asset_criticality
            )
        highest_criticality = max(criticality_by_asset.values(), default=config.unknown_asset_criticality)
        criticality_score = min(highest_criticality / config.maximum_asset_criticality, 1.0) * 100.0

        evidence_quantity = min(len(evidence_ids) / config.evidence_event_saturation, 1.0) * 100.0
        evidence_quality = min(len(evidence_details) / config.evidence_detail_saturation, 1.0) * 100.0
        has_mapping = (
            alert.mitre_mapping_status == MITREMappingStatus.MAPPED and bool(alert.mitre_mappings)
        )
        values = {
            "severity": SEVERITY_VALUES[alert.severity],
            "confidence": alert.confidence * 100.0,
            "asset_criticality": criticality_score,
            "evidence_quantity": evidence_quantity,
            "evidence_quality": evidence_quality,
            "mitre_mapping": 100.0 if has_mapping else 0.0,
        }
        weights = {
            "severity": config.severity_weight,
            "confidence": config.confidence_weight,
            "asset_criticality": config.asset_criticality_weight,
            "evidence_quantity": config.evidence_quantity_weight,
            "evidence_quality": config.evidence_quality_weight,
            "mitre_mapping": config.mitre_mapping_weight,
        }
        formula = "risk_score = " + " + ".join(
            f"{name}×{weights[name]:.2f}" for name in self._factor_order
        )
        rationales = {
            "severity": f"Alert severity {alert.severity.value} normalized to {values['severity']:.2f}/100.",
            "confidence": f"Rule confidence {alert.confidence:.4f} normalized to {values['confidence']:.2f}/100.",
            "asset_criticality": (
                f"Highest source/target criticality is {highest_criticality}/"
                f"{config.maximum_asset_criticality}; assets: {criticality_by_asset or 'none'}"
            ),
            "evidence_quantity": (
                f"{len(evidence_ids)} unique supporting event IDs; saturation at "
                f"{config.evidence_event_saturation}."
            ),
            "evidence_quality": (
                f"{len(evidence_details)} non-empty structured evidence details; saturation at "
                f"{config.evidence_detail_saturation}."
            ),
            "mitre_mapping": (
                f"Supported MITRE mapping present: {has_mapping}."
                if has_mapping else "No supported MITRE mapping is present; no mapping bonus applied."
            ),
        }
        factors = {
            name: RiskFactor(
                value=values[name],
                weight=weights[name],
                contribution=round(values[name] * weights[name], 4),
                rationale=rationales[name],
            )
            for name in values
        }
        raw_score = sum(values[name] * weights[name] for name in self._factor_order)
        score = round(min(max(raw_score, 0.0), 100.0), 2)
        level = self.level_for_score(score, config)
        explanation = (
            f"{level.value} risk ({score:.2f}/100). "
            + " ".join(
                f"{name} {factor.value:.2f} × {factor.weight:.2f} = "
                f"{factor.contribution:.2f}."
                for name, factor in factors.items()
            )
        )
        return RiskAssessment(
            alert_id=alert.alert_id,
            risk_score=score,
            risk_level=level,
            factors=factors,
            formula=formula,
            explanation=explanation,
        )

    @staticmethod
    def level_for_score(score: float, config: RiskConfig | None = None) -> RiskLevel:
        """Map rounded 0–100 scores to configured low/medium/high/critical bands."""
        config = config or RiskConfig()
        if not 0.0 <= score <= 100.0:
            raise ValueError("risk score must be between 0 and 100")
        if score < config.medium_threshold:
            return RiskLevel.LOW
        if score < config.high_threshold:
            return RiskLevel.MEDIUM
        if score < config.critical_threshold:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def assess_many(self, alerts: Iterable[SecurityAlert]) -> list[RiskAssessment]:
        """Score each alert independently while retaining input order."""
        return [self.assess(alert) for alert in alerts]
