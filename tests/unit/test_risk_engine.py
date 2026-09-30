import json
import subprocess
import sys
from pathlib import Path

import pytest

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from detection_engine.models.alert import AlertSeverity, SecurityAlert
from telemetry.assets import AssetRegistry
from risk_engine import RiskAssessment, RiskConfig, RiskEngine, RiskLevel


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = AssetRegistry()


def make_alert(severity=AlertSeverity.MEDIUM, confidence=0.8, *, evidence=None, mapped=False,
               asset_id="PLC-001"):
    asset = REGISTRY.get_asset(asset_id)
    alert = SecurityAlert.from_rule(
        rule_id="DET-001-NETWORK-RECON" if mapped else "TEST-RISK-RULE",
        timestamp=AttackSimulation().run("network_recon", seed=1, count=1).generated_events[0].timestamp,
        severity=severity,
        confidence=confidence,
        title="Synthetic test alert",
        description="Risk scoring fixture",
        source_assets=[asset.to_summary()],
        target_assets=[],
        evidence=evidence or {"event_ids": ["event-1"], "signal": "measured"},
    )
    if mapped:
        alert = MITREMapper().enrich(alert)
    return alert


def severity_only_config():
    return RiskConfig(
        severity_weight=1.0,
        confidence_weight=0.0,
        asset_criticality_weight=0.0,
        evidence_quantity_weight=0.0,
        evidence_quality_weight=0.0,
        mitre_mapping_weight=0.0,
    )


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0.0, RiskLevel.LOW),
        (24.99, RiskLevel.LOW),
        (25.0, RiskLevel.MEDIUM),
        (49.99, RiskLevel.MEDIUM),
        (50.0, RiskLevel.HIGH),
        (74.99, RiskLevel.HIGH),
        (75.0, RiskLevel.CRITICAL),
        (100.0, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundary_scores(score, level):
    assert RiskEngine.level_for_score(score) == level


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (AlertSeverity.LOW, RiskLevel.LOW),
        (AlertSeverity.MEDIUM, RiskLevel.MEDIUM),
        (AlertSeverity.HIGH, RiskLevel.HIGH),
        (AlertSeverity.CRITICAL, RiskLevel.CRITICAL),
    ],
)
def test_each_risk_level_is_reachable_with_severity_only_weights(severity, expected_level):
    result = RiskEngine(config=severity_only_config()).assess(make_alert(severity=severity))
    assert result.risk_level == expected_level
    assert isinstance(RiskAssessment.model_validate(result.model_dump()), RiskAssessment)


def test_weighted_formula_explains_every_input_and_does_not_mutate_alert():
    alert = make_alert(
        severity=AlertSeverity.CRITICAL,
        confidence=1.0,
        evidence={
            "event_ids": [f"event-{index}" for index in range(5)],
            "observed_count": 5,
            "threshold": 3,
            "source": "simulated",
            "target": "PLC-001",
        },
        mapped=True,
    )
    before = alert.model_dump(mode="json")
    result = RiskEngine().assess(alert)
    assert result.risk_score == 100.0
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.factors["severity"].contribution == pytest.approx(30.0)
    assert result.factors["confidence"].contribution == pytest.approx(20.0)
    assert result.factors["asset_criticality"].value == 100.0
    assert result.factors["evidence_quantity"].value == 100.0
    assert result.factors["evidence_quality"].value == 100.0
    assert result.factors["mitre_mapping"].value == 100.0
    assert all(factor.rationale for factor in result.factors.values())
    assert "severity×0.30" in result.formula
    assert "CRITICAL risk (100.00/100)" in result.explanation
    assert alert.model_dump(mode="json") == before


def test_confidence_evidence_quantity_quality_and_asset_criticality_affect_score():
    engine = RiskEngine()
    concise = make_alert(severity=AlertSeverity.HIGH, confidence=0.4,
                         evidence={"event_ids": ["one"]})
    supported = make_alert(severity=AlertSeverity.HIGH, confidence=0.9,
                           evidence={"event_ids": [str(i) for i in range(5)],
                                     "signal": 1, "threshold": 2, "window": 60, "action": "write"})
    assert engine.assess(supported).risk_score > engine.assess(concise).risk_score
    assert engine.assess(supported).factors["evidence_quantity"].value == 100.0
    assert engine.assess(supported).factors["evidence_quality"].value == 100.0

    low_criticality = make_alert(asset_id="HMI-001")
    high_criticality = make_alert(asset_id="PLC-001")
    assert engine.assess(high_criticality).factors["asset_criticality"].value > \
        engine.assess(low_criticality).factors["asset_criticality"].value


def test_unmapped_alert_receives_no_mitre_bonus_and_unknown_asset_uses_configured_fallback():
    registry = AssetRegistry()
    alert = make_alert(mapped=False)
    assessment = RiskEngine(registry=registry).assess(alert)
    assert assessment.factors["mitre_mapping"].value == 0.0

    unknown_summary = alert.source_assets[0].model_copy(update={"asset_id": "PLC-UNKNOWN"})
    unknown_alert = alert.model_copy(update={"source_assets": [unknown_summary]})
    result = RiskEngine().assess(unknown_alert)
    assert result.factors["asset_criticality"].value == pytest.approx(60.0)
    assert "PLC-UNKNOWN" in result.factors["asset_criticality"].rationale


def test_risk_config_rejects_invalid_weights_and_thresholds():
    with pytest.raises(ValueError, match="sum to 1.0"):
        RiskConfig(severity_weight=0.5)
    with pytest.raises(ValueError, match="thresholds"):
        RiskConfig(medium_threshold=60, high_threshold=50)


def test_risk_cli_demo_scores_a_detected_scenario():
    result = subprocess.run(
        [sys.executable, "-m", "risk_engine", "demo", "network_recon", "--seed", "7"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    assert report["event_count"] == 5
    assert report["alert_count"] >= 1
    assessment = report["risk_assessments"][0]
    assert 0 <= assessment["risk_score"] <= 100
    assert assessment["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert assessment["factors"]["mitre_mapping"]["value"] == 100
