"""Reproducible Isolation Forest fitting, inference, evidence, and alerts."""

from dataclasses import dataclass
from statistics import median
from typing import Any

from detection_engine.models.alert import AlertSeverity, SecurityAlert
from ml_detection.features import FEATURE_NAMES, OTFeatureExtractor
from telemetry.schemas.event import TelemetryEvent


RULE_ID = "ML-001-OT-BEHAVIOR-ANOMALY"


@dataclass(frozen=True)
class AnomalyFinding:
    event: TelemetryEvent
    anomaly_score: float
    feature_evidence: dict[str, dict[str, float]]
    unusual_features: tuple[str, ...]

    def to_alert(self) -> SecurityAlert:
        severity = AlertSeverity.HIGH if len(self.unusual_features) >= 2 else AlertSeverity.MEDIUM
        return SecurityAlert.from_rule(
            rule_id=RULE_ID, timestamp=self.event.timestamp, severity=severity,
            confidence=min(0.89, 0.65 + 0.08 * min(len(self.unusual_features), 3)),
            title="ML anomaly: unusual OT behavior",
            description=("Isolation Forest flagged telemetry outside its synthetic historical baseline; "
                         f"unusual features: {', '.join(self.unusual_features)}."),
            source_assets=[self.event.source_asset],
            target_assets=[self.event.destination_asset] if self.event.destination_asset else [],
            evidence={"event_ids": [self.event.event_id], "anomaly_score": round(self.anomaly_score, 6),
                      "feature_evidence": self.feature_evidence,
                      "unusual_features": list(self.unusual_features), "model": "IsolationForest",
                      "baseline_type": "synthetic_normal_telemetry"},
            metadata={"ml_generated": True, "detection_source": "ML", "model_name": "IsolationForest",
                      "model_version": "1", "rule_id": RULE_ID},
        )


class IsolationForestModel:
    """Isolation Forest trained only from supplied normal synthetic events."""

    def __init__(self, *, random_state: int = 7, contamination: float | str = "auto",
                 n_estimators: int = 200) -> None:
        if contamination != "auto" and (not isinstance(contamination, (float, int)) or not 0 < contamination <= 0.5):
            raise ValueError("contamination must be 'auto' or a value in (0, 0.5]")
        if n_estimators < 10:
            raise ValueError("n_estimators must be at least 10")
        self.random_state = random_state
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.extractor = OTFeatureExtractor()
        self._model = None
        self._baseline: list[TelemetryEvent] = []
        self._ranges: dict[str, tuple[float, float, float]] = {}

    def fit(self, normal_events: list[TelemetryEvent]) -> "IsolationForestModel":
        if len(normal_events) < 10:
            raise ValueError("At least 10 synthetic normal events are required to train")
        from sklearn.ensemble import IsolationForest
        self._baseline = list(normal_events)
        matrix = self._matrix(self.extractor.extract(self._baseline, reference_events=self._baseline))
        self._model = IsolationForest(n_estimators=self.n_estimators, contamination=self.contamination,
                                      random_state=self.random_state, n_jobs=1)
        self._model.fit(matrix)
        for name in FEATURE_NAMES:
            values = [row[name] for row in self.extractor.extract(self._baseline, reference_events=self._baseline)]
            center = median(values)
            lower, upper = self._quantile(values, 0.05), self._quantile(values, 0.95)
            self._ranges[name] = (center, lower, upper)
        return self

    @staticmethod
    def _quantile(values: list[float], fraction: float) -> float:
        ordered = sorted(values)
        return ordered[round((len(ordered) - 1) * fraction)]

    @staticmethod
    def _matrix(rows: list[dict[str, float]]):
        return [[row[name] for name in FEATURE_NAMES] for row in rows]

    def predict(self, events: list[TelemetryEvent]) -> list[AnomalyFinding]:
        if self._model is None:
            raise RuntimeError("Call fit with a normal synthetic baseline before inference")
        rows = self.extractor.extract(events, reference_events=self._baseline)
        if not rows:
            return []
        matrix = self._matrix(rows)
        labels = self._model.predict(matrix)
        scores = -self._model.score_samples(matrix)
        findings = []
        for event, row, label, score in zip(sorted(events, key=lambda item: (item.timestamp, item.event_id)), rows, labels, scores):
            if label != -1:
                continue
            evidence = {}
            deviations = []
            for name, value in row.items():
                center, lower, upper = self._ranges[name]
                spread = max(upper - lower, 0.25)
                distance = max(lower - value, value - upper, 0.0) / spread
                evidence[name] = {"value": round(value, 6), "baseline_median": round(center, 6),
                                  "baseline_p05": round(lower, 6), "baseline_p95": round(upper, 6),
                                  "deviation": round(distance, 6)}
                if distance > 0:
                    deviations.append((distance, name))
            unusual = tuple(name for _, name in sorted(deviations, reverse=True)[:4])
            findings.append(AnomalyFinding(event, float(score), evidence, unusual or ("multivariate_pattern",)))
        return findings

    def save(self, path: str) -> None:
        if self._model is None:
            raise RuntimeError("Cannot save before fit")
        import joblib
        joblib.dump({"model": self._model, "baseline": [event.model_dump(mode="json") for event in self._baseline],
                     "ranges": self._ranges, "random_state": self.random_state,
                     "contamination": self.contamination, "n_estimators": self.n_estimators}, path)

    @classmethod
    def load(cls, path: str) -> "IsolationForestModel":
        import joblib
        from telemetry.schemas.event import TelemetryEvent
        saved: dict[str, Any] = joblib.load(path)
        instance = cls(random_state=saved["random_state"], contamination=saved["contamination"],
                       n_estimators=saved["n_estimators"])
        instance._model = saved["model"]
        instance._baseline = [TelemetryEvent.model_validate(item) for item in saved["baseline"]]
        instance._ranges = saved["ranges"]
        return instance
