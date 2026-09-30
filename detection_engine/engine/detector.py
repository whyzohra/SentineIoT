"""Orchestration of modular rules over an event iterable."""

from collections.abc import Iterable, Sequence

from detection_engine.models.alert import SecurityAlert
from detection_engine.models.config import DetectionConfig
from detection_engine.rules import DEFAULT_RULES
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import TelemetryEvent


class DetectionEngine:
    """Evaluate a batch/stream of existing telemetry events with configured rules."""

    def __init__(self, config: DetectionConfig | None = None,
                 rules: Sequence[DetectionRule] | None = None) -> None:
        self.config = config or DetectionConfig()
        self.rules = tuple(rules) if rules is not None else DEFAULT_RULES

    def detect(self, events: Iterable[TelemetryEvent]) -> list[SecurityAlert]:
        """Consume an iterable once and return deterministic, sorted alerts."""
        event_batch = tuple(events)
        alerts = [alert for rule in self.rules for alert in rule.evaluate(event_batch, self.config)]
        return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    def process(self, events: Iterable[TelemetryEvent]) -> list[SecurityAlert]:
        """Alias for detect, useful at telemetry pipeline call sites."""
        return self.detect(events)
