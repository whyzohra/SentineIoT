"""Rule interface and shared alert evidence helpers."""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence

from detection_engine.models.alert import AlertSeverity, SecurityAlert, utc_timestamp
from detection_engine.models.config import DetectionConfig
from telemetry.schemas.asset import AssetSummary
from telemetry.schemas.event import TelemetryEvent


class DetectionRule(ABC):
    """A rule evaluates an event batch and returns zero or more alerts."""

    rule_id: str
    detection_id: str
    title: str

    @abstractmethod
    def evaluate(self, events: Sequence[TelemetryEvent], config: DetectionConfig) -> list[SecurityAlert]:
        """Evaluate telemetry and return matching alerts."""

    def alert(
        self,
        *,
        events: Sequence[TelemetryEvent],
        config: DetectionConfig,
        severity: AlertSeverity,
        confidence: float,
        description: str,
        evidence: dict,
        metadata: dict | None = None,
        source_assets: list[AssetSummary] | None = None,
        target_assets: list[AssetSummary] | None = None,
    ) -> SecurityAlert:
        event_ids = [event.event_id for event in events]
        return SecurityAlert.from_rule(
            rule_id=self.rule_id,
            timestamp=max((utc_timestamp(event.timestamp) for event in events)),
            severity=severity,
            confidence=confidence,
            title=self.title,
            description=description,
            source_assets=source_assets or unique_assets(event.source_asset for event in events),
            target_assets=target_assets or unique_assets(
                event.destination_asset for event in events if event.destination_asset is not None
            ),
            evidence={**evidence, "event_ids": event_ids},
            metadata={"detection_id": self.detection_id, **(metadata or {})},
        )


def unique_assets(assets: Iterable[AssetSummary]) -> list[AssetSummary]:
    """Deduplicate asset summaries by ID while preserving encounter order."""
    results: dict[str, AssetSummary] = {}
    for asset in assets:
        results.setdefault(asset.asset_id, asset)
    return list(results.values())
