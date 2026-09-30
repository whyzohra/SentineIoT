"""Shared scenario contract and deterministic event construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import random
from typing import Optional
from uuid import NAMESPACE_URL, uuid5

from telemetry.assets import AssetRegistry
from telemetry.schemas.asset import AssetSummary
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


@dataclass(frozen=True)
class ScenarioResult:
    """Scenario metadata and the telemetry records generated for one run."""

    scenario_id: str
    name: str
    description: str
    source_asset: AssetSummary
    target_asset: Optional[AssetSummary]
    generated_events: tuple[TelemetryEvent, ...]
    expected_severity: EventSeverity
    expected_detection: str
    mitre_attack: dict[str, str]


class Scenario(ABC):
    """Base class for telemetry-only scenarios; performs no network I/O."""

    scenario_id: str
    name: str
    description: str
    source_asset_id: str
    target_asset_id: Optional[str]
    expected_severity: EventSeverity
    expected_detection: str
    mitre_attack: dict[str, str]
    default_count = 1

    def __init__(self, registry: AssetRegistry, seed: Optional[int] = None) -> None:
        self.registry = registry
        self.seed = seed
        self.rng = random.Random(seed)
        self._event_index = 0
        self._run_key = f"{self.scenario_id}:{seed}" if seed is not None else f"{self.scenario_id}:{random.getrandbits(128)}"
        self.source_asset = self._summary(self.source_asset_id)
        self.target_asset = self._summary(self.target_asset_id) if self.target_asset_id else None

    def _summary(self, asset_id: str) -> AssetSummary:
        summary = self.registry.get_summary(asset_id)
        if summary is None:
            raise ValueError(f"registry is missing required simulated asset {asset_id}")
        return summary

    def make_event(
        self,
        event_type: EventType,
        message: str,
        metadata: dict,
        *,
        severity: Optional[EventSeverity] = None,
        target: Optional[AssetSummary] = None,
    ) -> TelemetryEvent:
        """Build a schema-validated event with stable identifiers for seeded runs."""
        index = self._event_index
        self._event_index += 1
        return TelemetryEvent(
            event_id=str(uuid5(NAMESPACE_URL, f"sentinelot:{self._run_key}:{index}")),
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
            source_asset=self.source_asset,
            destination_asset=target if target is not None else self.target_asset,
            event_type=event_type,
            severity=severity or self.expected_severity,
            message=message,
            metadata={
                **metadata,
                "scenario_id": self.scenario_id,
                "simulation_only": True,
                "mitre_attack": self.mitre_attack.copy(),
            },
        )

    @abstractmethod
    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        """Generate synthetic telemetry without changing assets or contacting systems."""

    def event_count(self, count: Optional[int]) -> int:
        result = self.default_count if count is None else count
        if result < 1:
            raise ValueError("count must be at least 1")
        return result

    def result(self, events: list[TelemetryEvent]) -> ScenarioResult:
        return ScenarioResult(
            scenario_id=self.scenario_id,
            name=self.name,
            description=self.description,
            source_asset=self.source_asset,
            target_asset=self.target_asset,
            generated_events=tuple(events),
            expected_severity=self.expected_severity,
            expected_detection=self.expected_detection,
            mitre_attack=self.mitre_attack.copy(),
        )
