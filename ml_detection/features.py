"""Deterministic, explainable numeric feature extraction from SentinelOT events."""

from collections import Counter
from datetime import datetime, timezone
from math import log1p

from telemetry.schemas.event import EventType, TelemetryEvent


FEATURE_NAMES = (
    "is_plc_command", "commands_from_source_to_target_60s", "historical_relationship_count",
    "historical_source_count", "historical_event_type_count", "severity_score",
    "source_purdue_level", "target_purdue_level",
)
COMMAND_TYPES = {EventType.SCADA_COMMAND, EventType.CONFIG_CHANGE, EventType.HMI_INTERACTION}


def _identity(event: TelemetryEvent) -> tuple[str, str, str]:
    return (event.source_asset.asset_id,
            event.destination_asset.asset_id if event.destination_asset else "<none>",
            event.event_type.value)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class OTFeatureExtractor:
    """Extract stable relationship, rate, severity, and Purdue-level features.

    Reference counts describe the historical normal baseline. The 60-second
    command count includes the candidate stream up to each event, so a command
    burst becomes progressively more visible.
    """

    def extract(self, events: list[TelemetryEvent], *,
                reference_events: list[TelemetryEvent] | None = None) -> list[dict[str, float]]:
        reference = reference_events if reference_events is not None else events
        pair_counts = Counter((item.source_asset.asset_id,
                               item.destination_asset.asset_id if item.destination_asset else "<none>")
                              for item in reference)
        source_counts = Counter(item.source_asset.asset_id for item in reference)
        type_counts = Counter(item.event_type.value for item in reference)
        combined = sorted([*reference, *events], key=lambda item: (_utc(item.timestamp), item.event_id))
        rows = []
        for event in sorted(events, key=lambda item: (_utc(item.timestamp), item.event_id)):
            source_id, target_id, event_type = _identity(event)
            is_command = event.event_type in COMMAND_TYPES
            at = _utc(event.timestamp)
            recent_commands = sum(
                item.event_type in COMMAND_TYPES
                and item.source_asset.asset_id == source_id
                and (item.destination_asset.asset_id if item.destination_asset else "<none>") == target_id
                and 0 <= (at - _utc(item.timestamp)).total_seconds() <= 60
                for item in combined
            ) if is_command else 0
            rows.append({
                "is_plc_command": float(is_command),
                "commands_from_source_to_target_60s": log1p(recent_commands),
                "historical_relationship_count": log1p(pair_counts[(source_id, target_id)]),
                "historical_source_count": log1p(source_counts[source_id]),
                "historical_event_type_count": log1p(type_counts[event_type]),
                "severity_score": float({"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[event.severity.value]),
                "source_purdue_level": float(event.source_asset.purdue_level),
                "target_purdue_level": float(event.destination_asset.purdue_level if event.destination_asset else 5),
            })
        return rows
