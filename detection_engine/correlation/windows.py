"""Shared deterministic grouping and rolling time-window operations."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Hashable, Iterable, TypeVar

from detection_engine.models.alert import utc_timestamp
from telemetry.schemas.event import TelemetryEvent

K = TypeVar("K", bound=Hashable)


def group_by(
    events: Iterable[TelemetryEvent],
    key: Callable[[TelemetryEvent], K],
) -> dict[K, list[TelemetryEvent]]:
    """Group events by a caller-defined identity in timestamp order."""
    groups: dict[K, list[TelemetryEvent]] = defaultdict(list)
    for event in events:
        groups[key(event)].append(event)
    return {
        group_key: sorted(group, key=lambda event: (utc_timestamp(event.timestamp), event.event_id))
        for group_key, group in groups.items()
    }


def rolling_windows(
    events: Iterable[TelemetryEvent],
    window_seconds: int,
) -> list[tuple[datetime, list[TelemetryEvent]]]:
    """Return an inclusive trailing window ending at each event timestamp."""
    ordered = sorted(events, key=lambda event: (utc_timestamp(event.timestamp), event.event_id))
    windows: list[tuple[datetime, list[TelemetryEvent]]] = []
    left = 0
    for right, event in enumerate(ordered):
        end = utc_timestamp(event.timestamp)
        start = end - timedelta(seconds=window_seconds)
        while left < right and utc_timestamp(ordered[left].timestamp) < start:
            left += 1
        windows.append((end, ordered[left:right + 1]))
    return windows
