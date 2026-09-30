"""Deterministic all-synthetic normal baseline and anomalous OT fixture batches."""

from datetime import datetime, timedelta, timezone

from telemetry.assets import AssetRegistry
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


def _event(registry, event_id, seconds, source, destination, kind, *, severity=EventSeverity.INFO, message="Synthetic OT event"):
    return TelemetryEvent(
        event_id=event_id,
        timestamp=datetime(2026, 1, 1, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_asset=registry.get_asset(source).to_summary(),
        destination_asset=registry.get_asset(destination).to_summary() if destination else None,
        event_type=kind, severity=severity, message=message,
        metadata={"fixture": "deterministic_synthetic", "process_state_modified": False},
    )


def normal_baseline(count=84):
    """Return regular, known OT relationships and low-rate command activity."""
    registry = AssetRegistry()
    patterns = (
        ("PLC-001", "SCADA-001", EventType.SENSOR_READING),
        ("PLC-002", None, EventType.PLC_STATE_CHANGE),
        ("HMI-001", "PLC-001", EventType.NETWORK_CONNECTION),
        ("SCADA-001", "PLC-001", EventType.SCADA_COMMAND),
        ("ENGINEERING-001", "PLC-002", EventType.CONFIG_CHANGE),
        ("HMI-001", "PLC-002", EventType.HMI_INTERACTION),
        ("HMI-001", "SCADA-001", EventType.AUTH_EVENT),
    )
    return [_event(registry, f"normal-{index:03}", index * 90, *patterns[index % len(patterns)])
            for index in range(count)]


def anomalous_batch():
    """Return a command burst and a never-seen source-target relationship."""
    registry = AssetRegistry()
    start = 84 * 90
    events = [_event(registry, f"burst-{index:03}", start + index * 5, "SCADA-001", "PLC-001",
                     EventType.SCADA_COMMAND, severity=EventSeverity.MEDIUM,
                     message="Synthetic high-rate SCADA command") for index in range(10)]
    events.append(_event(registry, "relationship-novel-001", start + 60, "PLC-002", "PLC-001",
                         EventType.NETWORK_CONNECTION,
                         message="Synthetic previously unseen OT peer relationship"))
    return events
