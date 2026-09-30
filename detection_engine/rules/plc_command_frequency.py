"""Detection 004: PLC-directed command volume above configured normal baseline."""

from collections.abc import Sequence

from detection_engine.correlation import group_by, rolling_windows
from detection_engine.models.alert import AlertSeverity
from detection_engine.models.config import DetectionConfig
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import TelemetryEvent


class PLCCommandFrequencyRule(DetectionRule):
    """HIGH indicates unusual command volume; no process-impact claim is made."""

    rule_id = "DET-004-PLC-COMMAND-FREQUENCY"
    detection_id = "DETECTION-004"
    title = "Abnormal PLC command frequency"

    def evaluate(self, events: Sequence[TelemetryEvent],
                 config: DetectionConfig):
        commands = [event for event in events
                    if event.event_type in config.plc_command_event_types
                    and event.destination_asset is not None
                    and event.destination_asset.asset_type.value == "PLC"]
        grouped = group_by(commands, lambda event: (
            event.source_asset.asset_id,
            event.destination_asset.asset_id if event.destination_asset else "",
        ))
        alerts = []
        baseline = config.plc_command_baseline_per_minute
        threshold = baseline * config.plc_command_baseline_multiplier
        for (_, _), group in grouped.items():
            for _, window in rolling_windows(group, config.plc_command_window_seconds):
                observed = len(window) * 60.0 / config.plc_command_window_seconds
                if observed <= threshold:
                    continue
                source = window[-1].source_asset
                target = window[-1].destination_asset
                alerts.append(self.alert(
                    events=window,
                    config=config,
                    severity=AlertSeverity.HIGH,
                    confidence=0.90,
                    description=(f"Observed {observed:.2f} PLC-directed commands/minute, above the "
                                 f"configured threshold of {threshold:.2f}/minute."),
                    evidence={"observed_frequency": observed,
                              "baseline_frequency": baseline,
                              "baseline_multiplier": config.plc_command_baseline_multiplier,
                              "window_seconds": config.plc_command_window_seconds,
                              "threshold_frequency": threshold},
                    source_assets=[source],
                    target_assets=[target] if target else [],
                    metadata={"observed_frequency": observed, "baseline_frequency": baseline},
                ))
                break
        return alerts
