"""Detection 001: source contacting many distinct OT assets in a short window."""

from collections.abc import Sequence

from detection_engine.correlation import group_by, rolling_windows
from detection_engine.models.alert import AlertSeverity
from detection_engine.models.config import DetectionConfig
from detection_engine.rules.base import DetectionRule, unique_assets
from telemetry.schemas.event import EventType, TelemetryEvent


class NetworkReconRule(DetectionRule):
    """Discovery activity is MEDIUM: it indicates asset discovery, not process impact."""

    rule_id = "DET-001-NETWORK-RECON"
    detection_id = "DETECTION-001"
    title = "OT network reconnaissance"

    def evaluate(self, events: Sequence[TelemetryEvent],
                 config: DetectionConfig):
        grouped = group_by(
            (event for event in events if event.event_type == EventType.NETWORK_CONNECTION
             and event.destination_asset is not None),
            lambda event: event.source_asset.asset_id,
        )
        alerts = []
        for source_id, source_events in grouped.items():
            for _, window in rolling_windows(source_events, config.network_recon_window_seconds):
                targets = unique_assets(event.destination_asset for event in window if event.destination_asset)
                if len(targets) < config.network_recon_unique_target_threshold:
                    continue
                alerts.append(self.alert(
                    events=window,
                    config=config,
                    severity=AlertSeverity.MEDIUM,
                    confidence=0.90,
                    description=(f"{source_id} referenced {len(targets)} unique OT assets within "
                                 f"{config.network_recon_window_seconds} seconds."),
                    evidence={"unique_destination_count": len(targets),
                              "window_seconds": config.network_recon_window_seconds,
                              "affected_assets": [asset.asset_id for asset in targets]},
                    source_assets=[window[0].source_asset],
                    target_assets=targets,
                    metadata={"affected_assets": [asset.model_dump(mode="json") for asset in targets]},
                ))
                break
        return alerts
