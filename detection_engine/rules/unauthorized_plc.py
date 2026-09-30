"""Detection 003: PLC-directed actions outside the simulated authorization policy."""

from collections.abc import Sequence

from detection_engine.models.alert import AlertSeverity
from detection_engine.models.config import DetectionConfig
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import EventType, TelemetryEvent


class UnauthorizedPLCAccessRule(DetectionRule):
    """Unauthorized PLC access is HIGH because a controller boundary was crossed."""

    rule_id = "DET-003-UNAUTHORIZED-PLC-ACCESS"
    detection_id = "DETECTION-003"
    title = "Unauthorized PLC access"
    _access_types = {EventType.NETWORK_CONNECTION, EventType.SCADA_COMMAND,
                     EventType.CONFIG_CHANGE, EventType.HMI_INTERACTION}

    def evaluate(self, events: Sequence[TelemetryEvent],
                 config: DetectionConfig):
        alerts = []
        for event in events:
            target = event.destination_asset
            if event.event_type not in self._access_types or target is None or target.asset_type.value != "PLC":
                continue
            # Phase 2 recon events represent synthetic references only, explicitly
            # marked as not performed; they must not be classified as PLC access.
            if str(event.metadata.get("connection_result", "")).upper() == "NOT_PERFORMED":
                continue
            allowed = config.authorized_plc_sources.get(target.asset_id, frozenset())
            status = str(event.metadata.get("authorization_status", "")).upper()
            explicitly_denied = status in config.unauthorized_status_values
            source_not_allowed = event.source_asset.asset_id not in allowed
            if not (explicitly_denied or source_not_allowed):
                continue
            access_type = str(event.metadata.get("command_type") or event.metadata.get("action")
                              or event.event_type.value)
            self_confidence = 0.99 if explicitly_denied else 0.92
            alerts.append(self.alert(
                events=[event],
                config=config,
                severity=AlertSeverity.HIGH,
                confidence=self_confidence,
                description=(f"{event.source_asset.asset_id} attempted {access_type} access to "
                             f"{target.asset_id} outside the simulated PLC authorization policy."),
                evidence={"access_type": access_type,
                          "authorization_status": status or "NOT_AUTHORIZED_BY_SOURCE_ALLOWLIST",
                          "authorized_sources": sorted(allowed)},
                metadata={"access_type": access_type},
            ))
        return alerts
