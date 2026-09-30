"""Detection 002: repeated failed authentication, with success escalation."""

from collections.abc import Sequence

from detection_engine.correlation import group_by, rolling_windows
from detection_engine.models.alert import AlertSeverity, utc_timestamp
from detection_engine.models.config import DetectionConfig
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import EventType, TelemetryEvent


def _account(event: TelemetryEvent) -> str:
    return str(event.metadata.get("user") or event.metadata.get("user_alias")
               or event.metadata.get("account") or "unknown")


def _auth_result(event: TelemetryEvent) -> str:
    return str(event.metadata.get("result", "")).upper()


class BruteForceRule(DetectionRule):
    """Repeated failures are MEDIUM; a later success raises severity to HIGH."""

    rule_id = "DET-002-AUTH-BRUTE-FORCE"
    detection_id = "DETECTION-002"
    title = "Repeated authentication failures"

    def evaluate(self, events: Sequence[TelemetryEvent],
                 config: DetectionConfig):
        auth_events = [event for event in events if event.event_type == EventType.AUTH_EVENT
                       and event.destination_asset is not None]
        grouped = group_by(auth_events, lambda event: (
            event.source_asset.asset_id,
            event.destination_asset.asset_id if event.destination_asset else "",
            _account(event),
        ))
        alerts = []
        for (source_id, target_id, account), group in grouped.items():
            for _, window in rolling_windows(group, config.auth_window_seconds):
                failures = [event for event in window if _auth_result(event) in {"FAILURE", "FAILED", "DENIED"}]
                if len(failures) < config.auth_failure_threshold:
                    continue
                # A later success inside the configured time window is corroborating
                # evidence, but is not required to detect repeated failed attempts.
                success_events = [event for event in group
                                  if _auth_result(event) in {"SUCCESS", "SUCCEEDED"}
                                  and (event_time(event) - event_time(failures[-1])).total_seconds() > 0
                                  and 0 <= (event_time(event) - event_time(failures[-1])).total_seconds()
                                  <= config.auth_window_seconds]
                success_after = bool(success_events)
                evidence_events = failures + success_events
                alerts.append(self.alert(
                    events=evidence_events,
                    config=config,
                    severity=AlertSeverity.HIGH if success_after else AlertSeverity.MEDIUM,
                    confidence=0.98 if success_after else 0.90,
                    description=(f"{len(failures)} authentication failures for account {account} at {target_id}"
                                 + (" were followed by a success." if success_after else " exceeded the configured threshold.")),
                    evidence={"account": account, "failed_attempt_count": len(failures),
                              "success_after_failures": success_after,
                              "window_seconds": config.auth_window_seconds,
                              "source_asset_id": source_id, "target_asset_id": target_id},
                    metadata={"account": account, "failed_attempt_count": len(failures),
                              "success_after_failures": success_after,
                              "source_asset_id": source_id, "target_asset_id": target_id},
                ))
                break
        return alerts


def event_time(event: TelemetryEvent):
    return utc_timestamp(event.timestamp)
