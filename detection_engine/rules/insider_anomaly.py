"""Detection 005: suspicious engineering, supervisory, or operator activity."""

from collections.abc import Sequence

from detection_engine.models.alert import AlertSeverity, utc_timestamp
from detection_engine.models.config import DetectionConfig
from detection_engine.correlation import group_by, rolling_windows
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import TelemetryEvent


def _account(event: TelemetryEvent) -> str | None:
    value = (event.metadata.get("user") or event.metadata.get("user_alias")
             or event.metadata.get("engineer") or event.metadata.get("account"))
    return str(value) if value is not None else None


class InsiderBehaviorRule(DetectionRule):
    """Medium for one contextual deviation; HIGH for explicit/unusual multi-signal activity."""

    rule_id = "DET-005-INSIDER-BEHAVIOR-ANOMALY"
    detection_id = "DETECTION-005"
    title = "Insider behavior anomaly"

    def evaluate(self, events: Sequence[TelemetryEvent],
                 config: DetectionConfig):
        alerts = []
        monitored = [event for event in events if event.event_type in config.insider_monitored_event_types]
        activity_evidence = {}
        baseline_limit = config.insider_activity_baseline_count * config.insider_activity_baseline_multiplier
        groups = group_by(monitored, lambda event: (
            event.source_asset.asset_id,
            _account(event) or "unknown",
            event.destination_asset.asset_id if event.destination_asset else "",
        ))
        for group in groups.values():
            for _, window in rolling_windows(group, config.insider_activity_window_seconds):
                if len(window) > baseline_limit:
                    activity_evidence[window[-1].event_id] = window
                    break

        for event in monitored:
            account = _account(event)
            source_id = event.source_asset.asset_id
            target_id = event.destination_asset.asset_id if event.destination_asset else None
            timestamp = utc_timestamp(event.timestamp)
            outside_window = not (config.maintenance_start_hour_utc <= timestamp.hour
                                  < config.maintenance_end_hour_utc)
            unusual_source = source_id not in config.trusted_insider_sources
            unusual_account = account is not None and account not in config.trusted_insider_accounts
            unusual_target = (target_id is not None and event.destination_asset.asset_type.value == "PLC"
                              and target_id not in config.approved_plc_targets)
            status = str(event.metadata.get("authorization_status", "")).upper()
            explicitly_unapproved = status in config.unauthorized_status_values
            activity_window = activity_evidence.get(event.event_id, [])
            unusually_frequent = bool(activity_window)
            indicators = [name for name, active in (
                ("outside_maintenance_window", outside_window),
                ("untrusted_source_asset", unusual_source),
                ("unrecognized_account", unusual_account),
                ("unapproved_target", unusual_target),
                ("explicitly_unapproved_activity", explicitly_unapproved),
                ("activity_frequency_above_baseline", unusually_frequent),
            ) if active]
            if not indicators:
                continue
            # HIGH requires explicit unapproved status or at least two independent
            # context deviations; a single weaker signal is MEDIUM.
            high_confidence = explicitly_unapproved or len(indicators) >= 2
            evidence_events = activity_window or [event]
            alerts.append(self.alert(
                events=evidence_events,
                config=config,
                severity=AlertSeverity.HIGH if high_confidence else AlertSeverity.MEDIUM,
                confidence=0.95 if high_confidence else 0.80,
                description=(f"{source_id} produced {event.event_type.value} activity with contextual "
                             f"anomalies: {', '.join(indicators)}."),
                evidence={"account": account, "indicators": indicators,
                          "maintenance_window_utc": [config.maintenance_start_hour_utc,
                                                      config.maintenance_end_hour_utc],
                          "observed_hour_utc": timestamp.hour,
                          "activity_count_in_window": len(activity_window) if activity_window else 1,
                          "activity_window_seconds": config.insider_activity_window_seconds,
                          "activity_baseline_count": config.insider_activity_baseline_count,
                          "activity_baseline_multiplier": config.insider_activity_baseline_multiplier},
                metadata={"account": account, "indicators": indicators,
                          "source_asset_id": source_id, "target_asset_id": target_id},
            ))
        return alerts
