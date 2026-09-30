"""Detections for FortiGate security logs with explicit supporting evidence."""

from collections import defaultdict
from collections.abc import Sequence

from detection_engine.models.alert import AlertSeverity
from detection_engine.models.config import DetectionConfig
from detection_engine.rules.base import DetectionRule
from telemetry.schemas.event import TelemetryEvent


class FortiGateIPSRule(DetectionRule):
    rule_id = "DET-006-FORTIGATE-IPS"
    detection_id = "DETECTION-006"
    title = "FortiGate intrusion prevention alert"

    def evaluate(self, events: Sequence[TelemetryEvent], config: DetectionConfig):
        matches = [event for event in events if event.metadata.get("integration") == "fortigate"
                   and event.metadata.get("category") == "ips"]
        return [self.alert(events=[event], config=config, severity=AlertSeverity.HIGH,
                           confidence=0.95, description=f"FortiGate IPS detected {event.metadata.get('attack', event.message)}.",
                           evidence={"fortigate_event_id": event.metadata.get("fortigate_event_id"),
                                     "category": "ips", "signature": event.metadata.get("fortigate", {}).get("attack")},
                           metadata={"integration": "fortigate", "category": "ips"}) for event in matches]


class FortiGateDeniedBurstRule(DetectionRule):
    rule_id = "DET-007-FORTIGATE-DENIED-BURST"
    detection_id = "DETECTION-007"
    title = "Repeated FortiGate traffic denials"

    def evaluate(self, events: Sequence[TelemetryEvent], config: DetectionConfig):
        groups = defaultdict(list)
        for event in events:
            if (event.metadata.get("integration") == "fortigate"
                    and event.metadata.get("category") == "traffic"
                    and event.metadata.get("action", "").lower() in {"deny", "blocked"}):
                groups[event.metadata.get("source_ip", "")].append(event)
        alerts = []
        for source, rows in groups.items():
            if len(rows) >= 5:
                alerts.append(self.alert(events=rows, config=config, severity=AlertSeverity.MEDIUM,
                                         confidence=0.9, description=f"{len(rows)} FortiGate traffic denials from {source}.",
                                         evidence={"source_ip": source, "denied_event_count": len(rows),
                                                   "fortigate_event_ids": [row.metadata.get("fortigate_event_id") for row in rows]},
                                         metadata={"integration": "fortigate", "category": "traffic"}))
        return alerts
