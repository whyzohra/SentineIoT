"""Simulated asset-enumeration activity represented as local event records."""

from typing import Optional

from telemetry.schemas.event import EventSeverity, EventType
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class NetworkReconScenario(Scenario):
    scenario_id = "network_recon"
    name = "Synthetic network reconnaissance"
    description = "Emit synthetic asset-enumeration connection events; no probes or packets are sent."
    source_asset_id = "ENGINEERING-001"
    target_asset_id = None
    expected_severity = EventSeverity.MEDIUM
    expected_detection = "One source referencing multiple OT assets in a short interval may indicate asset enumeration."
    mitre_attack = {
        "framework": "MITRE ATT&CK for ICS",
        "technique_id": "T0846",
        "technique_name": "Remote System Discovery",
        "url": "https://attack.mitre.org/techniques/T0846/",
    }
    default_count = 5

    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        event_count = self.event_count(count)
        candidates = [asset.to_summary() for asset in self.registry.list_assets()
                      if asset.asset_id != self.source_asset_id]
        events = []
        for index in range(event_count):
            target = candidates[index % len(candidates)]
            events.append(self.make_event(
                EventType.NETWORK_CONNECTION,
                f"Synthetic asset enumeration referenced {target.asset_id}; no network request was sent.",
                {"activity": "SYNTHETIC_ASSET_ENUMERATION", "protocol": "SIMULATED", "connection_result": "NOT_PERFORMED"},
                target=target,
            ))
        return self.result(events)
