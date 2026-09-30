"""Synthetic anomalous engineering activity from a registered lab asset."""

from typing import Optional

from telemetry.schemas.event import EventSeverity, EventType
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class InsiderAnomalyScenario(Scenario):
    scenario_id = "insider_anomaly"
    name = "Synthetic insider configuration anomaly"
    description = "Emit audit records of unusual engineering changes; no PLC configuration is modified."
    source_asset_id = "ENGINEERING-001"
    target_asset_id = "PLC-002"
    expected_severity = EventSeverity.HIGH
    expected_detection = "An unapproved engineering change outside the maintenance window may indicate insider misuse."
    mitre_attack = {
        "framework": "MITRE ATT&CK for ICS",
        "technique_id": "T0859",
        "technique_name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T0859/",
    }

    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        events = [self.make_event(
            EventType.CONFIG_CHANGE,
            "Synthetic unapproved engineering change audit record; no configuration was applied.",
            {
                "change_type": "SIMULATED_PARAMETER_EDIT",
                "user_alias": "authorized_engineer_simulated",
                "authorization_status": "UNAPPROVED_SIMULATED",
                "maintenance_window": False,
                "change_applied": False,
            },
        ) for _ in range(self.event_count(count))]
        return self.result(events)
