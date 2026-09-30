"""Synthetic unauthorized PLC command event; no controller state is changed."""

from typing import Optional

from telemetry.schemas.event import EventSeverity, EventType
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class UnauthorizedPLCScenario(Scenario):
    scenario_id = "unauthorized_plc"
    name = "Synthetic unauthorized PLC command"
    description = "Record an unauthorized-command event against a synthetic PLC; command execution is not attempted."
    source_asset_id = "HMI-001"
    target_asset_id = "PLC-001"
    expected_severity = EventSeverity.HIGH
    expected_detection = "A command from an unapproved principal or source may indicate unauthorized control activity."
    mitre_attack = {
        "framework": "MITRE ATT&CK for ICS",
        "technique_id": "T1692.001",
        "technique_name": "Unauthorized Message: Command Message",
        "url": "https://attack.mitre.org/techniques/T1692/001/",
    }

    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        events = [self.make_event(
            EventType.SCADA_COMMAND,
            "Synthetic unauthorized PLC command recorded; command was not executed.",
            {
                "command_type": "SIMULATED_SETPOINT_WRITE",
                "principal": "unapproved_lab_identity",
                "authorization_status": "DENIED_SIMULATED",
                "command_executed": False,
                "protocol": "SIMULATED",
            },
        ) for _ in range(self.event_count(count))]
        return self.result(events)
