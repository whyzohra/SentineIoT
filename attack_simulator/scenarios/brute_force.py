"""Synthetic failed-authentication telemetry without credential attempts."""

from typing import Optional

from telemetry.schemas.event import EventSeverity, EventType
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class BruteForceScenario(Scenario):
    scenario_id = "brute_force"
    name = "Synthetic authentication burst"
    description = "Emit failed-authentication audit events; no passwords or login requests are used."
    source_asset_id = "ENGINEERING-001"
    target_asset_id = "HMI-001"
    expected_severity = EventSeverity.HIGH
    expected_detection = "Repeated failed authentication events for one target in a short interval may indicate brute force."
    mitre_attack = {
        "framework": "MITRE ATT&CK Enterprise",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    }
    default_count = 5

    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        events = [self.make_event(
            EventType.AUTH_EVENT,
            "Synthetic authentication failure recorded; no credential was submitted.",
            {
                "auth_method": "SIMULATED_AUDIT_ONLY",
                "user_alias": f"lab_operator_{self.rng.randint(1, 3)}",
                "result": "FAILURE",
                "attempt_number": index + 1,
                "credential_attempted": False,
            },
        ) for index in range(self.event_count(count))]
        return self.result(events)
