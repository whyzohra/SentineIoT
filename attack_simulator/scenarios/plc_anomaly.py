"""Synthetic anomalous process reading; simulator process state is untouched."""

from typing import Optional

from telemetry.schemas.event import EventSeverity, EventType
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class PLCAnomalyScenario(Scenario):
    scenario_id = "plc_anomaly"
    name = "Synthetic PLC process anomaly"
    description = "Emit out-of-baseline PLC reading records without changing simulated process registers."
    source_asset_id = "PLC-001"
    target_asset_id = "SCADA-001"
    expected_severity = EventSeverity.CRITICAL
    expected_detection = "A process reading outside its configured normal envelope may indicate parameter or telemetry manipulation."
    mitre_attack = {
        "framework": "MITRE ATT&CK for ICS",
        "technique_id": "T0836",
        "technique_name": "Modify Parameter",
        "url": "https://attack.mitre.org/techniques/T0836/",
    }
    default_count = 3

    def generate_events(self, count: Optional[int] = None) -> ScenarioResult:
        events = []
        for index in range(self.event_count(count)):
            value = round(95.0 + self.rng.uniform(0.0, 5.0), 2)
            events.append(self.make_event(
                EventType.SENSOR_READING,
                f"Synthetic anomaly report: intake_line_pressure_psi = {value} (simulated only).",
                {
                    "parameter": "intake_line_pressure_psi",
                    "value": value,
                    "normal_range": [45.0, 60.0],
                    "anomaly": True,
                    "synthetic_reading": True,
                    "process_state_modified": False,
                },
            ))
        return self.result(events)
