"""Scenario implementations that emit telemetry only."""

from attack_simulator.scenarios.base import Scenario, ScenarioResult
from attack_simulator.scenarios.brute_force import BruteForceScenario
from attack_simulator.scenarios.insider_anomaly import InsiderAnomalyScenario
from attack_simulator.scenarios.network_recon import NetworkReconScenario
from attack_simulator.scenarios.plc_anomaly import PLCAnomalyScenario
from attack_simulator.scenarios.unauthorized_plc import UnauthorizedPLCScenario

SCENARIO_TYPES = (
    NetworkReconScenario,
    BruteForceScenario,
    UnauthorizedPLCScenario,
    PLCAnomalyScenario,
    InsiderAnomalyScenario,
)

__all__ = ["Scenario", "ScenarioResult", "SCENARIO_TYPES"]
