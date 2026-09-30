"""Scenario catalog and in-memory execution facade."""

from __future__ import annotations

from typing import Optional

from telemetry.assets import AssetRegistry
from attack_simulator.scenarios import SCENARIO_TYPES
from attack_simulator.scenarios.base import Scenario, ScenarioResult


class ScenarioCatalog:
    """Create and list the phase 2 synthetic scenario implementations."""

    def __init__(self, registry: Optional[AssetRegistry] = None) -> None:
        self.registry = registry or AssetRegistry()

    def list_scenarios(self) -> tuple[type[Scenario], ...]:
        return SCENARIO_TYPES

    def get(self, scenario_id: str, seed: Optional[int] = None) -> Scenario:
        for scenario_type in self.list_scenarios():
            if scenario_type.scenario_id == scenario_id:
                return scenario_type(self.registry, seed=seed)
        available = ", ".join(item.scenario_id for item in self.list_scenarios())
        raise ValueError(f"unknown scenario {scenario_id!r}; available: {available}")


class AttackSimulation:
    """Generate attack-shaped event data in memory only."""

    def __init__(self, registry: Optional[AssetRegistry] = None) -> None:
        self.catalog = ScenarioCatalog(registry)

    def run(self, scenario_id: str, seed: Optional[int] = None, count: Optional[int] = None) -> ScenarioResult:
        return self.catalog.get(scenario_id, seed=seed).generate_events(count=count)
