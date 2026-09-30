"""Deterministic, synthetic incidents for response workflow tests and demos."""

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from incident_management import IncidentService, SQLiteIncidentRepository
from risk_engine import RiskEngine


def seeded_incident(repository: SQLiteIncidentRepository, *, scenario: str = "network_recon", seed: int = 7):
    """Run an existing safe simulation into the regular incident store."""
    simulation = AttackSimulation().run(scenario, seed=seed, count=12 if scenario == "brute_force" else None)
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(simulation.generated_events))
    service = IncidentService(repository)
    incidents = [service.ingest(alert, assessment).incident
                 for alert, assessment in zip(alerts, RiskEngine().assess_many(alerts))]
    if not incidents:
        raise ValueError(f"Fixture scenario {scenario!r} did not produce an incident")
    return incidents[0]
