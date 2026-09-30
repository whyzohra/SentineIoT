"""CLI demo that runs a simulated scenario through detection and risk scoring."""

import argparse
import json

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from risk_engine import RiskEngine


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m risk_engine")
    demo = parser.add_subparsers(dest="command", required=True).add_parser(
        "demo", help="run a Phase 2 simulation through detection, MITRE mapping, and risk scoring"
    )
    demo.add_argument("scenario_id")
    demo.add_argument("--seed", type=int, default=7)
    demo.add_argument("--count", type=int, default=None)
    args = parser.parse_args()

    simulation = AttackSimulation().run(args.scenario_id, seed=args.seed, count=args.count)
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(simulation.generated_events))
    assessments = RiskEngine().assess_many(alerts)
    print(json.dumps({
        "scenario_id": simulation.scenario_id,
        "event_count": len(simulation.generated_events),
        "alert_count": len(alerts),
        "risk_assessments": [assessment.model_dump(mode="json") for assessment in assessments],
    }, indent=2))


if __name__ == "__main__":
    main()
