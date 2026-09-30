"""Command line interface for synthetic attack telemetry scenarios."""

import argparse
import json
import sys

from attack_simulator.engine import AttackSimulation, ScenarioCatalog


SAFETY_BANNER = "SIMULATION ONLY — SentinelOT isolated laboratory"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m attack_simulator")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list available synthetic scenarios")
    run = commands.add_parser("run", help="generate synthetic telemetry for one scenario")
    run.add_argument("scenario_id")
    run.add_argument("--seed", type=int, default=None, help="make generated events reproducible")
    run.add_argument("--count", type=int, default=None, help="number of synthetic events to generate")
    return parser


def main() -> None:
    args = _parser().parse_args()
    catalog = ScenarioCatalog()
    if args.command == "list":
        print("Available synthetic scenarios:")
        for scenario_type in catalog.list_scenarios():
            print(f"- {scenario_type.scenario_id}: {scenario_type.name}")
        return

    print(SAFETY_BANNER)
    try:
        result = AttackSimulation().run(args.scenario_id, seed=args.seed, count=args.count)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(json.dumps({
        "scenario_id": result.scenario_id,
        "name": result.name,
        "description": result.description,
        "source_asset": result.source_asset.model_dump(mode="json"),
        "target_asset": result.target_asset.model_dump(mode="json") if result.target_asset else None,
        "expected_severity": result.expected_severity.value,
        "expected_detection": result.expected_detection,
        "mitre_attack": result.mitre_attack,
        "generated_events": [event.to_dict() for event in result.generated_events],
    }, indent=2))


if __name__ == "__main__":
    main()
