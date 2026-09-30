"""Local CLI for running rules on JSONL events or Phase 2 simulation output."""

import argparse
import json
import sys

from attack_simulator import AttackSimulation
from detection_engine.engine import DetectionEngine
from detection_engine.mitre import MITREMapper
from telemetry.schemas.event import TelemetryEvent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m detection_engine")
    commands = parser.add_subparsers(dest="command", required=True)
    detect = commands.add_parser("detect", help="detect alerts from JSONL telemetry on stdin or a file")
    detect.add_argument("--input", help="JSONL event file (default: stdin)")
    demo = commands.add_parser("demo", help="run one Phase 2 scenario through the rule engine")
    demo.add_argument("scenario_id")
    demo.add_argument("--seed", type=int, default=7)
    demo.add_argument("--count", type=int, default=None)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "demo":
        result = AttackSimulation().run(args.scenario_id, seed=args.seed, count=args.count)
        events = list(result.generated_events)
    else:
        stream = open(args.input, encoding="utf-8") if args.input else sys.stdin
        try:
            events = [TelemetryEvent.model_validate_json(line)
                      for line in stream if line.strip()]
        finally:
            if args.input:
                stream.close()

    alerts = MITREMapper().enrich_many(DetectionEngine().detect(events))
    print(json.dumps({
        "event_count": len(events),
        "events": [event.to_dict() for event in events],
        "alert_count": len(alerts),
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
    }, indent=2))


if __name__ == "__main__":
    main()
