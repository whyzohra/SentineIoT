"""Incident workflow CLI and complete local attack-to-incident demonstration."""

import argparse
import json
import sys
from typing import Any

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from incident_management import CorrelationConfig, IncidentService, IncidentStatus, SQLiteIncidentRepository
from risk_engine import RiskEngine


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m incident_management")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list persisted incidents")
    listing.add_argument("--status", choices=[state.value for state in IncidentStatus])
    view = commands.add_parser("view", help="show one incident and its investigation history")
    view.add_argument("incident_id")
    update = commands.add_parser("update", help="change incident status with an audited transition")
    update.add_argument("incident_id")
    update.add_argument("status", choices=[state.value for state in IncidentStatus])
    update.add_argument("--actor", default="analyst")
    update.add_argument("--reason")
    investigate = commands.add_parser("investigate", help="start/continue investigation and record a note")
    investigate.add_argument("incident_id")
    investigate.add_argument("--note", required=True)
    investigate.add_argument("--actor", default="analyst")
    attach = commands.add_parser("attach", help="attach evidence metadata only (no file upload)")
    attach.add_argument("incident_id")
    attach.add_argument("--label", required=True)
    attach.add_argument("--metadata", default="{}", help="JSON metadata object; attachment bytes are not accepted")
    attach.add_argument("--actor", default="analyst")
    demo = commands.add_parser("demo", help="simulate, detect, map MITRE, assess risk, and persist an incident")
    demo.add_argument("scenario_id")
    demo.add_argument("--db", default=".sentinelot-incidents.sqlite3")
    demo.add_argument("--seed", type=int, default=7)
    demo.add_argument("--count", type=int, default=None)
    demo.add_argument("--window-seconds", type=int, default=900,
                      help="maximum alert timestamp distance for incident correlation")
    for command in (listing, view, update, investigate, attach):
        command.add_argument("--db", default=".sentinelot-incidents.sqlite3")
    return parser


def _print(value: Any) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif isinstance(value, list):
        value = [item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in value]
    print(json.dumps(value, indent=2, ensure_ascii=False))


def main() -> None:
    args = _parser().parse_args()
    try:
        with SQLiteIncidentRepository(args.db) as repository:
            service = IncidentService(
                repository,
                config=CorrelationConfig(time_window_seconds=getattr(args, "window_seconds", 900)),
            )
            if args.command == "list":
                state = IncidentStatus(args.status) if args.status else None
                _print(service.list(state))
            elif args.command == "view":
                _print(service.get(args.incident_id))
            elif args.command == "update":
                _print(service.update_status(
                    args.incident_id, IncidentStatus(args.status), actor=args.actor, reason=args.reason,
                ))
            elif args.command == "investigate":
                _print(service.investigate(args.incident_id, args.note, actor=args.actor))
            elif args.command == "attach":
                metadata = json.loads(args.metadata)
                if not isinstance(metadata, dict):
                    raise ValueError("--metadata must decode to a JSON object")
                _print(service.attach_evidence(args.incident_id, args.label, metadata, actor=args.actor))
            elif args.command == "demo":
                simulation = AttackSimulation().run(args.scenario_id, seed=args.seed, count=args.count)
                events = list(simulation.generated_events)
                alerts = MITREMapper().enrich_many(DetectionEngine().detect(events))
                assessments = RiskEngine().assess_many(alerts)
                outcomes = [service.ingest(alert, assessment) for alert, assessment in zip(alerts, assessments)]
                _print({
                    "flow": ["attack_simulation", "detection", "mitre_mapping", "risk_assessment", "incident_creation"],
                    "scenario_id": simulation.scenario_id,
                    "event_count": len(events),
                    "alerts": [alert.model_dump(mode="json") for alert in alerts],
                    "risk_assessments": [assessment.model_dump(mode="json") for assessment in assessments],
                    "incidents": [outcome.incident.model_dump(mode="json") for outcome in outcomes],
                    "duplicate_alerts_ignored": sum(outcome.duplicate for outcome in outcomes),
                    "database": args.db,
                })
    except (KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
