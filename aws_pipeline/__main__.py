"""Credential-free local exercise of the optional AWS processing stages."""

import argparse
import json

from attack_simulator import AttackSimulation
from detection_engine import DetectionEngine, MITREMapper
from risk_engine import RiskEngine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("demo", choices=["demo"])
    parser.add_argument("scenario", nargs="?", default="network_recon")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    simulation = AttackSimulation().run(args.scenario, seed=args.seed)
    events = simulation.generated_events
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(events))
    assessments = RiskEngine().assess_many(alerts)
    print(json.dumps({"mode": "LOCAL_ONLY_NO_AWS", "sqs_message_count": len(events),
                      "events": [event.model_dump(mode="json") for event in events],
                      "alerts": [alert.model_dump(mode="json") for alert in alerts],
                      "risk_assessments": [item.model_dump(mode="json") for item in assessments]}, indent=2))


if __name__ == "__main__":
    main()
