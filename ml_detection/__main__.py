"""Train and exercise the optional ML layer using local synthetic fixtures."""

import argparse
import json

from incident_management import IncidentService, SQLiteIncidentRepository
from ml_detection.fixtures import anomalous_batch, normal_baseline
from ml_detection.model import IsolationForestModel
from ml_detection.pipeline import process_with_ml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="fit a model on deterministic normal synthetic telemetry")
    train.add_argument("--output", default=".sentinelot-isolation-forest.joblib")
    train.add_argument("--seed", type=int, default=7)
    demo = commands.add_parser("demo", help="train and run the end-to-end local anomaly demo")
    demo.add_argument("--db", default=".sentinelot-ml-incidents.sqlite3")
    demo.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    baseline = normal_baseline()
    if args.command == "train":
        IsolationForestModel(random_state=args.seed).fit(baseline).save(args.output)
        print(json.dumps({"mode": "LOCAL_SYNTHETIC_ONLY", "training_events": len(baseline),
                          "model": "IsolationForest", "saved_model": args.output}, indent=2))
        return
    repository = SQLiteIncidentRepository(args.db)
    try:
        service = IncidentService(repository)
        result = process_with_ml(anomalous_batch(), baseline, incident_service=service, random_state=args.seed)
        print(json.dumps({"mode": "LOCAL_SYNTHETIC_ONLY", "baseline_event_count": len(baseline),
                          "candidate_event_count": len(result["events"]),
                          "ml_finding_count": len(result["findings"]),
                          "alerts": [{"alert_id": alert.alert_id, "rule_id": alert.rule_id,
                                      "severity": alert.severity.value, "ml_generated": bool(alert.metadata.get("ml_generated")),
                                      "unusual_features": alert.evidence.get("unusual_features", [])}
                                     for alert in result["alerts"]],
                          "risk_assessments": [{"alert_id": item.alert_id, "risk_score": item.risk_score,
                                                "risk_level": item.risk_level.value}
                                               for item in result["assessments"]],
                          "incident_ids": list(dict.fromkeys(item.incident_id for item in result["incidents"]))}, indent=2))
    finally:
        repository.close()


if __name__ == "__main__":
    main()
