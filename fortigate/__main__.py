"""Run bundled synthetic FortiGate fixtures through the local SOC pipeline."""

import argparse
import json
from pathlib import Path

from fortigate.pipeline import process_logs
from incident_management import IncidentService, SQLiteIncidentRepository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("demo", choices=["demo"])
    parser.add_argument("--db", default=".sentinelot-incidents.sqlite3")
    args = parser.parse_args()
    repository = SQLiteIncidentRepository(args.db)
    try:
        fixtures = Path(__file__).parent / "fixtures" / "demo.jsonl"
        result = process_logs(fixtures.read_text(encoding="utf-8").splitlines(),
                              incident_service=IncidentService(repository))
        print(json.dumps({"event_count": len(result["events"]),
                          "events": [event.model_dump(mode="json") for event in result["events"]],
                          "alerts": [alert.model_dump(mode="json") for alert in result["alerts"]],
                          "risk_assessments": [item.model_dump(mode="json") for item in result["assessments"]],
                          "incidents": [item.model_dump(mode="json") for item in result["incidents"]]}, indent=2))
    finally:
        repository.close()


if __name__ == "__main__":
    main()
