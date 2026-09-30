"""Validate SQS telemetry and route it to the configured EventBridge bus."""

import json
import os

from telemetry.schemas.event import TelemetryEvent


def handler(event, context, *, eventbridge=None, bus_name=None):
    """Process an SQS batch; return partial failures so SQS can retry safely."""
    if eventbridge is None:
        import boto3
        eventbridge = boto3.client("events")
    bus_name = bus_name or os.environ["EVENT_BUS_NAME"]
    failures = []
    for record in event.get("Records", []):
        try:
            payload = json.loads(record["body"])
            telemetry = TelemetryEvent.model_validate(payload)
            response = eventbridge.put_events(Entries=[{
                "EventBusName": bus_name,
                "Source": "sentinelot.telemetry",
                "DetailType": "SentinelOTTelemetry",
                "Detail": json.dumps({"event": telemetry.model_dump(mode="json")}, separators=(",", ":")),
            }])
            if response.get("FailedEntryCount", 0):
                raise RuntimeError("EventBridge rejected telemetry event")
        except Exception:
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
