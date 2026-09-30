"""Run existing SentinelOT detection and risk models on routed events."""

import json
import logging
import os
import uuid

from detection_engine import DetectionEngine, MITREMapper
from incident_management.models.incident import Incident, IncidentAlertRecord, IncidentStatus, TimelineEntry
from risk_engine import RiskEngine
from telemetry.schemas.event import TelemetryEvent

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)


def handler(event, context, *, table=None, cloudwatch=None):
    """Process one EventBridge telemetry event and persist traceable results."""
    if table is None:
        import boto3
        table = boto3.resource("dynamodb").Table(os.environ["SECURITY_TABLE_NAME"])
        cloudwatch = cloudwatch or boto3.client("cloudwatch")
    detail = event.get("detail", event)
    telemetry = TelemetryEvent.model_validate(detail.get("event", detail))
    alerts = MITREMapper().enrich_many(DetectionEngine().detect([telemetry]))
    table.put_item(Item={"PK": "EVENT", "SK": telemetry.event_id,
                         "record": telemetry.model_dump(mode="json")})
    assessments = RiskEngine().assess_many(alerts)
    for alert, assessment in zip(alerts, assessments):
        incident = Incident(
            incident_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelot:incident:{alert.alert_id}")),
            title=alert.title, status=IncidentStatus.OPEN, created_at=alert.timestamp,
            updated_at=alert.timestamp, last_alert_timestamp=alert.timestamp,
            severity=alert.severity, risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            alert_records=[IncidentAlertRecord(alert=alert, risk_assessment=assessment)],
            event_ids=list(alert.evidence.get("event_ids", [])),
            timeline=[TimelineEntry(timestamp=alert.timestamp, kind="ALERT_INGESTED",
                                    summary=alert.title, alert_id=alert.alert_id,
                                    event_ids=list(alert.evidence.get("event_ids", [])))],
        )
        table.put_item(Item={"PK": "ALERT", "SK": alert.alert_id,
                             "incident_id": incident.incident_id,
                             "incident_status": incident.status.value,
                             "record": alert.model_dump(mode="json"),
                             "risk_assessment": assessment.model_dump(mode="json")})
        table.put_item(Item={"PK": "INCIDENT", "SK": incident.incident_id,
                             "record": incident.model_dump(mode="json")})
        LOG.info("security_alert_processed", extra={"alert_id": alert.alert_id,
                                                     "rule_id": alert.rule_id,
                                                     "incident_id": incident.incident_id,
                                                     "risk_score": assessment.risk_score})
        if cloudwatch is not None:
            cloudwatch.put_metric_data(Namespace="SentinelOT/Security", MetricData=[
                {"MetricName": "AlertsProcessed", "Value": 1, "Unit": "Count",
                 "Dimensions": [{"Name": "RuleId", "Value": alert.rule_id}]},
                {"MetricName": "RiskScore", "Value": assessment.risk_score, "Unit": "None"},
            ])
    return {"event_id": telemetry.event_id, "alert_count": len(alerts),
            "alert_ids": [alert.alert_id for alert in alerts]}
