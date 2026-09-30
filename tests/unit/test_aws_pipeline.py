import json
from pathlib import Path

import pytest

cdk = pytest.importorskip("aws_cdk", reason="Install aws_pipeline/requirements.txt to run CDK tests")
from aws_cdk.assertions import Match, Template

from aws_pipeline.handlers.detect import handler as detect_handler
from aws_pipeline.handlers.ingest import handler as ingest_handler
from aws_pipeline.stack import SentinelOTSecurityStack
from fortigate.normalizer import normalize
from fortigate.parser import parse_log


FIXTURES = Path(__file__).parents[1] / ".." / "fortigate" / "fixtures"


class FakeEventBridge:
    def __init__(self, failed=0):
        self.entries = []
        self.failed = failed

    def put_events(self, *, Entries):
        self.entries.extend(Entries)
        return {"FailedEntryCount": self.failed}


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)


class FakeCloudWatch:
    def __init__(self):
        self.metrics = []

    def put_metric_data(self, **kwargs):
        self.metrics.append(kwargs)


def test_cdk_template_synthesizes_least_privilege_pipeline(tmp_path):
    app = cdk.App(outdir=str(tmp_path / "cdk.out"))
    stack = SentinelOTSecurityStack(app, "TestStack")
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::SQS::Queue", 3)
    template.resource_count_is("AWS::Lambda::Function", 2)
    template.resource_count_is("AWS::Events::EventBus", 1)
    template.resource_count_is("AWS::Events::Rule", 1)
    template.resource_count_is("AWS::DynamoDB::Table", 1)
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "BillingMode": "PAY_PER_REQUEST", "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
    })
    template.has_resource_properties("AWS::Lambda::EventSourceMapping", {
        "FunctionResponseTypes": ["ReportBatchItemFailures"], "BatchSize": 10,
    })
    template.has_resource_properties("AWS::SQS::Queue", {"RedrivePolicy": Match.any_value()})
    assembly = app.synth()
    assert assembly.get_stack_by_name("TestStack")


def test_sqs_ingestion_routes_valid_event_and_retries_invalid_or_failed():
    fixture = json.loads((FIXTURES / "formats.json").read_text(encoding="utf-8"))[0]
    event = normalize(fixture)
    msg = {"messageId": "ok", "body": event.model_dump_json()}
    malformed = {"messageId": "bad", "body": "not-json"}
    bus = FakeEventBridge()
    result = ingest_handler({"Records": [msg, malformed]}, None, eventbridge=bus, bus_name="local-bus")
    assert result == {"batchItemFailures": [{"itemIdentifier": "bad"}]}
    assert bus.entries[0]["EventBusName"] == "local-bus"
    assert json.loads(bus.entries[0]["Detail"])["event"]["event_id"] == event.event_id
    failed_bus = FakeEventBridge(failed=1)
    result = ingest_handler({"Records": [msg]}, None, eventbridge=failed_bus, bus_name="local-bus")
    assert result["batchItemFailures"][0]["itemIdentifier"] == "ok"


def test_detection_handler_reuses_rules_risk_and_persists_records():
    fixture = json.loads((FIXTURES / "formats.json").read_text(encoding="utf-8"))[0]
    raw = {**fixture, "type": "utm", "subtype": "ips", "attack": "Synthetic IPS signature", "severity": "high"}
    telemetry = normalize(raw)
    table = FakeTable()
    cloudwatch = FakeCloudWatch()
    result = detect_handler({"detail": {"event": telemetry.model_dump(mode="json")}}, None,
                            table=table, cloudwatch=cloudwatch)
    assert result["alert_count"] >= 1
    assert {item["PK"] for item in table.items} == {"EVENT", "ALERT", "INCIDENT"}
    alert_items = [item for item in table.items if item["PK"] == "ALERT"]
    assert any(item["record"]["rule_id"] == "DET-006-FORTIGATE-IPS" for item in alert_items)
    assert all(item["risk_assessment"]["alert_id"] == item["SK"] for item in alert_items)
    assert len(cloudwatch.metrics) == result["alert_count"]
