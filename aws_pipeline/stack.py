"""Least-privilege CDK deployment for the optional AWS telemetry pipeline."""

from pathlib import Path

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sqs as sqs
from constructs import Construct


class TelemetryQueue(Construct):
    """Isolated SQS intake and poison-message dead-letter queue."""

    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)
        self.dead_letter_queue = sqs.Queue(
            self, "DeadLetterQueue", encryption=sqs.QueueEncryption.SQS_MANAGED,
            retention_period=Duration.days(14), enforce_ssl=True,
        )
        self.queue = sqs.Queue(
            self, "Queue", encryption=sqs.QueueEncryption.SQS_MANAGED,
            retention_period=Duration.days(4), visibility_timeout=Duration.seconds(180),
            dead_letter_queue=sqs.DeadLetterQueue(queue=self.dead_letter_queue, max_receive_count=3),
            enforce_ssl=True,
        )


class EventRouting(Construct):
    """Custom EventBridge bus and the telemetry routing rule."""

    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)
        self.bus = events.EventBus(self, "Bus", event_bus_name="sentinelot-security")


class SecurityDataStore(Construct):
    """On-demand encrypted table for normalized telemetry and investigations."""

    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)
        self.table = dynamodb.Table(
            self, "Table", partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True),
            removal_policy=RemovalPolicy.RETAIN,
        )


class SentinelOTSecurityStack(Stack):
    """Optional AWS path. Deploying this stack is never needed for local mode."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        project_root = Path(__file__).resolve().parents[1]
        queue = TelemetryQueue(self, "TelemetryIngestion")
        routing = EventRouting(self, "SecurityRouting")
        data = SecurityDataStore(self, "SecurityData")

        layer = lambda_.LayerVersion(
            self, "SentinelOTDependencies",
            code=lambda_.Code.from_asset(str(project_root / "aws_pipeline" / "layer")),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            description="Pydantic runtime used by the existing SentinelOT data models",
        )
        source = lambda_.Code.from_asset(
            str(project_root), exclude=[".git", ".aws", ".venv", ".pytest_cache", "tests", "dashboard",
                                        ".env", "**/.env", "**/.env.*", "**/*.pem", "**/*.key",
                                        "node_modules", "**/__pycache__", "*.sqlite3", "cdk.out",
                                        "aws_pipeline/layer"],
        )
        ingest_log = logs.LogGroup(self, "IngestLogs", retention=logs.RetentionDays.ONE_MONTH,
                                   removal_policy=RemovalPolicy.RETAIN)
        detect_log = logs.LogGroup(self, "DetectionLogs", retention=logs.RetentionDays.ONE_MONTH,
                                   removal_policy=RemovalPolicy.RETAIN)
        ingest_role = iam.Role(self, "IngestRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ingest_log.grant_write(ingest_role)
        routing.bus.grant_put_events_to(ingest_role)
        ingest = lambda_.Function(
            self, "IngestFunction", runtime=lambda_.Runtime.PYTHON_3_12,
            handler="aws_pipeline.handlers.ingest.handler", code=source, role=ingest_role,
            layers=[layer], timeout=Duration.seconds(30), memory_size=256,
            environment={"EVENT_BUS_NAME": routing.bus.event_bus_name}, log_group=ingest_log,
        )
        ingest.add_event_source(event_sources.SqsEventSource(
            queue.queue, batch_size=10, report_batch_item_failures=True,
        ))

        detect_role = iam.Role(self, "DetectionRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        detect_log.grant_write(detect_role)
        data.table.grant_read_write_data(detect_role)
        detect_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"], resources=["*"],
            conditions={"StringEquals": {"cloudwatch:namespace": "SentinelOT/Security"}},
        ))
        detect = lambda_.Function(
            self, "DetectionFunction", runtime=lambda_.Runtime.PYTHON_3_12,
            handler="aws_pipeline.handlers.detect.handler", code=source, role=detect_role,
            layers=[layer], timeout=Duration.seconds(60), memory_size=512,
            environment={"SECURITY_TABLE_NAME": data.table.table_name}, log_group=detect_log,
        )
        rule = events.Rule(self, "TelemetryRule", event_bus=routing.bus,
                           event_pattern=events.EventPattern(source=["sentinelot.telemetry"],
                                                            detail_type=["SentinelOTTelemetry"]))
        event_dlq = sqs.Queue(self, "EventDeliveryDlq", encryption=sqs.QueueEncryption.SQS_MANAGED,
                              retention_period=Duration.days(14), enforce_ssl=True)
        rule.add_target(targets.LambdaFunction(detect, dead_letter_queue=event_dlq, retry_attempts=2,
                                               max_event_age=Duration.hours(1)))

        cloudwatch.Alarm(self, "DeadLetterAlarm", metric=queue.dead_letter_queue.metric_approximate_number_of_messages_visible(),
                         threshold=1, evaluation_periods=1, alarm_description="SentinelOT telemetry reached the DLQ")
        cloudwatch.Alarm(self, "LambdaErrorsAlarm", metric=detect.metric_errors(period=Duration.minutes(5)),
                         threshold=1, evaluation_periods=1, alarm_description="SentinelOT detection Lambda errors")
        cloudwatch.Alarm(self, "EventDeliveryDlqAlarm", metric=event_dlq.metric_approximate_number_of_messages_visible(),
                         threshold=1, evaluation_periods=1,
                         alarm_description="EventBridge could not deliver security events to detection")

        from aws_cdk import CfnOutput
        CfnOutput(self, "TelemetryQueueUrl", value=queue.queue.queue_url)
        CfnOutput(self, "SecurityEventBusArn", value=routing.bus.event_bus_arn)
        CfnOutput(self, "SecurityTableName", value=data.table.table_name)
