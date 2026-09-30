# Optional AWS security telemetry pipeline

The AWS deployment is an optional, credential-free-to-test path. Running SentinelOT locally still uses its existing in-process pipeline and SQLite store; no AWS SDK client is created unless the dashboard is explicitly configured with `SENTINELOT_AWS_TABLE`.

## Architecture and data flow

1. Producers send serialized existing `TelemetryEvent` JSON records to an encrypted SQS queue. A redrive policy moves repeatedly failing records to an SQS dead-letter queue.
2. The ingestion Lambda validates each body with the existing Pydantic model and publishes it to a dedicated EventBridge bus. Partial batch failures let SQS retry only failed records; malformed events eventually reach the queue DLQ.
3. An EventBridge rule invokes the detection Lambda for the SentinelOT event source. EventBridge retries failed delivery and sends exhausted events to its own encrypted DLQ.
4. The detection Lambda invokes the existing detection engine and MITRE mapper, calculates risk with `RiskEngine`, then persists the normalized event, alert, risk assessment, and an `Incident` model record in DynamoDB. Writes use deterministic keys so retries are idempotent.
5. Structured Lambda logs and CloudWatch metrics report processing and risk scores. Alarms cover Lambda errors and both dead-letter queues.
6. The existing dashboard API can optionally read AWS-backed events, alerts, and incidents from the same table by setting `SENTINELOT_AWS_TABLE`. API access uses the AWS SDK default credential chain and IAM role; local mode leaves it unset.

CDK defines independent queue, routing, and data-store constructs inside the deployable `SentinelOTSecurity` stack. IAM is scoped to the exact EventBridge bus, DynamoDB table, and pre-created log groups. CloudWatch `PutMetricData` is restricted by the `SentinelOT/Security` namespace condition (the API requires a wildcard resource).

## Install and deploy

Use Python 3.10+ and install the optional infrastructure and AWS API dependencies in the environment you use for CDK or for an AWS-configured dashboard API:

```powershell
python -m pip install -r aws_pipeline/requirements.txt
python -m aws_pipeline.build_layer
cd aws_pipeline
cdk synth
cdk bootstrap   # once per account and region, if required
cdk deploy
```

The dependency layer contains Pydantic for the reused SentinelOT schemas and must be prepared before deployment. The CDK app only synthesizes infrastructure and does not require AWS credentials; bootstrap/deploy require AWS credentials through the standard AWS CLI credential chain. The infrastructure source is packaged from this repository, including the existing detection, MITRE, risk, and incident models.

After deployment, send JSON `TelemetryEvent` records to the `TelemetryQueueUrl` stack output. Configure an appropriately authorized dashboard API process with `SENTINELOT_AWS_TABLE` set to `SecurityTableName` to display AWS-backed records.

## Local run and tests

Exercise the existing synthetic telemetry and security stages without AWS:

```powershell
python -m aws_pipeline demo network_recon --seed 7
```

CDK assertions and Lambda mock tests run in the ordinary unit test suite. They synthesize templates in memory, use fake EventBridge/DynamoDB/CloudWatch clients, and do not create AWS resources.
