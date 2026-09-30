# Security model and safe-use boundaries

SentinelOT is a portfolio lab built around synthetic OT/ICS telemetry. It demonstrates defensive data processing and incident workflow; it is not an OT gateway, vulnerability scanner, or production SOC service.

## Safe by default

- The OT and attack simulators create schema-shaped records in memory. They do not connect to PLCs, send packets, attempt logins, execute shell commands, or change process state.
- FortiGate parsing uses synthetic fixture lines only. It neither connects to an appliance nor requires vendor credentials.
- ML training and inference use local synthetic fixtures. The model is an exploratory unsupervised baseline, not a validated safety or threat decision system.
- Incident response records hypothetical host isolation, account disablement, PLC access blocking, or evidence references. There are no adapters to real network, OS, account, firewall, or PLC operations. An analyst must request and separately authorize each simulation. No detector or incident creation starts response.
- Dashboard and API are intended for local use. The API binds to `127.0.0.1`; analyst names are audit labels, not authenticated identity claims.
- The optional AWS deployment is not part of local mode. Synthesis and mock tests do not create resources. Deploying the CDK stack is an explicit infrastructure operation and requires operator credentials.

## Data and credentials

Checked-in fixtures are synthetic. Local incidents may be stored in ignored SQLite files in the project directory. Do not commit real operational logs, database files, AWS credentials, environment files, or model artifacts. The AWS SDK uses its standard credential chain only when the AWS-backed API/deployment path is deliberately configured; no credentials are embedded in source.

## Limitations

The asset inventory and activity patterns are small and simulated. Detection thresholds, risk weights, and MITRE mappings are transparent examples that need validation against an organization's policies and telemetry. ML alert evidence describes unusual features but does not establish causation. The AWS stack is a reference integration path, not a production-reviewed or compliance-certified architecture. Local dashboard analyst attribution is not authentication or authorization security.

Do not connect this project to real OT networks or treat its scores and actions as operational guidance.
