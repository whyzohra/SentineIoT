# SentinelOT portfolio notes

## Project bullets

- Built a modular OT security pipeline that carries shared-schema synthetic PLC/HMI/SCADA events through seven deterministic detections, MITRE ATT&CK enrichment, explainable risk scoring, correlated SQLite incidents, and an investigation dashboard.
- Added a FortiGate adapter for JSON, CEF, and syslog-style fixtures, preserving vendor fields while normalizing events into the existing telemetry and detection pipeline.
- Integrated an optional reproducible Isolation Forest layer with behavioral features for command volume and source/target relationships; ML findings reuse the alert, mapping, risk, and incident models and include feature evidence.
- Implemented an optional AWS CDK path using SQS, Lambda, EventBridge, CloudWatch, and DynamoDB, with retries, dead-letter handling, scoped permissions, and mocked offline tests.
- Built analyst-requested, explicitly authorized incident response simulations with evidence-derived targets and audited success, failure, cancellation, and rollback states; no real response adapter exists.

## Technology stack

Python, Pydantic, pytest, scikit-learn Isolation Forest, SQLite, AWS CDK (Python), SQS, Lambda, EventBridge, CloudWatch, DynamoDB, React, TypeScript, Vite, Vitest, and Lucide icons.

## Measurable implementation details

- **7 default deterministic detection rules**: network reconnaissance, brute force, unauthorized PLC access, PLC command frequency, insider behavior, FortiGate IPS, and FortiGate denied burst.
- **4 incident response playbooks**, each represented as simulation-only and gated by analyst authorization.
- **3 FortiGate input styles**: JSON, CEF, and syslog-style key/value records.
- **1 shared telemetry schema** (`TelemetryEvent`) carried into alerts, MITRE enrichment, risk assessments, and incidents.
- **Deterministic local demos** use fixed seeds and checked-in synthetic fixtures. The full Python suite, frontend tests/build, and CDK synthesis can run without live cloud resources.

## Two-minute interview explanation

SentinelOT is a local-first OT/ICS SOC lab. The problem I focused on is how a security team can preserve context when industrial events arrive from different layers: controller activity, authentication, and network security logs. I model a small set of PLC, HMI, SCADA, and engineering assets and generate synthetic telemetry with a shared Pydantic schema. Deterministic rules turn event evidence into alerts; the MITRE mapper adds only supported ATT&CK context; a separate risk engine explains its score; and incident management persists the linked evidence and analyst history in SQLite.

I then added three optional integration paths without replacing that core: a FortiGate parser for synthetic JSON/CEF/syslog fixtures, an Isolation Forest layer using interpretable behavioral features, and an AWS CDK deployment path using queue-based ingestion and serverless processing. The React dashboard uses the same API models for investigation. Finally, response playbooks require an analyst request and a separate authorization and only write simulation/audit records. This project deliberately never sends attack traffic or changes real endpoints or PLCs. The main engineering choices were reuse of shared models, explicit evidence traceability, opt-in components, and reproducible local validation.
