# SentinelOT implementation roadmap

This page records the delivered project phases. It replaces the original proposal, which described network services, Modbus control, process physics, and response behavior that are not present in this repository.

1. **Telemetry foundation:** synthetic asset registry and shared event/asset schemas.
2. **Safe scenario generation:** attack-shaped telemetry records with deterministic seeds.
3. **Detection:** modular deterministic OT behavior rules.
4. **MITRE ATT&CK mapping:** evidence-supported technique/tactic enrichment and explicit unmapped results.
5. **Risk scoring:** separate, explainable risk assessments.
6. **Incident management:** correlation, SQLite persistence, status workflow, notes, timeline, and audit history.
7. **SOC dashboard:** local React/TypeScript interface and loopback API.
8. **FortiGate integration:** synthetic JSON, CEF, and syslog-style parsing/normalization.
9. **AWS pipeline:** optional CDK architecture for SQS, Lambda, EventBridge, CloudWatch, and DynamoDB.
10. **ML anomaly detection:** optional Isolation Forest adapter using deterministic synthetic telemetry.
11. **Safe incident response:** analyst-driven, separately authorized simulations only.
12. **Final integration and portfolio documentation:** consolidated landing page, architecture/demo/security documentation, validation, and cleanup.

The current component architecture, setup, and validation instructions are maintained in [README.md](../README.md), [architecture.md](architecture.md), and [demo.md](demo.md). This roadmap is informational; it does not imply an unimplemented production service or feature.
