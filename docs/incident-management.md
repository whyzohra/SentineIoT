# Incident management

SentinelOT Phase 6 groups existing `SecurityAlert` and `RiskAssessment` records into persisted incidents. The module does not change detection, MITRE enrichment, or risk scoring. Every alert and its full risk explanation is stored as a pair, so original alert fields, MITRE mappings, and evidence event IDs remain available to analysts.

## Correlation policy

Only incidents in `OPEN`, `INVESTIGATING`, or `CONTAINED` can receive a new alert. By default, alerts must be within 900 seconds of the incident's most recent alert and share at least one source/target asset, account, or MITRE technique. Accounts are compared case-insensitively. A match with the most shared signal types wins; ties prefer the closest alert time. Set `CorrelationConfig(time_window_seconds=..., minimum_shared_assets=..., correlate_shared_accounts=..., correlate_shared_techniques=...)` when constructing `IncidentService` to tune the policy. Asset matching is always enabled; the minimum counts the number of shared asset IDs.

The incident severity is recalculated as the highest alert severity by the documented order `LOW < MEDIUM < HIGH < CRITICAL`. Incident risk score and level retain the highest associated assessment; each per-alert assessment and its factor rationales remain preserved unchanged.

## Status and audit

Allowed transitions:

| Current | Allowed next states |
|---|---|
| OPEN | INVESTIGATING, RESOLVED, FALSE_POSITIVE |
| INVESTIGATING | OPEN, CONTAINED, RESOLVED, FALSE_POSITIVE |
| CONTAINED | INVESTIGATING, RESOLVED, FALSE_POSITIVE |
| RESOLVED | INVESTIGATING |
| FALSE_POSITIVE | none |

Every transition records actor, timestamp, prior and next state, and optional reason. Alert correlation, notes, and evidence metadata also leave audit records. Timeline entries are ordered by timestamp; alert entries retain their source event IDs. Evidence attachments accept a label and JSON metadata only: the system does not upload or store file contents.

## SQLite and commands

SQLite uses the standard library and stores records locally. The default database is `.sentinelot-incidents.sqlite3` in the current directory; use `--db` to select another location. No network service or external dependency is required.

```powershell
python -m incident_management demo network_recon --seed 7 --db .sentinelot-demo.sqlite3
python -m incident_management demo network_recon --seed 7 --window-seconds 300 --db .sentinelot-demo.sqlite3
python -m incident_management list --db .sentinelot-demo.sqlite3
python -m incident_management view INCIDENT_ID --db .sentinelot-demo.sqlite3
python -m incident_management investigate INCIDENT_ID --note "Review the correlated asset activity" --actor analyst --db .sentinelot-demo.sqlite3
python -m incident_management update INCIDENT_ID CONTAINED --reason "Access isolated in lab" --actor analyst --db .sentinelot-demo.sqlite3
python -m incident_management attach INCIDENT_ID --label "analyst reference" --metadata '{"ticket":"LAB-42"}' --db .sentinelot-demo.sqlite3
```

The `demo` command executes the local synthetic flow: attack simulation → detection → MITRE enrichment → risk assessment → incident ingestion. The `list`, `view`, `update`, and `investigate` commands can run in separate CLI invocations against the same database.
