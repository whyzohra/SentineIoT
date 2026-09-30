# Phase 4: MITRE ATT&CK alert enrichment

`MITREMapper` enriches an existing `SecurityAlert` after rule evaluation. It is
independent of detection-rule implementations and returns a copy with structured
`mitre_mappings`, `mitre_mapping_status`, and (when applicable)
`mitre_unmapped_reason` fields. Original alert data, including evidence
`event_ids`, is preserved.

## Mappings

| Detection | ATT&CK mapping | Tactic | Basis |
|---|---|---|---|
| DET-001 Network reconnaissance | ICS **T0846 Remote System Discovery** ([technique](https://attack.mitre.org/techniques/T0846/)) | **TA0102 Discovery** ([tactic](https://attack.mitre.org/tactics/TA0102/)) | Multiple distinct OT asset references from one source within a short window are consistent with remote system discovery. |
| DET-002 Brute force | Enterprise **T1110 Brute Force** ([technique](https://attack.mitre.org/techniques/T1110/)) | **TA0006 Credential Access** ([tactic](https://attack.mitre.org/tactics/TA0006/)) | Repeated authentication failures support generic credential brute-force behavior. The evidence does not identify ICS I/O brute forcing, so the ICS T0806 technique is not used. |
| DET-003 Unauthorized PLC access | ICS **T1692.001 Unauthorized Message: Command Message** ([technique](https://attack.mitre.org/techniques/T1692/001/)) | **TA0103 Evasion** and **TA0106 Impair Process Control** ([ICS tactics](https://attack.mitre.org/tactics/ics/)) | Applied only when alert `metadata.access_type` identifies a command/setpoint write. Generic unauthorized network access or configuration access is left unmapped. |
| DET-004 PLC command frequency | Unmapped | — | Elevated command frequency alone does not establish unauthorized or adversarial commands. |
| DET-005 Insider behavior anomaly | Unmapped | — | Time, source, account, or activity deviations alone do not establish a specific ATT&CK technique or valid-account misuse. |

Technique IDs, names, tactic IDs, and tactic names are curated in
`detection_engine/mitre/catalog.py`. Unsupported detections receive an explicit
unmapped status and reason instead of an inferred technique. No ATT&CK mapping is
added to telemetry events or detection rules.

## Use

```python
from detection_engine import DetectionEngine, MITREMapper

alerts = DetectionEngine().detect(events)
enriched_alerts = MITREMapper().enrich_many(alerts)
```

The existing detection CLI applies this enrichment automatically:

```powershell
python -m detection_engine demo network_recon --seed 7
```

The report contains `mitre_mapping_status` and structured `mitre_mappings` on
each alert.
