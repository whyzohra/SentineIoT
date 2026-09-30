# Phase 5: transparent risk model

`RiskEngine` consumes `SecurityAlert` values and returns separate
`RiskAssessment` results. It never updates the alert. Assessments refer back to
the original alert using `alert_id`, and expose every normalized factor,
configured weight, weighted contribution, and a readable calculation summary.

## Formula

Each input is normalized to 0–100, multiplied by its configured weight, summed,
and rounded to two decimal places:

```text
risk_score = severity × 0.30
           + confidence × 0.20
           + asset_criticality × 0.20
           + evidence_quantity × 0.15
           + evidence_quality × 0.10
           + mitre_mapping × 0.05
```

Default normalizations:

| Factor | Normalization |
|---|---|
| Severity | LOW = 0, MEDIUM = 33.33, HIGH = 66.67, CRITICAL = 100. |
| Confidence | Alert confidence (0–1) multiplied by 100. |
| Asset criticality | Highest registered source/target criticality divided by 5, multiplied by 100. Unknown assets use criticality 3/5 by default. |
| Evidence quantity | Unique supporting `event_ids` divided by 5, capped at 100. |
| Evidence quality | Count of non-empty structured evidence details other than `event_ids`, divided by 4, capped at 100. |
| MITRE mapping | 100 only if mapping status is MAPPED and at least one structured technique mapping is present; otherwise 0. |

The evidence-quality component is a transparent measure of structured
corroboration detail, not a claim that any one evidence key is independently
true. Confidence remains a separate factor supplied by the detection rule.

## Risk levels

The rounded score maps to these ranges:

| Score | Level |
|---|---|
| 0 to less than 25 | LOW |
| 25 to less than 50 | MEDIUM |
| 50 to less than 75 | HIGH |
| 75 to 100 | CRITICAL |

Weights, evidence saturation points, unknown-asset criticality, and boundaries
are centralized in `RiskConfig`. Weights must be finite, non-negative, and sum
to 1.0. No random value, learned model, detection-rule identity, incident state,
or response state is used in scoring.

## Example

```powershell
python -m risk_engine demo network_recon --seed 7
```

The command runs a Phase 2 scenario through detection and MITRE enrichment, then
prints risk assessments as JSON. Each assessment includes component-by-component
rationales and the `alert_id` needed to retrieve its original alert.
