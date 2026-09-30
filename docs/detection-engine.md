# Phase 3: Detection Engine

The importable `detection_engine` package consumes the existing
`telemetry.schemas.event.TelemetryEvent` model and the existing in-memory
`AssetRegistry` policy. It emits `SecurityAlert` records; there is no second
telemetry schema and no event mutation. Rules are separate modules implementing
the `DetectionRule.evaluate(events, config)` interface. `DetectionEngine.detect`
accepts an iterable (including a generator) and returns deterministically sorted
alerts.

## Rules and rationale

| Rule | Default behavior | Severity rationale |
|---|---|---|
| DET-001 Network reconnaissance | At least 3 unique OT destinations from one source in 60 seconds | MEDIUM: asset discovery is suspicious but does not indicate process impact. |
| DET-002 Brute force | At least 3 failures for one source, account, and target in 300 seconds | MEDIUM for repeated failures; HIGH if a later success follows in the window. |
| DET-003 Unauthorized PLC access | A PLC-directed event from a source outside that PLC's configured source allowlist, or explicit simulated denial | HIGH: an unauthorized controller boundary access is significant even if no command executes. |
| DET-004 PLC command frequency | PLC-directed commands exceed 2 events/minute × 2 in a 60-second rolling window | HIGH: unusual control command volume warrants prompt review; this rule does not claim process impact. |
| DET-005 Insider behavior | Monitored activity outside 06:00–18:00 UTC, from an untrusted source/account, to an unapproved target, or above the configured activity baseline | MEDIUM for one contextual deviation; HIGH for explicit unapproved status or at least two independent indicators. |

Thresholds and source/account/target policies live in `DetectionConfig`. Insider
activity defaults to 3 events per 300-second source/account/target window, with a
strict multiplier of 2. Pass a custom instance to `DetectionEngine(config=...)`
to change any setting. Command
frequency is normalized to events per minute and uses a strict `>` comparison at
the configured multiplier boundary. The PLC access defaults permit HMI-001 and
SCADA-001 to PLC-001, and additionally permit ENGINEERING-001 to PLC-002.

Alert confidence is a rule match strength, not a risk score: baseline matches
use documented fixed confidence values in their rule modules; brute-force
confidence increases when a success follows failures, and explicit access
denials increase confidence for the authorization rule. Alert evidence includes
all supporting original `event_id` values. IDs are stable for the same rule and
evidence, allowing repeatable tests and analyst traceability.

## CLI

Run a Phase 2 scenario directly through the detector:

```powershell
python -m detection_engine demo network_recon --seed 7
python -m detection_engine demo brute_force --seed 7 --count 12
python -m detection_engine demo unauthorized_plc --seed 7
```

Or read existing event-schema JSONL from a file or standard input:

```powershell
python -m telemetry --count 10 --interval 0 --seed 7 | python -m detection_engine detect
```

The PLC anomaly Phase 2 scenario emits sensor values, but Phase 3's five rules do
not include a general process-value anomaly rule; it therefore does not itself
produce an alert unless its events also match another configured rule.
