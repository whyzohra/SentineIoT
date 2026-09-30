# SentinelOT phase 1: simulated industrial environment

This phase provides an isolated, in-memory industrial lab with PLC-001, PLC-002,
HMI-001, SCADA-001, and ENGINEERING-001. It generates synthetic baseline process,
operator, engineering, and supervisory events. The simulators do not open sockets,
connect to industrial devices, or communicate with external networks.

## Start

Use Python 3.10+ with Pydantic 2 installed (`python -m pip install "pydantic>=2,<3"`).
From the repository root, print 20 events and exit:

```powershell
python -m telemetry --count 20 --interval 0 --seed 7
```

Each line is a JSON event. Omit `--count` to stream continuously; set `--interval`
to control the delay between events. Press Ctrl+C to stop.

## Event and asset models

Events use `TelemetryEvent` in `telemetry/schemas/event.py`; serialized records
contain `event_id`, UTC `timestamp`, `source_asset`, nullable `destination_asset`,
`event_type`, `severity`, `message`, and structured `metadata`. Asset records in
`telemetry/schemas/asset.py` include identity, hostname, private IPv4 address,
type, manufacturer, firmware, criticality, and status. `AssetRegistry` seeds the
five standard lab assets and rejects duplicate IP assignments.

The in-memory generator can also be used directly:

```python
from telemetry.generator import NormalTelemetryGenerator

events = NormalTelemetryGenerator(seed=7).events(count=10)
for event in events:
    print(event.to_json())
```

## Tests

Run the phase 1 unit tests with `python -m pytest tests/unit -q`.

## Phase 2: safe attack simulation

Attack-shaped activity is represented only by synthetic `TelemetryEvent` records
attributed to registered lab assets. Scenario generation does not send packets,
attempt logins, execute PLC commands, change process state, or contact external
systems. Each run prints `SIMULATION ONLY — SentinelOT isolated laboratory`
before its scenario report.

List scenarios and run one with a reproducible seed:

```powershell
python -m attack_simulator list
python -m attack_simulator run network_recon --seed 7
python -m attack_simulator run brute_force --seed 7 --count 5
python -m attack_simulator run unauthorized_plc --seed 7
python -m attack_simulator run plc_anomaly --seed 7 --count 3
python -m attack_simulator run insider_anomaly --seed 7
```

`--count` controls the number of synthetic events (each scenario has a default).
The command prints scenario details and schema-shaped events as JSON. Run all
unit tests with `python -m pytest tests/unit -q`.

## Phase 3: rule-based detection

The detection engine consumes the same telemetry event schema and emits
structured alerts with traceable source event IDs. Run an end-to-end demo or
feed JSONL events from the baseline simulator into detection:

```powershell
python -m detection_engine demo network_recon --seed 7
python -m detection_engine demo brute_force --seed 7 --count 12
python -m detection_engine demo unauthorized_plc --seed 7 --count 5
python -m detection_engine demo insider_anomaly --seed 7
python -m telemetry --count 10 --interval 0 --seed 7 | python -m detection_engine detect
```

Rules, thresholds, severity rationale, and configuration options are documented
in [docs/detection-engine.md](docs/detection-engine.md).
