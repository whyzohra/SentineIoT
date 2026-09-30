# Optional ML anomaly detection

`ml_detection` is an opt-in layer for local, synthetic SentinelOT telemetry. It runs beside the established deterministic detection rules; it is not added to `DetectionEngine.DEFAULT_RULES` and does not alter existing rule results. The adapter merges ML alerts into the same MITRE mapper, risk engine, and incident service.

## Model and reproducibility

The first model is scikit-learn's unsupervised `IsolationForest` (`n_estimators=200`, `contamination="auto"`, `n_jobs=1`, fixed `random_state=7` by default). Fit only on the supplied normal baseline, then score separate candidate events. No internet service, cloud account, real OT device, or real telemetry is used. `ml_detection.fixtures` provides a deterministic all-synthetic normal baseline and candidate command burst/novel relationship fixture.

Install the optional dependency and run the integrated demo:

```powershell
python -m pip install -r ml_detection/requirements.txt
python -m ml_detection demo --seed 7 --db .sentinelot-ml-incidents.sqlite3
```

Train and save a reusable local model artifact:

```powershell
python -m ml_detection train --seed 7 --output .sentinelot-isolation-forest.joblib
```

Use `IsolationForestModel.load(path)` to load a previously trained artifact, then call `predict(candidate_events)`. Model files use joblib/pickle serialization; only load trusted local artifacts. `process_with_ml(events, baseline, incident_service=...)` is the convenience path for combined rule and ML alerts, MITRE mapping, risk assessment, and incident ingestion.

## Features and evidence

Each event is represented with the following deterministic features:

- PLC command flag and number of commands from the same source to target within the preceding 60 seconds.
- Historical source-target relationship frequency, source frequency, and event-type frequency in the normal reference set.
- Normalized event severity and source/target Purdue levels.

Each generated alert has rule ID `ML-001-OT-BEHAVIOR-ANOMALY`, `ml_generated: true`, and includes the anomaly score, each feature value, baseline median and 5th/95th percentile range, deviation outside that range, and the most unusual features. This is descriptive feature evidence, not a causal explanation of an Isolation Forest decision. MITRE mapping remains unmapped unless the shared mapper has evidence-supported coverage.

## Limitations

This small unsupervised baseline demonstrates reproducible behavior, not production calibration. Isolation Forest can flag benign shifts, miss subtle attacks, and reflect biases in the synthetic baseline. Frequency uses a fixed 60-second window and historical categorical counts; it does not model process physics, seasonality, operator schedules, or long-term concept drift. Retrain only with a reviewed baseline and evaluate alert quality before operational use. The layer only creates alerts; it performs no response or control actions.
