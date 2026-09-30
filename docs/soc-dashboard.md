# SentinelOT SOC dashboard

The dashboard is a local React + TypeScript application backed by the `dashboard_api` package. It renders existing Pydantic telemetry, asset, alert, MITRE, risk, and incident models. FortiGate fixture events and resulting findings use the same event and incident views. Analyst-driven response simulations are available in incident investigation. The browser does not implement detection or risk calculations.

## Start locally

Use two PowerShell terminals from the repository root. The API binds to `127.0.0.1` only; Vite is also bound to loopback and proxies `/api` to the API process.

Terminal 1 — local API:

```powershell
python -m dashboard_api --db .sentinelot-incidents.sqlite3 --port 8000
```

Terminal 2 — frontend:

```powershell
cd dashboard
npm ci
npm run dev
```

Open the loopback URL printed by Vite (normally `http://127.0.0.1:5173`). To create sample detections and incidents for the dashboard, run this from a third terminal:

```powershell
python -m incident_management demo network_recon --seed 7 --db .sentinelot-incidents.sqlite3
```

The dashboard reads incidents and related alerts/risk assessments from SQLite, assets from the existing `AssetRegistry`, MITRE mappings from persisted alerts, and live events from the existing benign `NormalTelemetryGenerator`. Live events are generated in memory, refreshed in batches, and are not persisted. The frontend uses local/system fonts and makes no external requests.

## Views

- **SOC Overview:** severity counts, active cases, recent alerts, assets affected by active incidents, mapped techniques, incident timeline, and current event stream.
- **Live Events:** searchable synthetic event stream.
- **Alerts:** searchable, severity-filterable alert and risk records.
- **Incidents:** searchable queue with status/severity filters and risk indicators.
- **Incident Investigation:** alert evidence, risk factor explanations, assets, original event IDs, ATT&CK metadata, analyst notes, timeline, and audit history. Status, notes, and explicitly authorized simulated response actions are audited.
- **OT Assets:** asset inventory with status, criticality, Purdue level, zone, manufacturer, firmware, and protocol.
- **MITRE ATT&CK:** observed structured techniques, tactics, domain, mapping basis, and linked incidents.

The interface includes loading, empty, error, and success-feedback states and adapts to narrow screens. No authentication or remote service is configured.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Local service status |
| GET | `/api/overview` | Aggregated counts and overview panels |
| GET | `/api/events?limit=100&search=` | In-memory generated telemetry |
| GET | `/api/alerts?search=&severity=` | Persisted alert/risk records |
| GET | `/api/incidents?search=&status=&severity=` | Filterable incident queue |
| GET | `/api/incidents/{incident_id}` | Full incident investigation record |
| POST | `/api/incidents/{incident_id}/status` | Validated, audited status transition |
| POST | `/api/incidents/{incident_id}/notes` | Add an analyst note |
| GET | `/api/incidents/{incident_id}/response-playbooks` | List playbooks supported by incident evidence |
| POST | `/api/incidents/{incident_id}/responses` | Request a simulation; creates a pending authorization record |
| POST | `/api/incidents/{incident_id}/responses/{action_id}/authorize` | Separately authorize and record a simulated outcome |
| POST | `/api/incidents/{incident_id}/responses/{action_id}/cancel` | Cancel a pending simulated action |
| POST | `/api/incidents/{incident_id}/responses/{action_id}/rollback` | Record a rollback simulation |
| POST | `/api/fortigate/demo` | Ingest bundled synthetic FortiGate fixtures |
| GET | `/api/assets?search=` | AssetRegistry records |
| GET | `/api/mitre` | Techniques observed in stored alerts |

Responses are JSON representations of existing models. API integration tests run the actual HTTP server on a loopback ephemeral port.

## Verify

```powershell
python -m pytest tests/unit -q
cd dashboard
npm test
npm run build
```
