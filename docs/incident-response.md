# Safe simulated incident response

`incident_response` adds an analyst-driven dry-run workflow to incident investigation. It contains no adapters to operating systems, networks, firewalls, accounts, or PLCs. The simulator only builds response records, audit entries, and evidence references; there is no code path that performs a real containment or collection operation.

## Incident-driven playbooks

The local dashboard offers these playbooks when their targets exist in the incident's alert evidence:

- **Simulated host isolation:** choose an asset referenced by a linked alert.
- **Simulated account disablement:** choose an account/user identifier present in linked alert evidence.
- **Simulated PLC access block:** choose an affected PLC or RTU.
- **Collect evidence references:** record the incident's event IDs and alert IDs. No event payload is copied.

Targets are restricted to incident evidence. The playbook list is derived from each incident, so accounts, assets, or controllers from unrelated environments cannot be entered as arbitrary targets.

## Analyst workflow and lifecycle

1. Open an incident and request a playbook with an analyst label and reason. This creates a `PENDING_AUTHORIZATION` record only; no simulation is executed.
2. Review the target and request. Check **I explicitly authorize this simulated action**, provide an authorization reason, and choose a deterministic simulated success or failure outcome.
3. The action ends as `SUCCEEDED` or `FAILED`. A pending request can instead be cancelled; only a successful simulation can be rolled back. Rollback records a hypothetical reversal and does not change system state.
4. Each transition appends an incident timeline entry and audit record containing action/incident IDs, status, timestamp, analyst, reason, simulation result, and a `simulation_only` flag. Action records are persisted with the incident in SQLite.

The incident detail API provides `GET /api/incidents/{id}/response-playbooks`, `POST /api/incidents/{id}/responses`, and action-specific `authorize`, `cancel`, and `rollback` endpoints. Authorization requires the literal boolean `authorized: true`, a non-empty analyst label, and a reason; failed authorization attempts are themselves audited and leave the action pending. The dashboard API remains loopback-only. Analyst labels are audit attribution in this local lab, not identity verification from an external identity provider.

## Safety boundaries

- Response services only read incident models and write simulated action, timeline, and audit records.
- “Success” and “failure” are selected simulation outcomes; neither contacts nor modifies a target.
- Evidence collection records event/alert IDs and counts only. It does not retrieve payloads, files, or host data.
- No playbook runs from detection, incident creation, model inference, startup, or status changes. An analyst must request and separately authorize each simulation.
- No automated response or real containment is implemented.

Run the deterministic workflow tests with `python -m pytest tests/unit/test_incident_response.py -q`. The regular dashboard is still run with the local API described in [SOC dashboard documentation](soc-dashboard.md).
