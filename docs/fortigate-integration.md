# Synthetic FortiGate integration

The `fortigate` package accepts synthetic FortiGate JSON objects/JSON lines, CEF records, and syslog-style `key=value` records. `parse_log` parses a record and `normalize` converts it to the established `TelemetryEvent` schema. Original vendor fields are retained under `metadata.fortigate`; `fortigate_event_id` preserves the vendor log ID. Normalized metadata includes policy, action, interfaces, service, endpoints, user, and security profile when present.

Traffic records become `NETWORK_CONNECTION`. Authentication and VPN records become `AUTH_EVENT`; IPS, web-filter, and related UTM records remain network events with their category in metadata. Known lab endpoint IPs reuse SentinelOT asset identities; other endpoints are represented as firewall-class assets.

The existing detection, MITRE mapping, risk scoring, and incident services process these events. Existing authentication brute-force detection applies to FortiGate authentication records. FortiGate-specific detections cover IPS records and batches with at least five denied traffic records from one source. ATT&CK enrichment remains governed by the shared mapper's supported mappings.

All examples are synthetic. No FortiGate device, credentials, network connection, or configuration is used.

Run the sample pipeline locally:

```powershell
python -m fortigate demo --db .sentinelot-incidents.sqlite3
```

The local dashboard API exposes `POST /api/fortigate/demo`. The Live Events view includes a button to submit bundled synthetic records; resulting events, alerts, risk assessments, and incidents appear through existing dashboard views.

Fixtures live in `fortigate/fixtures/`. `demo.jsonl` drives the end-to-end sample; `formats.json` contains JSON, CEF, and syslog examples.
