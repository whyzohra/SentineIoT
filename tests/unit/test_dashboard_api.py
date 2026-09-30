"""API integration tests using the actual local HTTP server and SentinelOT pipeline."""

import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from attack_simulator import AttackSimulation
from dashboard_api import create_server
from detection_engine import DetectionEngine, MITREMapper
from incident_management import IncidentService
from risk_engine import RiskEngine


@pytest.fixture
def api_server(tmp_path):
    server = create_server(str(tmp_path / "dashboard.sqlite3"), 0)
    _SERVERS[server.server_port] = server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    server.dashboard_repository.close()
    thread.join(timeout=2)
    _SERVERS.pop(server.server_port, None)


def get_json(base_url, path):
    with urlopen(f"{base_url}{path}", timeout=3) as response:
        assert response.headers["Content-Type"].startswith("application/json")
        return json.loads(response.read())


def post_json(base_url, path, body):
    request = Request(
        f"{base_url}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urlopen(request, timeout=3) as response:
        return json.loads(response.read())


def test_read_endpoints_use_asset_registry_and_telemetry_generator(api_server):
    assert get_json(api_server, "/api/health") == {"status": "ok", "mode": "local-only"}
    events = get_json(api_server, "/api/events?limit=10")
    assets = get_json(api_server, "/api/assets")
    overview = get_json(api_server, "/api/overview")
    assert len(events) == 10
    assert {event["event_type"] for event in events}
    assert {asset["asset_id"] for asset in assets} == {
        "PLC-001", "PLC-002", "HMI-001", "SCADA-001", "ENGINEERING-001",
    }
    assert set(overview["incident_counts_by_severity"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert overview["active_incident_count"] == 0
    assert get_json(api_server, "/api/assets?search=plc")


def test_attack_detection_mitre_risk_incident_appears_through_api(api_server):
    # Seed through existing public pipeline and incident service, as the Phase 6 CLI does.
    from urllib.parse import urlsplit
    address = urlsplit(api_server)
    live_server = _SERVERS[address.port]
    simulation = AttackSimulation().run("network_recon", seed=7)
    alerts = MITREMapper().enrich_many(DetectionEngine().detect(simulation.generated_events))
    assessments = RiskEngine().assess_many(alerts)
    outcome = IncidentService(live_server.dashboard_repository).ingest(alerts[0], assessments[0])
    incident_id = outcome.incident.incident_id

    alert_rows = get_json(api_server, "/api/alerts")
    assert alert_rows[0]["alert"]["mitre_mapping_status"] == "MAPPED"
    assert alert_rows[0]["risk_assessment"]["explanation"]
    overview = get_json(api_server, "/api/overview")
    assert overview["total_incident_count"] == 1
    assert overview["recent_alerts"][0]["incident_id"] == incident_id
    assert overview["affected_assets"]
    assert overview["mitre_techniques"]

    detail = get_json(api_server, f"/api/incidents/{incident_id}")
    assert set(detail["event_ids"]) == set(alerts[0].evidence["event_ids"])
    assert detail["alert_records"][0]["alert"]["mitre_mappings"]
    assert detail["alert_records"][0]["risk_assessment"]["factors"]
    assert get_json(api_server, f"/api/incidents?search={incident_id[:8]}")[0]["incident_id"] == incident_id


def test_status_note_filters_and_missing_incident_errors(api_server):
    from urllib.parse import urlsplit
    server = _SERVERS[urlsplit(api_server).port]
    simulation = AttackSimulation().run("network_recon", seed=9)
    alert = MITREMapper().enrich_many(DetectionEngine().detect(simulation.generated_events))[0]
    assessment = RiskEngine().assess(alert)
    incident = IncidentService(server.dashboard_repository).ingest(alert, assessment).incident

    result = post_json(api_server, f"/api/incidents/{incident.incident_id}/status", {"status": "INVESTIGATING"})
    assert result["status"] == "INVESTIGATING"
    result = post_json(api_server, f"/api/incidents/{incident.incident_id}/notes", {"text": "Verify simulated PLC access"})
    assert result["analyst_notes"][0]["text"] == "Verify simulated PLC access"
    assert result["audit_trail"]
    assert get_json(api_server, "/api/incidents?status=INVESTIGATING")[0]["incident_id"] == incident.incident_id
    with pytest.raises(HTTPError) as error:
        urlopen(f"{api_server}/api/incidents/not-present", timeout=3)
    assert error.value.code == 404
    result = post_json(api_server, f"/api/incidents/{incident.incident_id}/status", {"status": "CONTAINED"})
    assert result["status"] == "CONTAINED"
    with pytest.raises(HTTPError) as bad_transition:
        post_json(api_server, f"/api/incidents/{incident.incident_id}/status", {"status": "OPEN"})
    assert bad_transition.value.code == 400


_SERVERS = {}
