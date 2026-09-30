import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from attack_simulator import AttackSimulation, ScenarioCatalog
from telemetry.assets import AssetRegistry
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


ROOT = Path(__file__).resolve().parents[2]
SCENARIO_IDS = (
    "network_recon",
    "brute_force",
    "unauthorized_plc",
    "plc_anomaly",
    "insider_anomaly",
)


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_scenario_identity_assets_events_and_determinism(scenario_id, monkeypatch):
    def forbidden_socket(*_args, **_kwargs):
        raise AssertionError("scenario attempted real network activity")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    first = AttackSimulation().run(scenario_id, seed=41, count=3)
    second = AttackSimulation().run(scenario_id, seed=41, count=3)

    assert first.scenario_id == scenario_id
    assert first.name and first.description and first.expected_detection
    assert first.expected_severity in EventSeverity
    assert first.mitre_attack["technique_id"]
    assert first.mitre_attack["url"].startswith("https://attack.mitre.org/")
    registry = AssetRegistry()
    assert first.source_asset.asset_id in {asset.asset_id for asset in registry.list_assets()}
    if first.target_asset is not None:
        assert first.target_asset.asset_id in {asset.asset_id for asset in registry.list_assets()}
    assert [event.to_dict() for event in first.generated_events] == [
        event.to_dict() for event in second.generated_events
    ]
    assert len(first.generated_events) == 3
    for event in first.generated_events:
        assert isinstance(TelemetryEvent.model_validate(event.to_dict()), TelemetryEvent)
        assert event.source_asset.asset_id == first.source_asset.asset_id
        assert event.metadata["scenario_id"] == scenario_id
        assert event.metadata["simulation_only"] is True
        assert event.metadata["mitre_attack"] == first.mitre_attack
        if event.destination_asset:
            assert registry.get_asset(event.destination_asset.asset_id) is not None


@pytest.mark.parametrize(
    ("scenario_id", "event_type", "severity", "metadata_key", "metadata_value"),
    [
        ("network_recon", EventType.NETWORK_CONNECTION, EventSeverity.MEDIUM, "connection_result", "NOT_PERFORMED"),
        ("brute_force", EventType.AUTH_EVENT, EventSeverity.HIGH, "credential_attempted", False),
        ("unauthorized_plc", EventType.SCADA_COMMAND, EventSeverity.HIGH, "command_executed", False),
        ("plc_anomaly", EventType.SENSOR_READING, EventSeverity.CRITICAL, "anomaly", True),
        ("insider_anomaly", EventType.CONFIG_CHANGE, EventSeverity.HIGH, "change_applied", False),
    ],
)
def test_scenario_expected_event_characteristics(scenario_id, event_type, severity, metadata_key, metadata_value):
    result = AttackSimulation().run(scenario_id, seed=8, count=1)
    event = result.generated_events[0]
    assert event.event_type == event_type
    assert event.severity == severity == result.expected_severity
    assert event.metadata[metadata_key] == metadata_value


def test_network_recon_only_references_registered_assets_and_registry_is_unchanged():
    registry = AssetRegistry()
    initial_assets = [asset.model_dump(mode="json") for asset in registry.list_assets()]
    result = AttackSimulation(registry).run("network_recon", seed=1)
    assert all(event.destination_asset for event in result.generated_events)
    assert {event.destination_asset.asset_id for event in result.generated_events} <= {
        asset.asset_id for asset in registry.list_assets()
    }
    assert [asset.model_dump(mode="json") for asset in registry.list_assets()] == initial_assets


def test_scenario_catalog_rejects_unknown_id():
    with pytest.raises(ValueError, match="available"):
        ScenarioCatalog().get("not_a_scenario")


def test_cli_list_and_all_scenario_commands_smoke():
    listed = subprocess.run(
        [sys.executable, "-m", "attack_simulator", "list"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    for scenario_id in SCENARIO_IDS:
        assert scenario_id in listed.stdout

        result = subprocess.run(
            [sys.executable, "-m", "attack_simulator", "run", scenario_id, "--seed", "12", "--count", "2"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        assert result.stdout.startswith("SIMULATION ONLY — SentinelOT isolated laboratory\n")
        payload = json.loads(result.stdout.split("\n", 1)[1])
        assert payload["scenario_id"] == scenario_id
        assert len(payload["generated_events"]) == 2
