import json
import subprocess
import sys
from pathlib import Path

import pytest

from telemetry.assets import AssetRegistry
from telemetry.generator import NormalTelemetryGenerator
from telemetry.schemas.asset import Asset
from telemetry.schemas.event import EventType


ROOT = Path(__file__).resolve().parents[2]


def test_default_registry_contains_expected_private_assets():
    registry = AssetRegistry()
    assert {asset.asset_id for asset in registry.list_assets()} == {
        "PLC-001", "PLC-002", "HMI-001", "SCADA-001", "ENGINEERING-001"
    }
    assert all(Asset.model_validate(asset.model_dump()) for asset in registry.list_assets())


def test_registry_rejects_duplicate_ip_and_keeps_index_consistent():
    registry = AssetRegistry()
    duplicate = registry.get_asset("PLC-001").model_copy(update={"asset_id": "PLC-OTHER"})
    with pytest.raises(ValueError, match="already assigned"):
        registry.register_asset(duplicate)
    moved = registry.get_asset("PLC-001").model_copy(update={"ip_address": "192.168.10.99"})
    registry.register_asset(moved)
    assert registry.get_asset_by_ip("192.168.10.11") is None
    assert registry.get_asset_by_ip("192.168.10.99").asset_id == "PLC-001"


def test_asset_model_rejects_public_ip():
    raw = AssetRegistry().get_asset("PLC-001").model_dump()
    raw["ip_address"] = "8.8.8.8"
    with pytest.raises(ValueError, match="private IPv4"):
        Asset.model_validate(raw)


def test_generator_emits_all_event_types_with_common_json_schema():
    events = list(NormalTelemetryGenerator(seed=12).events(count=10))
    assert {event.event_type for event in events} == set(EventType)
    for event in events:
        data = json.loads(event.to_json())
        assert {"event_id", "timestamp", "source_asset", "destination_asset", "event_type",
                "severity", "message", "metadata"} <= data.keys()
        assert data["source_asset"]["asset_id"] in {
            "PLC-001", "PLC-002", "HMI-001", "SCADA-001", "ENGINEERING-001"
        }


def test_seeded_generators_are_repeatable_and_process_values_stay_bounded():
    left = NormalTelemetryGenerator(seed=27)
    right = NormalTelemetryGenerator(seed=27)
    for _ in range(30):
        assert left.next_event().metadata == right.next_event().metadata
    for plc in left.plcs:
        for _ in range(100):
            plc.step_physics()
        if plc.asset.asset_id == "PLC-001":
            assert 1100 <= plc.registers["intake_flow_rate_gpm"] <= 1400
            assert 50 <= plc.registers["raw_water_level_pct"] <= 80
        else:
            assert 6.9 <= plc.registers["dosing_ph"] <= 7.6
            assert .2 <= plc.registers["turbidity_ntu"] <= .5


def test_cli_outputs_jsonl_without_network_setup():
    result = subprocess.run(
        [sys.executable, "-m", "telemetry", "--count", "3", "--interval", "0", "--seed", "5"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 3
