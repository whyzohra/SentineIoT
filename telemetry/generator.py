"""Local generator for benign, synthetic OT baseline events."""

from __future__ import annotations

from typing import Iterator, Optional

from telemetry.assets import AssetRegistry, EngineeringSimulator, HMISimulator, PLCSimulator, SCADASimulator
from telemetry.schemas.event import TelemetryEvent


class NormalTelemetryGenerator:
    """Compose simulated assets into a repeatable stream of normal events.

    This class is deliberately in-memory: it does not create sockets, open device
    connections, or send telemetry to any destination.
    """

    def __init__(self, registry: Optional[AssetRegistry] = None, seed: Optional[int] = None) -> None:
        self.registry = registry or AssetRegistry()
        self.plcs = [
            PLCSimulator(self._required_asset("PLC-001"), seed=seed),
            PLCSimulator(self._required_asset("PLC-002"), seed=None if seed is None else seed + 1),
        ]
        self.hmi = HMISimulator(self._required_asset("HMI-001"), seed=None if seed is None else seed + 2)
        self.scada = SCADASimulator(self._required_asset("SCADA-001"), seed=None if seed is None else seed + 3)
        self.engineering = EngineeringSimulator(
            self._required_asset("ENGINEERING-001"), seed=None if seed is None else seed + 4
        )
        self._index = 0

    def _required_asset(self, asset_id: str):
        asset = self.registry.get_asset(asset_id)
        if asset is None:
            raise ValueError(f"registry is missing required simulated asset {asset_id}")
        return asset

    def next_event(self) -> TelemetryEvent:
        """Generate one ordinary event, cycling through all event categories."""
        plc = self.plcs[self._index % len(self.plcs)]
        peer = self.plcs[(self._index + 1) % len(self.plcs)]
        target = plc.asset.to_summary()
        hmi_summary = self.hmi.asset.to_summary()
        scada_summary = self.scada.asset.to_summary()
        eng_summary = self.engineering.asset.to_summary()
        generators = (
            lambda: plc.generate_sensor_reading_event(destination_asset=scada_summary),
            plc.generate_state_change_event,
            lambda: self.hmi.generate_network_polling_event(target),
            lambda: plc.generate_network_connection_event(hmi_summary),
            lambda: self.hmi.generate_hmi_interaction_event(target),
            self.hmi.generate_auth_event,
            lambda: self.scada.generate_network_connection_event(target),
            lambda: self.scada.generate_scada_command_event(target),
            lambda: self.engineering.generate_config_change_event(peer.asset.to_summary()),
            self.engineering.generate_auth_event,
        )
        event = generators[self._index % len(generators)]()
        self._index += 1
        return event

    def events(self, count: Optional[int] = None) -> Iterator[TelemetryEvent]:
        """Yield events continuously, or stop after ``count`` events."""
        if count is not None and count < 0:
            raise ValueError("count must be non-negative")
        generated = 0
        while count is None or generated < count:
            yield self.next_event()
            generated += 1
