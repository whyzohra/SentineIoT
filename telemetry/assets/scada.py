"""SCADA simulator modeling supervisory control, automated polling, and batch commands."""

import random
from typing import Any, Dict, List, Optional
from telemetry.schemas.asset import Asset, AssetSummary
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


class SCADASimulator:
    """Simulates Supervisory Control and Data Acquisition (SCADA) server operations."""

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.batch_id = 1001
        self.active_recipe = "STANDARD_TREATMENT_RECIPE_V4"

    def generate_scada_command_event(
        self,
        target_plc: Optional[AssetSummary] = None,
    ) -> TelemetryEvent:
        """Simulate a supervisory command issued from the central SCADA server."""
        commands = [
            (
                "BATCH_SYNC",
                f"SCADA dispatched batch profile #{self.batch_id} to {target_plc.asset_id if target_plc else 'PLC-001'}",
                {"recipe": self.active_recipe, "batch_id": self.batch_id, "execution_mode": "AUTOMATIC"},
            ),
            (
                "FLOW_BALANCE_OPT",
                f"SCADA automated plant-wide flow balancing optimization cycle executed",
                {"algorithm": "PID_AUTO_TRIM", "target_efficiency": 98.4},
            ),
            (
                "HISTORIAN_ARCHIVE",
                f"SCADA Historian: committed 1,200 process variable samples to disk archive",
                {"compression_ratio": "4.2:1", "archive_status": "COMMITTED"},
            ),
            (
                "SYSTEM_WIDE_POLL",
                f"SCADA executed master scan integrity poll across all Level 1 controllers",
                {"cycle_time_ms": 112, "active_nodes_responding": 2},
            ),
        ]
        cmd_type, msg, meta = random.choice(commands)
        self.batch_id += 1

        meta.update({
            "command_type": cmd_type,
            "initiator": "SCADA_CORE_ENGINE",
            "protocol": "OPC_UA",
        })

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=target_plc,
            event_type=EventType.SCADA_COMMAND,
            severity=EventSeverity.INFO,
            message=msg,
            metadata=meta,
        )

    def generate_network_connection_event(self, target_asset: AssetSummary) -> TelemetryEvent:
        """Simulate SCADA network session establishment with field controllers."""
        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=target_asset,
            event_type=EventType.NETWORK_CONNECTION,
            severity=EventSeverity.INFO,
            message=f"Supervisory OPC UA secure channel established: {self.asset.hostname} -> {target_asset.hostname} ({target_asset.ip_address}):4840",
            metadata={
                "protocol": "OPC_UA",
                "transport": "TCP",
                "security_policy": "Basic256Sha256",
                "message_security_mode": "SignAndEncrypt",
                "status": "CHANNEL_OPEN",
            },
        )
