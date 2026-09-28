"""Engineering Workstation simulator modeling maintenance, configuration changes, and programming sessions."""

import random
from typing import Any, Dict, List, Optional
from telemetry.schemas.asset import Asset, AssetSummary
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


class EngineeringSimulator:
    """Simulates maintenance activities and authorized programming actions from ENGINEERING-001."""

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.active_engineer = "eng_chen"
        self.engineers = ["eng_chen", "eng_rodriguez"]

    def generate_config_change_event(
        self,
        target_plc: Optional[AssetSummary] = None,
    ) -> TelemetryEvent:
        """Simulate an authorized configuration verification or maintenance change."""
        changes = [
            (
                "ROUTINE_TAG_BACKUP",
                f"Engineering workstation completed routine program tag snapshot for {target_plc.asset_id if target_plc else 'PLC-001'}",
                {"action": "EXPORT_TAG_DATABASE", "backup_hash": "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            ),
            (
                "LOGIC_CHECKSUM_VERIFY",
                f"Engineering workstation validated safety logic block checksum on {target_plc.asset_id if target_plc else 'PLC-002'}",
                {"action": "VERIFY_BLOCK_CHECKSUM", "result": "MATCH_CONFIRMED", "block_name": "FC_DISINFECTION_INTERLOCK"},
            ),
            (
                "RACK_DIAGNOSTIC_POLL",
                f"Engineering diagnostic utility queried module firmware health on {target_plc.asset_id if target_plc else 'PLC-001'}",
                {"action": "QUERY_CHASSIS_STATUS", "modules_scanned": 4, "faults_detected": 0},
            ),
        ]
        change_type, msg, meta = random.choice(changes)
        meta.update({
            "change_type": change_type,
            "engineer": self.active_engineer,
            "tool": "Siemens TIA Portal / Rockwell Studio 5000",
            "authorization_ticket": f"CHG-2026-{random.randint(1000, 9999)}",
        })

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=target_plc,
            event_type=EventType.CONFIG_CHANGE,
            severity=EventSeverity.INFO,
            message=msg,
            metadata=meta,
        )

    def generate_auth_event(self) -> TelemetryEvent:
        """Simulate authorized engineer authentication."""
        self.active_engineer = random.choice(self.engineers)
        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=None,
            event_type=EventType.AUTH_EVENT,
            severity=EventSeverity.INFO,
            message=f"Maintenance authentication successful: engineer '{self.active_engineer}' authenticated on {self.asset.asset_id}",
            metadata={
                "auth_method": "PKI_SMARTCARD_CAC",
                "user": self.active_engineer,
                "role": "OT_SYSTEMS_ENGINEER",
                "result": "SUCCESS",
            },
        )
