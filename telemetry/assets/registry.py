"""OT Asset Registry managing all industrial devices in the simulated laboratory."""

from typing import Dict, List, Optional
from telemetry.schemas.asset import (
    Asset,
    AssetStatus,
    AssetSummary,
    AssetType,
    PurdueLevel,
)


class AssetRegistry:
    """Registry maintaining an in-memory inventory of simulated OT/ICS assets."""

    def __init__(self, load_defaults: bool = True) -> None:
        self._assets: Dict[str, Asset] = {}
        self._ip_index: Dict[str, str] = {}  # ip_address -> asset_id
        if load_defaults:
            self._load_default_assets()

    def _load_default_assets(self) -> None:
        """Seed default industrial assets representing a realistic water treatment plant."""
        default_assets = [
            Asset(
                asset_id="PLC-001",
                hostname="plc01.water.ot.local",
                ip_address="192.168.10.11",
                asset_type=AssetType.PLC,
                manufacturer="Rockwell Automation",
                firmware_version="v32.011",
                criticality=5,
                status=AssetStatus.ONLINE,
                purdue_level=PurdueLevel.LEVEL_1.value,
                zone="ZONE_PROCESS_INTAKE",
                protocols=["MODBUS_TCP", "CIP", "ETHERNET_IP"],
                description="Primary Water Intake & Pumping Controller",
                metadata={
                    "rack": 1,
                    "slot": 0,
                    "model": "ControlLogix 5580",
                    "monitored_subsystem": "Water Intake & Raw Storage",
                },
            ),
            Asset(
                asset_id="PLC-002",
                hostname="plc02.chem.ot.local",
                ip_address="192.168.10.12",
                asset_type=AssetType.PLC,
                manufacturer="Siemens",
                firmware_version="v2.9.4",
                criticality=5,
                status=AssetStatus.ONLINE,
                purdue_level=PurdueLevel.LEVEL_1.value,
                zone="ZONE_PROCESS_TREATMENT",
                protocols=["MODBUS_TCP", "S7COMM", "PROFINET"],
                description="Chemical Dosing & Rapid Filtration Controller",
                metadata={
                    "rack": 1,
                    "slot": 2,
                    "model": "SIMATIC S7-1500",
                    "monitored_subsystem": "Chemical Dosing & Disinfection",
                },
            ),
            Asset(
                asset_id="HMI-001",
                hostname="hmi01.controlroom.ot.local",
                ip_address="192.168.20.21",
                asset_type=AssetType.HMI,
                manufacturer="Schneider Electric",
                firmware_version="v2023.1",
                criticality=4,
                status=AssetStatus.ONLINE,
                purdue_level=PurdueLevel.LEVEL_2.value,
                zone="ZONE_SUPERVISORY_AREA",
                protocols=["HTTPS", "MODBUS_TCP", "OPC_UA"],
                description="Central Control Room Operator Terminal",
                metadata={
                    "os": "Windows 10 Enterprise LTSC",
                    "software": "Wonderware InTouch HMI v2023",
                    "terminal_location": "Main Control Building Room 102",
                },
            ),
            Asset(
                asset_id="SCADA-001",
                hostname="scada01.central.ot.local",
                ip_address="192.168.30.31",
                asset_type=AssetType.SCADA,
                manufacturer="Inductive Automation",
                firmware_version="v8.1.33",
                criticality=5,
                status=AssetStatus.ONLINE,
                purdue_level=PurdueLevel.LEVEL_3.value,
                zone="ZONE_OPERATIONS_CONTROL",
                protocols=["OPC_UA", "DNP3", "HTTPS", "MODBUS_TCP"],
                description="Enterprise Supervisory SCADA & Historian Server",
                metadata={
                    "os": "Red Hat Enterprise Linux 9",
                    "software": "Ignition Gateway Pro v8.1.33",
                    "historian_enabled": True,
                },
            ),
            Asset(
                asset_id="ENGINEERING-001",
                hostname="eng01.maint.ot.local",
                ip_address="192.168.30.41",
                asset_type=AssetType.ENGINEERING_WORKSTATION,
                manufacturer="Siemens / Dell",
                firmware_version="v18.0",
                criticality=4,
                status=AssetStatus.ONLINE,
                purdue_level=PurdueLevel.LEVEL_3.value,
                zone="ZONE_OPERATIONS_CONTROL",
                protocols=["RDP", "S7COMM", "SSH", "CIP"],
                description="Authorized Engineering Maintenance & Programming Workstation",
                metadata={
                    "os": "Windows 11 Pro for Workstations",
                    "installed_ides": ["TIA Portal v18", "Studio 5000 Logix Designer v34"],
                    "security_token_required": True,
                },
            ),
        ]

        for asset in default_assets:
            self.register_asset(asset)

    def register_asset(self, asset: Asset) -> None:
        """Add or replace an asset while preserving unique ID and IP indexes."""
        ip_owner = self._ip_index.get(asset.ip_address)
        if ip_owner is not None and ip_owner != asset.asset_id:
            raise ValueError(f"IP address {asset.ip_address} is already assigned to {ip_owner}")
        old = self._assets.get(asset.asset_id)
        if old and old.ip_address != asset.ip_address:
            self._ip_index.pop(old.ip_address, None)
        self._assets[asset.asset_id] = asset
        self._ip_index[asset.ip_address] = asset.asset_id

    def remove_asset(self, asset_id: str) -> Optional[Asset]:
        """Remove an asset and its IP index entry."""
        asset = self._assets.pop(asset_id, None)
        if asset:
            self._ip_index.pop(asset.ip_address, None)
        return asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Lookup an asset by its unique asset_id."""
        return self._assets.get(asset_id)

    def get_asset_by_ip(self, ip_address: str) -> Optional[Asset]:
        """Lookup an asset by its IP address."""
        asset_id = self._ip_index.get(ip_address)
        if asset_id:
            return self._assets.get(asset_id)
        return None

    def get_summary(self, asset_id: str) -> Optional[AssetSummary]:
        """Retrieve lightweight summary for an asset."""
        asset = self.get_asset(asset_id)
        if asset:
            return asset.to_summary()
        return None

    def list_assets(
        self,
        asset_type: Optional[AssetType] = None,
        status: Optional[AssetStatus] = None,
        purdue_level: Optional[int] = None,
    ) -> List[Asset]:
        """Filter assets by type, status, or Purdue hierarchy level."""
        results = list(self._assets.values())
        if asset_type:
            results = [a for a in results if a.asset_type == asset_type]
        if status:
            results = [a for a in results if a.status == status]
        if purdue_level is not None:
            results = [a for a in results if a.purdue_level == purdue_level]
        return results

    def count(self) -> int:
        """Return total number of registered assets."""
        return len(self._assets)
