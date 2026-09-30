"""Asset data models and schemas for SentinelOT."""

from enum import Enum
from ipaddress import IPv4Address
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class AssetType(str, Enum):
    """Industrial asset classification aligned with ISA-95/Purdue model."""
    PLC = "PLC"
    HMI = "HMI"
    SCADA = "SCADA"
    ENGINEERING_WORKSTATION = "ENGINEERING_WORKSTATION"
    FIREWALL = "FIREWALL"
    RTU = "RTU"
    SENSOR = "SENSOR"


class AssetStatus(str, Enum):
    """Operational status of an OT asset."""
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    FAULT = "FAULT"
    MAINTENANCE = "MAINTENANCE"
    OFFLINE = "OFFLINE"


class PurdueLevel(int, Enum):
    """Purdue Enterprise Reference Architecture (ISA-95) levels."""
    LEVEL_0 = 0  # Physical process (sensors, actuators)
    LEVEL_1 = 1  # Basic control (PLCs, RTUs, safety controllers)
    LEVEL_2 = 2  # Area supervisory control (HMIs, supervisory PLCs)
    LEVEL_3 = 3  # Operations & control (SCADA servers, Engineering stations, Historians)
    LEVEL_4 = 4  # Business planning & logistics (Enterprise IT)
    LEVEL_5 = 5  # Enterprise network / Cloud uplink


class AssetSummary(BaseModel):
    """Condensed asset summary embedded inside telemetry events."""
    asset_id: str = Field(..., description="Unique asset identifier (e.g., PLC-001)")
    hostname: str = Field(..., description="Network hostname")
    ip_address: str = Field(..., description="IP address within isolated lab subnet")
    asset_type: AssetType = Field(..., description="Classification of the industrial asset")
    purdue_level: int = Field(..., ge=0, le=5, description="Purdue model hierarchy level")


class Asset(BaseModel):
    """Full industrial asset record maintained in the OT Asset Registry."""
    asset_id: str = Field(..., description="Unique asset identifier (e.g., PLC-001)")
    hostname: str = Field(..., description="Network hostname (e.g., plc01.water.ot.local)")
    ip_address: str = Field(..., description="IP address from private lab subnet")
    asset_type: AssetType = Field(..., description="Asset type")
    manufacturer: str = Field(..., description="Vendor/Manufacturer (e.g., Rockwell Automation, Siemens)")
    firmware_version: str = Field(..., description="Firmware version (e.g., v32.011, v2.9.4)")
    criticality: int = Field(..., ge=1, le=5, description="Asset criticality (1=Low, 5=Mission-Critical)")
    status: AssetStatus = Field(default=AssetStatus.ONLINE, description="Current operational state")
    purdue_level: int = Field(..., ge=0, le=5, description="Purdue Level (0 to 5)")
    zone: str = Field(default="CONTROL", description="ISA/IEC 62443 Security Zone")
    protocols: List[str] = Field(default_factory=list, description="Supported industrial protocols")
    description: Optional[str] = Field(default=None, description="Human-readable description of function")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom operational metadata")

    @field_validator("ip_address")
    @classmethod
    def require_private_ipv4(cls, value: str) -> str:
        address = IPv4Address(value)
        if not address.is_private:
            raise ValueError("simulated assets must use a private IPv4 address")
        return str(address)

    def to_summary(self) -> AssetSummary:
        """Convert asset model to a lightweight summary for event attribution."""
        return AssetSummary(
            asset_id=self.asset_id,
            hostname=self.hostname,
            ip_address=self.ip_address,
            asset_type=self.asset_type,
            purdue_level=self.purdue_level,
        )
