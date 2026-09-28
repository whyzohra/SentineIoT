"""Telemetry event schemas for SentinelOT."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field

from telemetry.schemas.asset import AssetSummary


class EventType(str, Enum):
    """Categorization of industrial telemetry events."""
    PLC_STATE_CHANGE = "PLC_STATE_CHANGE"
    SENSOR_READING = "SENSOR_READING"
    AUTH_EVENT = "AUTH_EVENT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    HMI_INTERACTION = "HMI_INTERACTION"
    SCADA_COMMAND = "SCADA_COMMAND"


class EventSeverity(str, Enum):
    """Normalized severity rating for events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TelemetryEvent(BaseModel):
    """Normalized telemetry event model adhering to SentinelOT standard schema."""
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the telemetry event"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event occurred"
    )
    source_asset: AssetSummary = Field(
        ...,
        description="Originating asset generating the event"
    )
    destination_asset: Optional[AssetSummary] = Field(
        default=None,
        description="Target asset receiving the action or request (optional for internal state changes)"
    )
    event_type: EventType = Field(
        ...,
        description="Standardized classification of the telemetry event"
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Severity level of the event"
    )
    message: str = Field(
        ...,
        description="Human-readable event message"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value context (protocol, registers, process values, user, status)"
    )

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize event to a formatted JSON string."""
        return self.model_dump_json(indent=indent)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to a Python dictionary."""
        return self.model_dump(mode="json")
