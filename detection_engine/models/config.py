"""Centralized, validated thresholds and simulated OT policy settings."""

from dataclasses import dataclass, field

from telemetry.schemas.event import EventType


@dataclass(frozen=True)
class DetectionConfig:
    """All tunable detection windows, baselines, and simulated allowlist policy.

    Frequencies are measured as events per minute. Maintenance hours are UTC,
    start-inclusive and end-exclusive. PLC access allowlists are keyed by target
    asset ID and list authorized source asset IDs.
    """

    network_recon_window_seconds: int = 60
    network_recon_unique_target_threshold: int = 3
    auth_window_seconds: int = 300
    auth_failure_threshold: int = 3
    plc_command_window_seconds: int = 60
    plc_command_baseline_per_minute: float = 2.0
    plc_command_baseline_multiplier: float = 2.0
    plc_command_event_types: tuple[EventType, ...] = (
        EventType.SCADA_COMMAND,
        EventType.CONFIG_CHANGE,
        EventType.HMI_INTERACTION,
    )
    authorized_plc_sources: dict[str, frozenset[str]] = field(default_factory=lambda: {
        "PLC-001": frozenset({"HMI-001", "SCADA-001"}),
        "PLC-002": frozenset({"HMI-001", "SCADA-001", "ENGINEERING-001"}),
    })
    maintenance_start_hour_utc: int = 6
    maintenance_end_hour_utc: int = 18
    insider_activity_window_seconds: int = 300
    insider_activity_baseline_count: int = 3
    insider_activity_baseline_multiplier: float = 2.0
    insider_monitored_event_types: tuple[EventType, ...] = (
        EventType.CONFIG_CHANGE,
        EventType.SCADA_COMMAND,
        EventType.HMI_INTERACTION,
    )
    trusted_insider_sources: frozenset[str] = frozenset({"ENGINEERING-001", "SCADA-001", "HMI-001"})
    trusted_insider_accounts: frozenset[str] = frozenset({
        "eng_chen", "eng_rodriguez", "op_smith", "op_patel", "supervisor_jones", "SCADA_CORE_ENGINE"
    })
    approved_plc_targets: frozenset[str] = frozenset({"PLC-001", "PLC-002"})
    unauthorized_status_values: frozenset[str] = frozenset({
        "DENIED", "DENIED_SIMULATED", "UNAPPROVED", "UNAPPROVED_SIMULATED"
    })

    def __post_init__(self) -> None:
        if self.network_recon_window_seconds <= 0 or self.network_recon_unique_target_threshold < 2:
            raise ValueError("recon window must be positive and unique target threshold at least 2")
        if self.auth_window_seconds <= 0 or self.auth_failure_threshold < 1:
            raise ValueError("authentication window and failure threshold must be positive")
        if self.plc_command_window_seconds <= 0:
            raise ValueError("PLC command window must be positive")
        if self.plc_command_baseline_per_minute < 0 or self.plc_command_baseline_multiplier <= 0:
            raise ValueError("PLC command baseline must be non-negative and multiplier positive")
        if not 0 <= self.maintenance_start_hour_utc <= 23 or not 0 <= self.maintenance_end_hour_utc <= 24:
            raise ValueError("maintenance hours must be in UTC hour range [0, 24]")
        if self.maintenance_start_hour_utc >= self.maintenance_end_hour_utc:
            raise ValueError("maintenance start hour must be earlier than end hour")
        if self.insider_activity_window_seconds <= 0 or self.insider_activity_baseline_count < 1:
            raise ValueError("insider activity window and baseline count must be positive")
        if self.insider_activity_baseline_multiplier <= 0:
            raise ValueError("insider activity baseline multiplier must be positive")
