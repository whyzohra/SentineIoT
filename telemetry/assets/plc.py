"""PLC simulator modeling programmable logic controllers and physical sensor readings."""

import random
from typing import Any, Dict, List, Optional
from telemetry.schemas.asset import Asset, AssetSummary
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


class PLCSimulator:
    """Simulates a Programmable Logic Controller (PLC) with internal registers and physical I/O."""

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.cpu_mode = "RUN"
        self.scan_cycle_ms = 14.5
        self.cycle_count = 0
        self.registers: Dict[str, float] = {}
        self.coils: Dict[str, bool] = {}
        self._init_registers()

    def _init_registers(self) -> None:
        """Initialize process variables and registers according to asset role."""
        if self.asset.asset_id == "PLC-001":
            # Primary Water Intake PLC
            self.registers = {
                "intake_flow_rate_gpm": 1250.0,
                "raw_water_level_pct": 65.0,
                "intake_line_pressure_psi": 52.0,
                "pump_101_rpm": 1780.0,
                "pump_102_rpm": 0.0,  # Standby pump
                "intake_water_temp_c": 16.5,
            }
            self.coils = {
                "pump_101_run_cmd": True,
                "pump_102_run_cmd": False,
                "valve_101_open": True,
                "valve_102_open": False,
                "intake_estop_active": False,
            }
        else:
            # Chemical Dosing & Filtration PLC (e.g., PLC-002)
            self.registers = {
                "dosing_ph": 7.25,
                "turbidity_ntu": 0.32,
                "chlorine_residual_ppm": 1.45,
                "filter_differential_pressure_psi": 5.1,
                "coagulant_feed_rate_ml_min": 85.0,
                "disinfection_contact_time_min": 42.0,
            }
            self.coils = {
                "dosing_pump_1_active": True,
                "dosing_pump_2_active": False,
                "rapid_filter_backwash_cmd": False,
                "effluent_valve_open": True,
                "chem_estop_active": False,
            }

    def step_physics(self) -> None:
        """Simulate physical process drift within nominal operating envelopes."""
        self.cycle_count += 1
        # Realistic scan cycle jitter
        self.scan_cycle_ms = round(random.uniform(12.0, 16.5), 2)

        if self.asset.asset_id == "PLC-001":
            # Small bounded random walk
            self.registers["intake_flow_rate_gpm"] = round(
                max(1100.0, min(1400.0, self.registers["intake_flow_rate_gpm"] + random.uniform(-15.0, 15.0))), 1
            )
            self.registers["raw_water_level_pct"] = round(
                max(50.0, min(80.0, self.registers["raw_water_level_pct"] + random.uniform(-0.4, 0.4))), 1
            )
            self.registers["intake_line_pressure_psi"] = round(
                max(45.0, min(60.0, self.registers["intake_line_pressure_psi"] + random.uniform(-0.6, 0.6))), 1
            )
            self.registers["pump_101_rpm"] = round(
                max(1720.0, min(1820.0, self.registers["pump_101_rpm"] + random.uniform(-5.0, 5.0))), 1
            )
            self.registers["intake_water_temp_c"] = round(
                max(14.0, min(19.0, self.registers["intake_water_temp_c"] + random.uniform(-0.1, 0.1))), 1
            )
        else:
            self.registers["dosing_ph"] = round(
                max(6.90, min(7.60, self.registers["dosing_ph"] + random.uniform(-0.02, 0.02))), 2
            )
            self.registers["turbidity_ntu"] = round(
                max(0.20, min(0.50, self.registers["turbidity_ntu"] + random.uniform(-0.01, 0.01))), 2
            )
            self.registers["chlorine_residual_ppm"] = round(
                max(1.10, min(1.90, self.registers["chlorine_residual_ppm"] + random.uniform(-0.03, 0.03))), 2
            )
            self.registers["filter_differential_pressure_psi"] = round(
                max(4.0, min(6.8, self.registers["filter_differential_pressure_psi"] + random.uniform(-0.05, 0.05))), 1
            )

    def generate_sensor_reading_event(
        self,
        destination_asset: Optional[AssetSummary] = None,
        parameter_name: Optional[str] = None,
    ) -> TelemetryEvent:
        """Generate a simulated sensor reading event."""
        self.step_physics()
        if not parameter_name or parameter_name not in self.registers:
            parameter_name = random.choice(list(self.registers.keys()))

        current_val = self.registers[parameter_name]

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=destination_asset,
            event_type=EventType.SENSOR_READING,
            severity=EventSeverity.INFO,
            message=f"{self.asset.asset_id} sensor report: {parameter_name} = {current_val}",
            metadata={
                "parameter": parameter_name,
                "value": current_val,
                "protocol": "MODBUS_TCP",
                "function_code": 3,  # Read Holding Registers
                "register_block": "40001-40010",
                "scan_cycle_ms": self.scan_cycle_ms,
                "operating_status": "NORMAL",
                "all_registers_snapshot": self.registers.copy(),
            },
        )

    def generate_state_change_event(self) -> TelemetryEvent:
        """Generate a routine internal PLC diagnostic or state change event."""
        diagnostic_types = [
            ("Scan cycle watchdog check passed", EventSeverity.INFO, {"watchdog_ms": 250, "last_cycle_ms": self.scan_cycle_ms}),
            ("I/O backplane sync verified", EventSeverity.INFO, {"bus_status": "SYNCHRONIZED", "chassis_slots_active": 4}),
            ("Battery backup power health good", EventSeverity.INFO, {"battery_voltage": 3.65, "status": "HEALTHY"}),
            ("Routine memory checksum validated", EventSeverity.INFO, {"integrity_status": "PASS", "checksum": "0xA8F9"}),
        ]
        msg, sev, meta = random.choice(diagnostic_types)
        meta.update({
            "cpu_mode": self.cpu_mode,
            "firmware_version": self.asset.firmware_version,
            "cycle_count": self.cycle_count,
        })

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=None,
            event_type=EventType.PLC_STATE_CHANGE,
            severity=sev,
            message=f"{self.asset.asset_id} state check: {msg}",
            metadata=meta,
        )

    def generate_network_connection_event(self, client_asset: AssetSummary) -> TelemetryEvent:
        """Generate an event when an authorized client connects over an industrial protocol."""
        return TelemetryEvent(
            source_asset=client_asset,
            destination_asset=self.asset.to_summary(),
            event_type=EventType.NETWORK_CONNECTION,
            severity=EventSeverity.INFO,
            message=f"Modbus TCP connection established from {client_asset.hostname} ({client_asset.ip_address}) to {self.asset.asset_id} port 502",
            metadata={
                "transport": "TCP",
                "dest_port": 502,
                "protocol": "MODBUS_TCP",
                "session_state": "ESTABLISHED",
                "unit_id": 1,
            },
        )
