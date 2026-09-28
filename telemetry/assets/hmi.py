"""HMI simulator modeling operator interactions, screen navigation, and authentication."""

import random
from typing import Any, Dict, List, Optional
from telemetry.schemas.asset import Asset, AssetSummary
from telemetry.schemas.event import EventSeverity, EventType, TelemetryEvent


class HMISimulator:
    """Simulates Human-Machine Interface (HMI) operations in the central control room."""

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.active_operator = "op_smith"
        self.current_screen = "MAIN_WATER_OVERVIEW"
        self.operators = ["op_smith", "op_patel", "supervisor_jones"]
        self.screens = [
            "MAIN_WATER_OVERVIEW",
            "INTAKE_PUMPING_DETAIL",
            "CHEMICAL_DOSING_VIEW",
            "FILTRATION_TRENDS",
            "HISTORICAL_ALARMS",
        ]

    def generate_hmi_interaction_event(
        self,
        target_plc: Optional[AssetSummary] = None,
    ) -> TelemetryEvent:
        """Simulate an operator interacting with the HMI console."""
        interaction_types = [
            ("screen_navigation", "navigated to screen"),
            ("setpoint_adjustment", "adjusted nominal setpoint"),
            ("alarm_acknowledgement", "acknowledged advisory notification"),
            ("tag_view", "opened live trend telemetry monitor"),
        ]
        action_type, desc = random.choice(interaction_types)

        if action_type == "screen_navigation":
            self.current_screen = random.choice(self.screens)
            msg = f"Operator {self.active_operator} {desc} [{self.current_screen}] on {self.asset.asset_id}"
            meta = {
                "action": "SCREEN_NAVIGATION",
                "target_screen": self.current_screen,
                "operator": self.active_operator,
            }
        elif action_type == "setpoint_adjustment":
            param = "intake_target_flow_gpm" if not target_plc or target_plc.asset_id == "PLC-001" else "target_ph"
            val = round(random.uniform(1200.0, 1300.0), 1) if "flow" in param else round(random.uniform(7.15, 7.35), 2)
            msg = f"Operator {self.active_operator} {desc}: set {param} = {val} on {target_plc.asset_id if target_plc else 'PLC-001'}"
            meta = {
                "action": "SETPOINT_ADJUST",
                "parameter": param,
                "nominal_setpoint": val,
                "protocol": "MODBUS_TCP",
                "function_code": 6,  # Write Single Register
                "operator": self.active_operator,
            }
        elif action_type == "alarm_acknowledgement":
            msg = f"Operator {self.active_operator} {desc} on {self.asset.asset_id}"
            meta = {
                "action": "ALARM_ACKNOWLEDGE",
                "alarm_id": f"ALM-2026-{random.randint(100, 999)}",
                "operator": self.active_operator,
            }
        else:
            msg = f"Operator {self.active_operator} {desc} for {target_plc.asset_id if target_plc else 'Plant Wide'}"
            meta = {
                "action": "TAG_TREND_VIEW",
                "operator": self.active_operator,
                "screen": self.current_screen,
            }

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=target_plc,
            event_type=EventType.HMI_INTERACTION,
            severity=EventSeverity.INFO,
            message=msg,
            metadata=meta,
        )

    def generate_auth_event(self) -> TelemetryEvent:
        """Simulate legitimate operator authentication or shift handover."""
        event_subtype = random.choice(["LOGIN_SUCCESS", "LOGOUT_CLEAN", "SESSION_REFRESH"])
        if event_subtype == "LOGIN_SUCCESS":
            self.active_operator = random.choice(self.operators)
            msg = f"Operator authentication successful: user '{self.active_operator}' logged into {self.asset.asset_id}"
            meta = {
                "auth_method": "DOMAIN_CREDENTIAL_SMARTCARD",
                "user": self.active_operator,
                "role": "CONTROL_ROOM_OPERATOR",
                "result": "SUCCESS",
            }
        elif event_subtype == "LOGOUT_CLEAN":
            prev_user = self.active_operator
            msg = f"Operator session closed: user '{prev_user}' logged off {self.asset.asset_id}"
            meta = {
                "user": prev_user,
                "session_duration_minutes": random.randint(120, 480),
                "result": "SUCCESS",
            }
        else:
            msg = f"Interactive session token refreshed for user '{self.active_operator}' on {self.asset.asset_id}"
            meta = {
                "user": self.active_operator,
                "result": "SUCCESS",
            }

        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=None,
            event_type=EventType.AUTH_EVENT,
            severity=EventSeverity.INFO,
            message=msg,
            metadata=meta,
        )

    def generate_network_polling_event(self, target_plc: AssetSummary) -> TelemetryEvent:
        """Simulate HMI periodic supervisory polling to a PLC."""
        return TelemetryEvent(
            source_asset=self.asset.to_summary(),
            destination_asset=target_plc,
            event_type=EventType.NETWORK_CONNECTION,
            severity=EventSeverity.INFO,
            message=f"HMI supervisory poll: Read Holding Registers from {target_plc.hostname} ({target_plc.ip_address}):502",
            metadata={
                "protocol": "MODBUS_TCP",
                "function_code": 3,
                "register_range": "40001-40020",
                "transport": "TCP",
                "status": "RESPONSE_OK",
            },
        )
