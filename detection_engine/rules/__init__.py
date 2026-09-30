"""Independently testable rule implementations."""

from detection_engine.rules.auth_brute_force import BruteForceRule
from detection_engine.rules.insider_anomaly import InsiderBehaviorRule
from detection_engine.rules.network_recon import NetworkReconRule
from detection_engine.rules.fortigate import FortiGateDeniedBurstRule, FortiGateIPSRule
from detection_engine.rules.plc_command_frequency import PLCCommandFrequencyRule
from detection_engine.rules.unauthorized_plc import UnauthorizedPLCAccessRule

DEFAULT_RULES = (
    NetworkReconRule(),
    BruteForceRule(),
    UnauthorizedPLCAccessRule(),
    PLCCommandFrequencyRule(),
    InsiderBehaviorRule(),
    FortiGateIPSRule(),
    FortiGateDeniedBurstRule(),
)

__all__ = [
    "BruteForceRule", "InsiderBehaviorRule", "NetworkReconRule",
    "PLCCommandFrequencyRule", "UnauthorizedPLCAccessRule", "DEFAULT_RULES",
    "FortiGateIPSRule", "FortiGateDeniedBurstRule",
]
