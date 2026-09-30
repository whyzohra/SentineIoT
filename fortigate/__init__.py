"""Synthetic FortiGate log parsing and SentinelOT normalization."""

from fortigate.parser import FortiGateParseError, parse_log
from fortigate.normalizer import normalize
from fortigate.pipeline import process_logs

__all__ = ["FortiGateParseError", "parse_log", "normalize", "process_logs"]
