"""Local-only API and read models for the SOC dashboard."""

from dashboard_api.server import create_server
from dashboard_api.service import DashboardDataService

__all__ = ["create_server", "DashboardDataService"]

