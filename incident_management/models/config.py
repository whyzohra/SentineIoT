"""Correlation policy configuration."""

from pydantic import BaseModel, Field


class CorrelationConfig(BaseModel):
    time_window_seconds: int = Field(default=900, ge=1)
    minimum_shared_assets: int = Field(default=1, ge=1)
    correlate_shared_accounts: bool = True
    correlate_shared_techniques: bool = True

