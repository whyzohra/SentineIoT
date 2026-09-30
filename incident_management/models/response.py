"""Persisted records for analyst-authorized simulated response actions."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class ResponseActionType(str, Enum):
    SIMULATED_HOST_ISOLATION = "SIMULATED_HOST_ISOLATION"
    SIMULATED_ACCOUNT_DISABLEMENT = "SIMULATED_ACCOUNT_DISABLEMENT"
    SIMULATED_PLC_ACCESS_BLOCK = "SIMULATED_PLC_ACCESS_BLOCK"
    SIMULATED_EVIDENCE_COLLECTION = "SIMULATED_EVIDENCE_COLLECTION"


class ResponseActionStatus(str, Enum):
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    ROLLED_BACK = "ROLLED_BACK"


class SimulatedOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    playbook_id: str
    action_type: ResponseActionType
    target: str | None = None
    status: ResponseActionStatus = ResponseActionStatus.PENDING_AUTHORIZATION
    simulation_only: bool = True
    created_at: datetime
    updated_at: datetime
    authorized_at: datetime | None = None
    completed_at: datetime | None = None
    analyst: str
    authorized_by: str | None = None
    reason: str
    authorization_reason: str | None = None
    simulation_outcome: SimulatedOutcome | None = None
    result: str = "Awaiting explicit analyst authorization. No action has been executed."
    result_details: dict = Field(default_factory=dict)


class ResponsePlaybook(BaseModel):
    playbook_id: str
    title: str
    description: str
    action_type: ResponseActionType
    target_options: list[str] = Field(default_factory=list)
    safety_boundary: str = "Simulation only; no real system is modified."
