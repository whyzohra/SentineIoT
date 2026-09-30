"""Playbook planning and dry-run response simulations; contains no real actuators."""

from datetime import datetime, timezone

from incident_management import IncidentService
from incident_management.models import (
    AuditRecord, Incident, IncidentStatus, ResponseAction, ResponseActionStatus,
    ResponseActionType, ResponsePlaybook, SimulatedOutcome, TimelineEntry,
)


ACTIVE_INCIDENT_STATES = {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}


class IncidentResponseService:
    """Create pending actions, then require explicit analyst consent to simulate them."""

    SAFETY = "Simulation only. No network, OS, firewall, PLC, or account changes are performed."

    def __init__(self, incidents: IncidentService):
        self.incidents = incidents

    def available_playbooks(self, incident_id: str) -> list[ResponsePlaybook]:
        incident = self.incidents.get(incident_id)
        assets = self._asset_map(incident)
        accounts = self._accounts(incident)
        choices = []
        if assets:
            choices.append(ResponsePlaybook(
                playbook_id="isolate-host", title="Simulated host isolation",
                description="Record a dry-run isolation of an asset linked to this incident.",
                action_type=ResponseActionType.SIMULATED_HOST_ISOLATION, target_options=sorted(assets),
                safety_boundary=self.SAFETY,
            ))
        if accounts:
            choices.append(ResponsePlaybook(
                playbook_id="disable-account", title="Simulated account disablement",
                description="Record a dry-run disablement for an account in incident evidence.",
                action_type=ResponseActionType.SIMULATED_ACCOUNT_DISABLEMENT, target_options=sorted(accounts),
                safety_boundary=self.SAFETY,
            ))
        plc_targets = sorted(asset_id for asset_id, kind in assets.items() if kind in {"PLC", "RTU"})
        if plc_targets:
            choices.append(ResponsePlaybook(
                playbook_id="block-plc-access", title="Simulated PLC access block",
                description="Record a dry-run access block for an affected PLC or RTU.",
                action_type=ResponseActionType.SIMULATED_PLC_ACCESS_BLOCK, target_options=plc_targets,
                safety_boundary=self.SAFETY,
            ))
        choices.append(ResponsePlaybook(
            playbook_id="collect-evidence", title="Collect evidence references",
            description="Create a simulation record listing event and alert IDs for analyst review.",
            action_type=ResponseActionType.SIMULATED_EVIDENCE_COLLECTION,
            safety_boundary=self.SAFETY,
        ))
        return choices

    def request_action(self, incident_id: str, playbook_id: str, *, analyst: str,
                       reason: str, target: str | None = None) -> Incident:
        incident = self.incidents.get(incident_id)
        if incident.status not in ACTIVE_INCIDENT_STATES:
            raise ValueError("Simulated response requests require an active incident")
        analyst, reason = analyst.strip(), reason.strip()
        if not analyst or not reason:
            raise ValueError("Analyst and reason are required to request a response action")
        playbook = next((item for item in self.available_playbooks(incident_id)
                         if item.playbook_id == playbook_id), None)
        if playbook is None:
            raise ValueError("Playbook is unavailable for this incident evidence")
        if playbook.target_options:
            target = target or playbook.target_options[0]
            if target not in playbook.target_options:
                raise ValueError("Target must be present in this incident's evidence")
        elif target:
            raise ValueError("This playbook does not accept a target")
        now = datetime.now(timezone.utc)
        action = ResponseAction(
            incident_id=incident_id, playbook_id=playbook_id, action_type=playbook.action_type,
            target=target, created_at=now, updated_at=now, analyst=analyst, reason=reason,
        )
        return self._record(incident, action, "SIMULATED_RESPONSE_REQUESTED", analyst, reason,
                            "Response simulation requested and is awaiting authorization.",
                            expected_status=None)

    def authorize_and_execute(self, incident_id: str, action_id: str, *, analyst: str,
                              authorized: bool, reason: str,
                              outcome: SimulatedOutcome = SimulatedOutcome.SUCCESS) -> Incident:
        incident = self.incidents.get(incident_id)
        action = self._action(incident, action_id)
        analyst, reason = analyst.strip(), reason.strip()
        if action.status != ResponseActionStatus.PENDING_AUTHORIZATION:
            raise ValueError("Only a pending simulated action can be authorized")
        if not analyst or not reason:
            raise ValueError("Analyst and authorization reason are required")
        if authorized is not True:
            self._record(incident, action, "SIMULATED_RESPONSE_AUTHORIZATION_DENIED", analyst, reason,
                         "Authorization was not granted; action remains pending and nothing was executed.",
                         expected_status=ResponseActionStatus.PENDING_AUTHORIZATION)
            raise ValueError("Explicit analyst authorization is required before simulation")
        if incident.status not in ACTIVE_INCIDENT_STATES:
            raise ValueError("Incident is no longer active; simulated action cannot execute")
        now = datetime.now(timezone.utc)
        result, details = self._simulate(incident, action, outcome)
        status = ResponseActionStatus.SUCCEEDED if outcome == SimulatedOutcome.SUCCESS else ResponseActionStatus.FAILED
        updated = action.model_copy(update={
            "status": status, "updated_at": now, "authorized_at": now, "completed_at": now,
            "analyst": analyst, "authorized_by": analyst, "authorization_reason": reason,
            "simulation_outcome": outcome, "result": result, "result_details": details,
        })
        return self._record(incident, updated, "SIMULATED_RESPONSE_AUTHORIZED", analyst, reason,
                            result, expected_status=ResponseActionStatus.PENDING_AUTHORIZATION)

    def cancel(self, incident_id: str, action_id: str, *, analyst: str, reason: str) -> Incident:
        incident = self.incidents.get(incident_id)
        action = self._action(incident, action_id)
        if action.status != ResponseActionStatus.PENDING_AUTHORIZATION:
            raise ValueError("Only a pending action can be cancelled")
        analyst, reason = analyst.strip(), reason.strip()
        if not analyst or not reason:
            raise ValueError("Analyst and cancellation reason are required")
        now = datetime.now(timezone.utc)
        result = "Simulation cancelled before authorization; no action was executed."
        updated = action.model_copy(update={"status": ResponseActionStatus.CANCELLED, "updated_at": now,
                                            "completed_at": now, "analyst": analyst, "result": result,
                                            "result_details": {"simulation_only": True,
                                                               "cancellation_reason": reason,
                                                               "side_effects_performed": False}})
        return self._record(incident, updated, "SIMULATED_RESPONSE_CANCELLED", analyst, reason,
                            result, expected_status=ResponseActionStatus.PENDING_AUTHORIZATION)

    def rollback(self, incident_id: str, action_id: str, *, analyst: str, reason: str) -> Incident:
        incident = self.incidents.get(incident_id)
        action = self._action(incident, action_id)
        if action.status != ResponseActionStatus.SUCCEEDED:
            raise ValueError("Only a successful simulated action can be rolled back")
        analyst, reason = analyst.strip(), reason.strip()
        if not analyst or not reason:
            raise ValueError("Analyst and rollback reason are required")
        now = datetime.now(timezone.utc)
        result = "Simulated rollback recorded; no real state existed or was changed."
        updated = action.model_copy(update={"status": ResponseActionStatus.ROLLED_BACK,
                                            "updated_at": now, "completed_at": now,
                                            "analyst": analyst, "result": result,
                                            "result_details": {"simulation_only": True,
                                                               "rollback_reason": reason,
                                                               "side_effects_performed": False}})
        return self._record(incident, updated, "SIMULATED_RESPONSE_ROLLED_BACK", analyst, reason,
                            result, expected_status=ResponseActionStatus.SUCCEEDED)

    def _simulate(self, incident: Incident, action: ResponseAction, outcome: SimulatedOutcome):
        details = {"simulation_only": True, "side_effects_performed": False,
                   "target": action.target, "outcome": outcome.value}
        if outcome == SimulatedOutcome.FAILURE:
            return (f"Simulated {action.action_type.value.lower()} failed; no real system was contacted or changed.",
                    details)
        if action.action_type == ResponseActionType.SIMULATED_EVIDENCE_COLLECTION:
            details.update({"event_ids": list(incident.event_ids),
                            "alert_ids": [record.alert.alert_id for record in incident.alert_records],
                            "event_count": len(incident.event_ids),
                            "alert_count": len(incident.alert_records)})
            return "Evidence references collected in simulation; source data was not accessed or copied.", details
        return (f"Simulation succeeded: {action.target} would be affected by "
                f"{action.action_type.value.lower()}; no real system was contacted or changed.", details)

    def _record(self, incident: Incident, action: ResponseAction, audit_action: str,
                analyst: str, reason: str, result: str, *, expected_status):
        now = datetime.now(timezone.utc)
        timeline = TimelineEntry(timestamp=now, kind="SIMULATED_RESPONSE",
                                 summary=result, actor=analyst,
                                 event_ids=incident.event_ids,
                                 details={"action_id": action.action_id,
                                          "action_type": action.action_type.value,
                                          "status": action.status.value,
                                          "simulation_only": True})
        audit = AuditRecord(timestamp=now, actor=analyst, action=audit_action,
                            reason=reason, details={"action_id": action.action_id,
                                                    "incident_id": incident.incident_id,
                                                    "action_type": action.action_type.value,
                                                    "status": action.status.value,
                                                    "target": action.target,
                                                    "simulation_only": True,
                                                    "result": result})
        return self.incidents.repository.record_response_action(
            incident.incident_id, action, timeline=timeline, audit=audit,
            expected_status=expected_status,
        )

    @staticmethod
    def _action(incident: Incident, action_id: str) -> ResponseAction:
        action = next((item for item in incident.response_actions if item.action_id == action_id), None)
        if action is None:
            raise KeyError(f"Response action not found: {action_id}")
        return action

    @staticmethod
    def _asset_map(incident: Incident) -> dict[str, str]:
        result = {}
        for record in incident.alert_records:
            for asset in (*record.alert.source_assets, *record.alert.target_assets):
                result[asset.asset_id] = asset.asset_type.value
        return result

    @staticmethod
    def _accounts(incident: Incident) -> set[str]:
        values = set()
        for record in incident.alert_records:
            for source in (record.alert.evidence, record.alert.metadata):
                for key in ("account", "user", "username"):
                    value = source.get(key)
                    if value and str(value).lower() != "unknown":
                        values.add(str(value))
        return values
