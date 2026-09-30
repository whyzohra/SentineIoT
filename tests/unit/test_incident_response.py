import pytest

from incident_management import IncidentService, SQLiteIncidentRepository
from incident_management.models import ResponseActionStatus, SimulatedOutcome
from incident_response import IncidentResponseService
from incident_response.fixtures import seeded_incident


def test_analyst_must_explicitly_authorize_before_dry_run(tmp_path):
    repository = SQLiteIncidentRepository(str(tmp_path / "response.sqlite3"))
    try:
        incident = seeded_incident(repository)
        response = IncidentResponseService(IncidentService(repository))
        plans = response.available_playbooks(incident.incident_id)
        host_plan = next(item for item in plans if item.playbook_id == "isolate-host")
        pending = response.request_action(incident.incident_id, host_plan.playbook_id,
                                          analyst="analyst-a", reason="Review isolation outcome",
                                          target=host_plan.target_options[0])
        action = pending.response_actions[0]
        assert action.status == ResponseActionStatus.PENDING_AUTHORIZATION
        assert "awaiting explicit analyst authorization" in action.result.lower()

        with pytest.raises(ValueError, match="authorization"):
            response.authorize_and_execute(incident.incident_id, action.action_id,
                                           analyst="analyst-a", authorized=False,
                                           reason="Not approved")
        pending = response.incidents.get(incident.incident_id)
        assert pending.response_actions[0].status == ResponseActionStatus.PENDING_AUTHORIZATION
        assert pending.audit_trail[-1].action == "SIMULATED_RESPONSE_AUTHORIZATION_DENIED"

        completed = response.authorize_and_execute(
            incident.incident_id, action.action_id, analyst="analyst-b", authorized=True,
            reason="Approved for tabletop", outcome=SimulatedOutcome.SUCCESS,
        )
        action = completed.response_actions[0]
        assert action.status == ResponseActionStatus.SUCCEEDED
        assert action.simulation_only and action.authorized_by == "analyst-b"
        assert action.authorized_at and action.completed_at
        assert action.result_details["side_effects_performed"] is False
        audit = completed.audit_trail[-1]
        assert audit.details["incident_id"] == incident.incident_id
        assert audit.details["action_id"] == action.action_id
        assert audit.reason == "Approved for tabletop"
    finally:
        repository.close()


def test_failure_cancel_and_rollback_simulations_are_recorded(tmp_path):
    repository = SQLiteIncidentRepository(str(tmp_path / "response-lifecycle.sqlite3"))
    try:
        incident = seeded_incident(repository)
        response = IncidentResponseService(IncidentService(repository))
        playbook = next(item for item in response.available_playbooks(incident.incident_id)
                        if item.playbook_id == "collect-evidence")

        pending = response.request_action(incident.incident_id, playbook.playbook_id,
                                          analyst="soc", reason="Preserve event references")
        failed = response.authorize_and_execute(incident.incident_id, pending.response_actions[-1].action_id,
                                                 analyst="soc", authorized=True, reason="Failure fixture",
                                                 outcome=SimulatedOutcome.FAILURE)
        assert failed.response_actions[-1].status == ResponseActionStatus.FAILED
        assert failed.response_actions[-1].result_details["side_effects_performed"] is False

        pending = response.request_action(incident.incident_id, playbook.playbook_id,
                                         analyst="soc", reason="Cancel test")
        cancelled = response.cancel(incident.incident_id, pending.response_actions[-1].action_id,
                                    analyst="soc", reason="Analyst cancelled before authorization")
        assert cancelled.response_actions[-1].status == ResponseActionStatus.CANCELLED

        pending = response.request_action(incident.incident_id, playbook.playbook_id,
                                         analyst="soc", reason="Rollback test")
        success = response.authorize_and_execute(incident.incident_id, pending.response_actions[-1].action_id,
                                                 analyst="soc", authorized=True, reason="Authorized fixture")
        rolled_back = response.rollback(incident.incident_id, success.response_actions[-1].action_id,
                                        analyst="soc", reason="Tabletop rollback")
        assert rolled_back.response_actions[-1].status == ResponseActionStatus.ROLLED_BACK
        assert rolled_back.response_actions[-1].result_details["side_effects_performed"] is False
        assert {entry.action for entry in rolled_back.audit_trail if entry.action.startswith("SIMULATED_RESPONSE_")} >= {
            "SIMULATED_RESPONSE_REQUESTED", "SIMULATED_RESPONSE_AUTHORIZED",
            "SIMULATED_RESPONSE_CANCELLED", "SIMULATED_RESPONSE_ROLLED_BACK",
        }
        assert rolled_back.timeline[-1].details["simulation_only"] is True
    finally:
        repository.close()


def test_playbooks_only_offer_accounts_assets_and_plcs_in_incident_evidence(tmp_path):
    repository = SQLiteIncidentRepository(str(tmp_path / "response-targets.sqlite3"))
    try:
        incident = seeded_incident(repository, scenario="brute_force")
        response = IncidentResponseService(IncidentService(repository))
        plans = response.available_playbooks(incident.incident_id)
        account_plan = next(item for item in plans if item.playbook_id == "disable-account")
        assert account_plan.target_options
        assert all("unknown" not in item.lower() for item in account_plan.target_options)
        network_incident = seeded_incident(repository)
        network_plans = response.available_playbooks(network_incident.incident_id)
        plc_plan = next(item for item in network_plans if item.playbook_id == "block-plc-access")
        assert all(target.startswith("PLC-") for target in plc_plan.target_options)
        with pytest.raises(ValueError, match="Target"):
            response.request_action(network_incident.incident_id, "block-plc-access", analyst="soc",
                                   reason="Test validation", target="EXTERNAL-HOST")
    finally:
        repository.close()


def test_response_request_rejects_missing_analyst_or_reason(tmp_path):
    repository = SQLiteIncidentRepository(str(tmp_path / "response-validation.sqlite3"))
    try:
        incident = seeded_incident(repository)
        response = IncidentResponseService(IncidentService(repository))
        with pytest.raises(ValueError, match="Analyst and reason"):
            response.request_action(incident.incident_id, "collect-evidence", analyst="", reason="")
    finally:
        repository.close()
