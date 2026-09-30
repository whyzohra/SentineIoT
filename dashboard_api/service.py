"""Read model combining the existing SentinelOT repositories and simulators."""

from collections import deque
from datetime import datetime, timezone
import threading
from typing import Any

from incident_management import IncidentService, IncidentStatus, SQLiteIncidentRepository
from incident_management.models import AuditRecord, Incident, IncidentNote, IncidentStatus, TimelineEntry
from incident_management.service import ALLOWED_TRANSITIONS
from telemetry.assets import AssetRegistry
from telemetry.generator import NormalTelemetryGenerator
from fortigate.pipeline import process_logs
from pathlib import Path


ACTIVE_STATES = {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class DashboardDataService:
    """Dashboard queries sourced from established models; no security rules are duplicated."""

    def __init__(self, repository: SQLiteIncidentRepository, aws_table=None) -> None:
        self.repository = repository
        self.aws_table = aws_table
        self.incidents = IncidentService(repository)
        self.assets = AssetRegistry()
        self.telemetry = NormalTelemetryGenerator(self.assets, seed=2026)
        self._events: deque[dict[str, Any]] = deque(maxlen=200)
        self._event_lock = threading.Lock()
        self._generate_events(40)

    @staticmethod
    def _alert_rows(incidents) -> list[dict[str, Any]]:
        rows = []
        for incident in incidents:
            for record in incident.alert_records:
                rows.append({
                    "alert": record.alert.model_dump(mode="json"),
                    "risk_assessment": record.risk_assessment.model_dump(mode="json"),
                    "incident_id": incident.incident_id,
                    "incident_status": incident.status.value,
                })
        return sorted(rows, key=lambda row: row["alert"]["timestamp"], reverse=True)

    def _generate_events(self, count: int) -> None:
        with self._event_lock:
            self._events.extend(event.to_dict() for event in self.telemetry.events(count))

    def _cloud_records(self, record_type: str) -> list[dict[str, Any]]:
        if self.aws_table is None:
            return []
        from boto3.dynamodb.conditions import Key
        results = []
        request = {"KeyConditionExpression": Key("PK").eq(record_type)}
        while True:
            response = self.aws_table.query(**request)
            results.extend(response.get("Items", []))
            cursor = response.get("LastEvaluatedKey")
            if not cursor:
                return results
            request["ExclusiveStartKey"] = cursor

    def ingest_fortigate_demo(self) -> dict[str, Any]:
        fixture = Path(__file__).parents[1] / "fortigate" / "fixtures" / "demo.jsonl"
        result = process_logs(fixture.read_text(encoding="utf-8").splitlines(), incident_service=self.incidents)
        with self._event_lock:
            self._events.extend(event.to_dict() for event in result["events"])
        return {"events": [event.model_dump(mode="json") for event in result["events"]],
                "alerts": [alert.model_dump(mode="json") for alert in result["alerts"]],
                "incident_ids": [incident.incident_id for incident in result["incidents"]]}

    def events(self, *, limit: int = 100, search: str = "") -> list[dict[str, Any]]:
        self._generate_events(5)
        with self._event_lock:
            rows = list(self._events)
        rows.extend(item["record"] for item in self._cloud_records("EVENT") if item.get("record"))
        if search:
            query = search.casefold()
            rows = [row for row in rows if query in " ".join((
                row["event_id"], row["source_asset"]["asset_id"], row["event_type"],
                row["message"],
                row["destination_asset"]["asset_id"] if row["destination_asset"] else "",
            )).casefold()]
        return list(reversed(rows[-limit:]))

    def alerts(self, *, search: str = "", severity: str = "") -> list[dict[str, Any]]:
        rows = self._alert_rows(self.repository.list())
        rows.extend({"alert": item["record"], "risk_assessment": item["risk_assessment"],
                     "incident_id": item["incident_id"], "incident_status": item.get("incident_status", "OPEN")}
                    for item in self._cloud_records("ALERT")
                    if item.get("record") and item.get("risk_assessment") and item.get("incident_id"))
        query = search.casefold().strip()
        if severity:
            rows = [row for row in rows if row["alert"]["severity"] == severity.upper()]
        if query:
            rows = [row for row in rows if query in " ".join((
                row["alert"]["title"], row["alert"]["description"], row["alert"]["rule_id"],
                *(asset["asset_id"] for asset in row["alert"]["source_assets"]),
                *(asset["asset_id"] for asset in row["alert"]["target_assets"]),
            )).casefold()]
        return sorted(rows, key=lambda row: row["alert"]["timestamp"], reverse=True)

    def incidents_list(self, *, search: str = "", status: str = "", severity: str = "") -> list[dict[str, Any]]:
        state = IncidentStatus(status.upper()) if status else None
        rows = self.repository.list(state)
        rows.extend(Incident.model_validate(item["record"]) for item in self._cloud_records("INCIDENT")
                    if item.get("record") and (state is None or item["record"].get("status") == state.value))
        query = search.casefold().strip()
        if severity:
            rows = [incident for incident in rows if incident.severity.value == severity.upper()]
        if query:
            rows = [incident for incident in rows if query in " ".join((
                incident.incident_id, incident.title, incident.status.value,
                *(record.alert.rule_id for record in incident.alert_records),
                *incident.event_ids,
                *(asset.asset_id for record in incident.alert_records
                  for asset in (*record.alert.source_assets, *record.alert.target_assets)),
            )).casefold()]
        return [incident.model_dump(mode="json") if hasattr(incident, "model_dump") else incident for incident in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        incident = self.repository.get(incident_id)
        if incident is None:
            incident = self._cloud_incident(incident_id)
        return incident.model_dump(mode="json") if incident else None

    def update_incident_status(self, incident_id: str, status: IncidentStatus, *, actor: str, reason: str | None):
        if self.repository.get(incident_id) is not None:
            return self.incidents.update_status(incident_id, status, actor=actor, reason=reason)
        current = self._cloud_incident(incident_id)
        if current is None:
            raise KeyError(f"Incident not found: {incident_id}")
        if status not in ALLOWED_TRANSITIONS[current.status]:
            allowed = ", ".join(sorted(item.value for item in ALLOWED_TRANSITIONS[current.status])) or "none"
            raise ValueError(f"Transition {current.status.value} -> {status.value} is not allowed (allowed: {allowed})")
        now = datetime.now(timezone.utc)
        updated = current.model_copy(update={
            "status": status, "updated_at": now,
            "timeline": [*current.timeline, TimelineEntry(
                timestamp=now, kind="STATUS_CHANGED", summary=f"Status changed to {status.value}",
                actor=actor, details={"reason": reason} if reason else {})],
            "audit_trail": [*current.audit_trail, AuditRecord(
                timestamp=now, actor=actor, action="STATUS_TRANSITION", old_status=current.status,
                new_status=status, reason=reason)],
        })
        self._save_cloud_incident(updated)
        for record in updated.alert_records:
            self.aws_table.update_item(
                Key={"PK": "ALERT", "SK": record.alert.alert_id},
                UpdateExpression="SET incident_status = :status",
                ExpressionAttributeValues={":status": status.value},
            )
        return updated

    def add_incident_note(self, incident_id: str, note: str, *, actor: str):
        if self.repository.get(incident_id) is not None:
            return self.incidents.add_note(incident_id, note, actor=actor)
        current = self._cloud_incident(incident_id)
        if current is None:
            raise KeyError(f"Incident not found: {incident_id}")
        if not note.strip():
            raise ValueError("Analyst note cannot be empty")
        now = datetime.now(timezone.utc)
        updated = current.model_copy(update={
            "updated_at": now,
            "analyst_notes": [*current.analyst_notes, IncidentNote(timestamp=now, actor=actor, text=note.strip())],
            "timeline": [*current.timeline, TimelineEntry(timestamp=now, kind="ANALYST_NOTE_ADDED",
                                                          summary="Analyst note added", actor=actor)],
            "audit_trail": [*current.audit_trail, AuditRecord(timestamp=now, actor=actor,
                                                                action="ANALYST_NOTE_ADDED")],
        })
        self._save_cloud_incident(updated)
        return updated

    def _cloud_incident(self, incident_id: str) -> Incident | None:
        if self.aws_table is None:
            return None
        record = self.aws_table.get_item(Key={"PK": "INCIDENT", "SK": incident_id}).get("Item")
        return Incident.model_validate(record["record"]) if record and record.get("record") else None

    def _save_cloud_incident(self, incident: Incident) -> None:
        self.aws_table.put_item(Item={"PK": "INCIDENT", "SK": incident.incident_id,
                                      "record": incident.model_dump(mode="json")})

    def assets_list(self, *, search: str = "") -> list[dict[str, Any]]:
        rows = [asset.model_dump(mode="json") for asset in self.assets.list_assets()]
        query = search.casefold().strip()
        return [asset for asset in rows if not query or query in " ".join((
            asset["asset_id"], asset["hostname"], asset["asset_type"], asset["zone"], asset["manufacturer"],
        )).casefold()]

    def techniques(self) -> list[dict[str, Any]]:
        aggregate: dict[str, dict[str, Any]] = {}
        rows = self._alert_rows(self.repository.list())
        rows.extend({"alert": item["record"], "incident_id": item["incident_id"]}
                    for item in self._cloud_records("ALERT") if item.get("record"))
        for row in rows:
            for technique in row["alert"]["mitre_mappings"]:
                item = aggregate.setdefault(technique["technique_id"], {
                    **technique, "alert_count": 0, "alert_ids": [], "incident_ids": [],
                })
                item["alert_count"] += 1
                item["alert_ids"].append(row["alert"]["alert_id"])
                if row["incident_id"] not in item["incident_ids"]:
                    item["incident_ids"].append(row["incident_id"])
        return sorted(aggregate.values(), key=lambda item: (item["domain"], item["technique_id"]))

    def overview(self) -> dict[str, Any]:
        incidents = self.repository.list()
        incidents.extend(Incident.model_validate(item["record"]) for item in self._cloud_records("INCIDENT")
                         if item.get("record"))
        active = [incident for incident in incidents if incident.status in ACTIVE_STATES]
        alerts = self._alert_rows(incidents)
        alerts.extend({"alert": item["record"], "risk_assessment": item["risk_assessment"],
                       "incident_id": item["incident_id"], "incident_status": item.get("incident_status", "OPEN")}
                      for item in self._cloud_records("ALERT")
                      if item.get("record") and item.get("risk_assessment") and item.get("incident_id"))
        affected: dict[str, dict[str, Any]] = {}
        for incident in active:
            for record in incident.alert_records:
                for asset in (*record.alert.source_assets, *record.alert.target_assets):
                    asset_id = asset.asset_id
                    affected[asset_id] = {
                        "asset_id": asset_id, "hostname": asset.hostname,
                        "asset_type": asset.asset_type.value,
                    }
        alerts.sort(key=lambda row: row["alert"]["timestamp"], reverse=True)
        return {
            "incident_counts_by_severity": {
                severity: sum(incident.severity.value == severity for incident in incidents)
                for severity in SEVERITY_LEVELS
            },
            "active_incident_count": len(active),
            "total_incident_count": len(incidents),
            "recent_alerts": alerts[:8],
            "affected_assets": sorted(affected.values(), key=lambda item: item["asset_id"]),
            "mitre_techniques": self.techniques(),
            "event_timeline": self.events(limit=20),
        }
