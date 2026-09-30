"""Read model combining the existing SentinelOT repositories and simulators."""

from collections import deque
import threading
from typing import Any

from incident_management import IncidentService, IncidentStatus, SQLiteIncidentRepository
from telemetry.assets import AssetRegistry
from telemetry.generator import NormalTelemetryGenerator


ACTIVE_STATES = {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class DashboardDataService:
    """Dashboard queries sourced from established models; no security rules are duplicated."""

    def __init__(self, repository: SQLiteIncidentRepository) -> None:
        self.repository = repository
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

    def events(self, *, limit: int = 100, search: str = "") -> list[dict[str, Any]]:
        self._generate_events(5)
        with self._event_lock:
            rows = list(self._events)
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
        query = search.casefold().strip()
        if severity:
            rows = [row for row in rows if row["alert"]["severity"] == severity.upper()]
        if query:
            rows = [row for row in rows if query in " ".join((
                row["alert"]["title"], row["alert"]["description"], row["alert"]["rule_id"],
                *(asset["asset_id"] for asset in row["alert"]["source_assets"]),
                *(asset["asset_id"] for asset in row["alert"]["target_assets"]),
            )).casefold()]
        return rows

    def incidents_list(self, *, search: str = "", status: str = "", severity: str = "") -> list[dict[str, Any]]:
        state = IncidentStatus(status.upper()) if status else None
        rows = self.repository.list(state)
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
        return [incident.model_dump(mode="json") for incident in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        incident = self.repository.get(incident_id)
        return incident.model_dump(mode="json") if incident else None

    def assets_list(self, *, search: str = "") -> list[dict[str, Any]]:
        rows = [asset.model_dump(mode="json") for asset in self.assets.list_assets()]
        query = search.casefold().strip()
        return [asset for asset in rows if not query or query in " ".join((
            asset["asset_id"], asset["hostname"], asset["asset_type"], asset["zone"], asset["manufacturer"],
        )).casefold()]

    def techniques(self) -> list[dict[str, Any]]:
        aggregate: dict[str, dict[str, Any]] = {}
        for row in self._alert_rows(self.repository.list()):
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
        active = [incident for incident in incidents if incident.status in ACTIVE_STATES]
        alerts = self._alert_rows(incidents)
        affected: dict[str, dict[str, Any]] = {}
        for incident in active:
            for record in incident.alert_records:
                for asset in (*record.alert.source_assets, *record.alert.target_assets):
                    asset_id = asset.asset_id
                    affected[asset_id] = {
                        "asset_id": asset_id, "hostname": asset.hostname,
                        "asset_type": asset.asset_type.value,
                    }
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
