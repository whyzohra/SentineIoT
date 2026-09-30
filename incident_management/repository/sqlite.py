"""SQLite persistence for incidents, evidence references, timeline, and audit history."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from detection_engine.models.alert import AlertSeverity, SecurityAlert
from incident_management.correlation.engine import IncidentCorrelationEngine
from incident_management.models import (
    AuditRecord, CorrelationConfig, EvidenceAttachment, Incident,
    IncidentAlertRecord, IncidentNote, IncidentStatus, TimelineEntry,
)
from risk_engine.models.assessment import RiskAssessment, RiskLevel


_SEVERITY_RANK = {level: index for index, level in enumerate(AlertSeverity)}
_RISK_RANK = {level: index for index, level in enumerate(RiskLevel)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _event_ids(alert: SecurityAlert) -> list[str]:
    value = alert.evidence.get("event_ids", [])
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({str(event_id) for event_id in value if event_id is not None and str(event_id)})


def _validate_attachment_metadata(metadata: dict[str, Any]) -> None:
    if not isinstance(metadata, dict):
        raise ValueError("Evidence attachment metadata must be a JSON object")
    forbidden = {"content", "data", "bytes", "blob", "file_content", "payload"}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).casefold() in forbidden:
                    raise ValueError(f"Evidence attachment metadata cannot contain file payload field: {key}")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(metadata)
    try:
        json.dumps(metadata, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("Evidence attachment metadata must contain JSON-compatible values") from error


class SQLiteIncidentRepository:
    """Repository backed only by Python's standard-library SQLite driver."""

    def __init__(self, database: str | Path = ".sentinelot-incidents.sqlite3") -> None:
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.database, timeout=10, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 10000")
        self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteIncidentRepository":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    last_alert_timestamp TEXT NOT NULL, severity TEXT NOT NULL,
                    risk_score REAL NOT NULL, risk_level TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    alert_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    alert_json TEXT NOT NULL, risk_json TEXT NOT NULL, timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_incident_alerts_incident ON incident_alerts(incident_id);
                CREATE TABLE IF NOT EXISTS incident_timeline (
                    entry_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    timestamp TEXT NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL,
                    actor TEXT NOT NULL, alert_id TEXT, event_ids_json TEXT NOT NULL, details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_incident_timeline_order ON incident_timeline(incident_id, timestamp, entry_id);
                CREATE TABLE IF NOT EXISTS incident_notes (
                    note_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    timestamp TEXT NOT NULL, actor TEXT NOT NULL, text TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_attachments (
                    attachment_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    timestamp TEXT NOT NULL, actor TEXT NOT NULL, label TEXT NOT NULL, metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_audit (
                    audit_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                    old_status TEXT, new_status TEXT, reason TEXT, details_json TEXT NOT NULL
                );
            """)

    def _transaction(self):
        return self._connection

    def ingest_alert(
        self,
        alert: SecurityAlert,
        assessment: RiskAssessment,
        correlator: IncidentCorrelationEngine,
        config: CorrelationConfig,
    ) -> tuple[Incident, bool]:
        if alert.alert_id != assessment.alert_id:
            raise ValueError("RiskAssessment.alert_id must match SecurityAlert.alert_id")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT incident_id FROM incident_alerts WHERE alert_id = ?", (alert.alert_id,)
                ).fetchone()
                if existing:
                    incident = self._get_locked(existing["incident_id"])
                    self._connection.commit()
                    return incident, True

                candidates = [
                    incident for incident in self._list_locked()
                    if incident.status in {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}
                ]
                match = correlator.best_match(alert, candidates, config)
                now = _now()
                if match:
                    incident = self._get_locked(match.incident_id)
                    record = IncidentAlertRecord(alert=alert, risk_assessment=assessment)
                    incident.alert_records.append(record)
                    incident.event_ids = sorted(set(incident.event_ids) | set(_event_ids(alert)))
                    incident.last_alert_timestamp = max(incident.last_alert_timestamp, alert.timestamp)
                    incident.updated_at = now
                    if _SEVERITY_RANK[alert.severity] > _SEVERITY_RANK[incident.severity]:
                        incident.severity = alert.severity
                    if assessment.risk_score > incident.risk_score:
                        incident.risk_score = assessment.risk_score
                    if _RISK_RANK[assessment.risk_level] > _RISK_RANK[incident.risk_level]:
                        incident.risk_level = assessment.risk_level
                    self._connection.execute(
                        "UPDATE incidents SET updated_at=?,last_alert_timestamp=?,severity=?,risk_score=?,risk_level=? WHERE incident_id=?",
                        (now.isoformat(), incident.last_alert_timestamp.isoformat(), incident.severity.value,
                         incident.risk_score, incident.risk_level.value, incident.incident_id),
                    )
                    self._insert_alert(incident.incident_id, alert, assessment)
                    self._timeline(incident.incident_id, TimelineEntry(
                        timestamp=alert.timestamp, kind="ALERT_CORRELATED",
                        summary=f"Alert correlated via {', '.join(match.signals)}",
                        alert_id=alert.alert_id, event_ids=_event_ids(alert),
                        details={"signals": list(match.signals), "risk_score": assessment.risk_score},
                    ))
                    self._audit(incident.incident_id, AuditRecord(
                        timestamp=now, actor="system", action="ALERT_CORRELATED",
                        details={"alert_id": alert.alert_id, "signals": list(match.signals)},
                    ))
                    result_id = incident.incident_id
                else:
                    incident = Incident(
                        title=alert.title, created_at=now, updated_at=now,
                        last_alert_timestamp=alert.timestamp, severity=alert.severity,
                        risk_score=assessment.risk_score, risk_level=assessment.risk_level,
                        alert_records=[IncidentAlertRecord(alert=alert, risk_assessment=assessment)],
                        event_ids=_event_ids(alert),
                    )
                    self._connection.execute(
                        "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
                        (incident.incident_id, incident.title, incident.status.value, now.isoformat(),
                         now.isoformat(), alert.timestamp.isoformat(), alert.severity.value,
                         assessment.risk_score, assessment.risk_level.value),
                    )
                    self._insert_alert(incident.incident_id, alert, assessment)
                    self._timeline(incident.incident_id, TimelineEntry(
                        timestamp=alert.timestamp, kind="ALERT_OPENED", summary="Incident created from detection alert",
                        alert_id=alert.alert_id, event_ids=_event_ids(alert),
                        details={"risk_score": assessment.risk_score, "risk_explanation": assessment.explanation},
                    ))
                    self._audit(incident.incident_id, AuditRecord(
                        timestamp=now, actor="system", action="INCIDENT_CREATED",
                        details={"alert_id": alert.alert_id},
                    ))
                    result_id = incident.incident_id
                self._connection.commit()
                return self._get_locked(result_id), False
            except Exception:
                self._connection.rollback()
                raise

    def get(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._get_locked(incident_id)

    def list(self, status: IncidentStatus | None = None) -> list[Incident]:
        with self._lock:
            return self._list_locked(status)

    def _list_locked(self, status: IncidentStatus | None = None) -> list[Incident]:
        if status:
            rows = self._connection.execute(
                "SELECT incident_id FROM incidents WHERE status=? ORDER BY updated_at DESC,incident_id",
                (status.value,),
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT incident_id FROM incidents ORDER BY updated_at DESC,incident_id"
            ).fetchall()
        return [incident for row in rows if (incident := self._get_locked(row["incident_id"]))]

    def _get_locked(self, incident_id: str) -> Incident | None:
        row = self._connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not row:
            return None
        alert_rows = self._connection.execute(
            "SELECT alert_json,risk_json FROM incident_alerts WHERE incident_id=? ORDER BY timestamp,alert_id",
            (incident_id,),
        ).fetchall()
        timeline_rows = self._connection.execute(
            "SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY timestamp,entry_id", (incident_id,)
        ).fetchall()
        note_rows = self._connection.execute(
            "SELECT * FROM incident_notes WHERE incident_id=? ORDER BY timestamp,note_id", (incident_id,)
        ).fetchall()
        attachment_rows = self._connection.execute(
            "SELECT * FROM incident_attachments WHERE incident_id=? ORDER BY timestamp,attachment_id", (incident_id,)
        ).fetchall()
        audit_rows = self._connection.execute(
            "SELECT * FROM incident_audit WHERE incident_id=? ORDER BY timestamp,audit_id", (incident_id,)
        ).fetchall()
        records = [IncidentAlertRecord(
            alert=SecurityAlert.model_validate_json(item["alert_json"]),
            risk_assessment=RiskAssessment.model_validate_json(item["risk_json"]),
        ) for item in alert_rows]
        return Incident(
            incident_id=row["incident_id"], title=row["title"], status=IncidentStatus(row["status"]),
            created_at=_dt(row["created_at"]), updated_at=_dt(row["updated_at"]),
            last_alert_timestamp=_dt(row["last_alert_timestamp"]), severity=AlertSeverity(row["severity"]),
            risk_score=row["risk_score"], risk_level=RiskLevel(row["risk_level"]), alert_records=records,
            event_ids=sorted({event_id for record in records for event_id in record.alert.evidence.get("event_ids", [])}),
            timeline=[TimelineEntry(
                entry_id=item["entry_id"], timestamp=_dt(item["timestamp"]), kind=item["kind"],
                summary=item["summary"], actor=item["actor"], alert_id=item["alert_id"],
                event_ids=json.loads(item["event_ids_json"]), details=json.loads(item["details_json"]),
            ) for item in timeline_rows],
            analyst_notes=[IncidentNote(
                note_id=item["note_id"], timestamp=_dt(item["timestamp"]), actor=item["actor"], text=item["text"]
            ) for item in note_rows],
            evidence_attachments=[EvidenceAttachment(
                attachment_id=item["attachment_id"], timestamp=_dt(item["timestamp"]),
                actor=item["actor"], label=item["label"], metadata=json.loads(item["metadata_json"]),
            ) for item in attachment_rows],
            audit_trail=[AuditRecord(
                audit_id=item["audit_id"], timestamp=_dt(item["timestamp"]), actor=item["actor"],
                action=item["action"], old_status=IncidentStatus(item["old_status"]) if item["old_status"] else None,
                new_status=IncidentStatus(item["new_status"]) if item["new_status"] else None,
                reason=item["reason"], details=json.loads(item["details_json"]),
            ) for item in audit_rows],
        )

    def transition(
        self, incident_id: str, status: IncidentStatus, *, actor: str, reason: str | None
    ) -> Incident:
        with self._lock, self._connection:
            incident = self._require(incident_id)
            if status == incident.status:
                raise ValueError(f"Incident is already {status.value}")
            now = _now()
            self._connection.execute("UPDATE incidents SET status=?,updated_at=? WHERE incident_id=?",
                                     (status.value, now.isoformat(), incident_id))
            self._timeline(incident_id, TimelineEntry(
                timestamp=now, kind="STATUS_CHANGED", summary=f"Status changed to {status.value}",
                actor=actor, details={"old_status": incident.status.value, "new_status": status.value, "reason": reason},
            ))
            self._audit(incident_id, AuditRecord(
                timestamp=now, actor=actor, action="STATUS_CHANGED", old_status=incident.status,
                new_status=status, reason=reason,
            ))
            return self._require(incident_id)

    def add_note(self, incident_id: str, text: str, *, actor: str) -> Incident:
        text = text.strip()
        if not text:
            raise ValueError("Analyst note cannot be empty")
        with self._lock, self._connection:
            self._require(incident_id)
            now = _now()
            note = IncidentNote(timestamp=now, actor=actor, text=text)
            self._connection.execute("INSERT INTO incident_notes VALUES (?,?,?,?,?)",
                                     (note.note_id, incident_id, now.isoformat(), actor, text))
            self._timeline(incident_id, TimelineEntry(
                timestamp=now, kind="ANALYST_NOTE", summary=text, actor=actor,
            ))
            self._audit(incident_id, AuditRecord(timestamp=now, actor=actor, action="NOTE_ADDED"))
            self._connection.execute("UPDATE incidents SET updated_at=? WHERE incident_id=?", (now.isoformat(), incident_id))
            return self._require(incident_id)

    def attach_evidence(
        self, incident_id: str, label: str, metadata: dict[str, Any], *, actor: str
    ) -> Incident:
        label = label.strip()
        if not label:
            raise ValueError("Evidence label cannot be empty")
        _validate_attachment_metadata(metadata)
        with self._lock, self._connection:
            self._require(incident_id)
            now = _now()
            attachment = EvidenceAttachment(timestamp=now, actor=actor, label=label, metadata=metadata)
            self._connection.execute("INSERT INTO incident_attachments VALUES (?,?,?,?,?,?)",
                                     (attachment.attachment_id, incident_id, now.isoformat(), actor,
                                      label, _json(metadata)))
            self._timeline(incident_id, TimelineEntry(
                timestamp=now, kind="EVIDENCE_ATTACHED", summary=f"Evidence metadata attached: {label}",
                actor=actor, details={"attachment_id": attachment.attachment_id, "metadata": metadata},
            ))
            self._audit(incident_id, AuditRecord(
                timestamp=now, actor=actor, action="EVIDENCE_ATTACHED",
                details={"attachment_id": attachment.attachment_id, "label": label},
            ))
            self._connection.execute("UPDATE incidents SET updated_at=? WHERE incident_id=?", (now.isoformat(), incident_id))
            return self._require(incident_id)

    def investigate(self, incident_id: str, note_text: str, *, actor: str) -> Incident:
        note_text = note_text.strip()
        if not note_text:
            raise ValueError("Investigation note cannot be empty")
        with self._lock, self._connection:
            incident = self._require(incident_id)
            now = _now()
            target = incident.status
            if incident.status != IncidentStatus.INVESTIGATING:
                if incident.status not in {IncidentStatus.OPEN, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED}:
                    raise ValueError(f"Cannot investigate an incident in {incident.status.value} state")
                target = IncidentStatus.INVESTIGATING
                self._connection.execute("UPDATE incidents SET status=? WHERE incident_id=?",
                                         (target.value, incident_id))
                self._timeline(incident_id, TimelineEntry(
                    timestamp=now, kind="STATUS_CHANGED", summary="Status changed to INVESTIGATING",
                    actor=actor, details={"old_status": incident.status.value, "new_status": target.value},
                ))
                self._audit(incident_id, AuditRecord(
                    timestamp=now, actor=actor, action="STATUS_CHANGED", old_status=incident.status,
                    new_status=target, reason="Investigation started",
                ))
            note = IncidentNote(timestamp=now, actor=actor, text=note_text)
            self._connection.execute("INSERT INTO incident_notes VALUES (?,?,?,?,?)",
                                     (note.note_id, incident_id, now.isoformat(), actor, note_text))
            self._timeline(incident_id, TimelineEntry(
                timestamp=now, kind="ANALYST_NOTE", summary=note_text, actor=actor,
            ))
            self._audit(incident_id, AuditRecord(timestamp=now, actor=actor, action="NOTE_ADDED"))
            self._connection.execute("UPDATE incidents SET updated_at=? WHERE incident_id=?", (now.isoformat(), incident_id))
            return self._require(incident_id)

    def _require(self, incident_id: str) -> Incident:
        incident = self._get_locked(incident_id)
        if incident is None:
            raise KeyError(f"Incident not found: {incident_id}")
        return incident

    def _insert_alert(self, incident_id: str, alert: SecurityAlert, assessment: RiskAssessment) -> None:
        self._connection.execute("INSERT INTO incident_alerts VALUES (?,?,?,?,?)",
                                 (alert.alert_id, incident_id, alert.model_dump_json(),
                                  assessment.model_dump_json(), alert.timestamp.isoformat()))

    def _timeline(self, incident_id: str, entry: TimelineEntry) -> None:
        self._connection.execute("INSERT INTO incident_timeline VALUES (?,?,?,?,?,?,?,?,?)",
                                 (entry.entry_id, incident_id, entry.timestamp.isoformat(), entry.kind,
                                  entry.summary, entry.actor, entry.alert_id, _json(entry.event_ids), _json(entry.details)))

    def _audit(self, incident_id: str, entry: AuditRecord) -> None:
        self._connection.execute("INSERT INTO incident_audit VALUES (?,?,?,?,?,?,?,?,?)",
                                 (entry.audit_id, incident_id, entry.timestamp.isoformat(), entry.actor,
                                  entry.action, entry.old_status.value if entry.old_status else None,
                                  entry.new_status.value if entry.new_status else None, entry.reason,
                                  _json(entry.details)))
