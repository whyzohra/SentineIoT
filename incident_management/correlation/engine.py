"""Pure correlation logic for grouping alerts into active incidents."""

from dataclasses import dataclass
from datetime import datetime

from detection_engine.models.alert import SecurityAlert
from incident_management.models.config import CorrelationConfig
from incident_management.models.incident import Incident


@dataclass(frozen=True)
class CorrelationMatch:
    incident_id: str
    signals: tuple[str, ...]
    seconds_apart: float


def _accounts(alert: SecurityAlert) -> set[str]:
    result: set[str] = set()
    for container in (alert.metadata, alert.evidence):
        for key in ("account", "user", "user_alias", "username", "engineer"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                result.add(value.strip().casefold())
        values = container.get("accounts")
        if isinstance(values, list):
            result.update(str(value).strip().casefold() for value in values if str(value).strip())
    return result


def _assets(alert: SecurityAlert) -> set[str]:
    return {asset.asset_id for asset in (*alert.source_assets, *alert.target_assets)}


def _techniques(alert: SecurityAlert) -> set[str]:
    return {mapping.technique_id for mapping in alert.mitre_mappings}


class IncidentCorrelationEngine:
    """Match a new alert against incidents using time, assets, accounts, and techniques."""

    def match(
        self, alert: SecurityAlert, incident: Incident, config: CorrelationConfig
    ) -> CorrelationMatch | None:
        delta = abs((alert.timestamp - incident.last_alert_timestamp).total_seconds())
        if delta > config.time_window_seconds:
            return None
        signals: list[str] = []
        shared_assets = _assets(alert) & {
            asset.asset_id
            for record in incident.alert_records
            for asset in (*record.alert.source_assets, *record.alert.target_assets)
        }
        if len(shared_assets) >= config.minimum_shared_assets:
            signals.append("shared_asset")
        if config.correlate_shared_accounts and _accounts(alert) & {
            account
            for record in incident.alert_records
            for account in _accounts(record.alert)
        }:
            signals.append("shared_account")
        if config.correlate_shared_techniques and _techniques(alert) & {
            technique
            for record in incident.alert_records
            for technique in _techniques(record.alert)
        }:
            signals.append("shared_technique")
        if not signals:
            return None
        return CorrelationMatch(incident.incident_id, tuple(signals), delta)

    def best_match(
        self, alert: SecurityAlert, incidents: list[Incident], config: CorrelationConfig
    ) -> CorrelationMatch | None:
        matches = [match for incident in incidents if (
            match := self.match(alert, incident, config)
        ) is not None]
        if not matches:
            return None
        return sorted(matches, key=lambda match: (-len(match.signals), match.seconds_apart, match.incident_id))[0]
