"""Rule-independent enrichment of SecurityAlert instances with ATT&CK metadata."""

from collections.abc import Iterable

from detection_engine.mitre.catalog import MAPPINGS, UNMAPPED_ACCESS_REASON, UNMAPPED_REASONS
from detection_engine.models.alert import MITREMappingStatus, SecurityAlert


class MITREMapper:
    """Enrich alerts based on stable rule identifiers and the alert's evidence."""

    _plc_command_access_types = frozenset({
        "SIMULATED_SETPOINT_WRITE",
        "SETPOINT_WRITE",
        "SETPOINT_ADJUST",
        "WRITE_REGISTER",
        "SCADA_COMMAND",
    })

    def enrich(self, alert: SecurityAlert) -> SecurityAlert:
        """Return a copy enriched with a structured mapping or an explicit reason."""
        mapping_key = {
            "DET-001-NETWORK-RECON": "network_recon",
            "DET-002-AUTH-BRUTE-FORCE": "brute_force",
        }.get(alert.rule_id)

        if alert.rule_id == "DET-003-UNAUTHORIZED-PLC-ACCESS":
            access_type = str(alert.metadata.get("access_type", "")).upper()
            if access_type in self._plc_command_access_types:
                mapping_key = "unauthorized_plc_command"
            else:
                return alert.model_copy(update={
                    "mitre_mapping_status": MITREMappingStatus.UNMAPPED,
                    "mitre_mappings": [],
                    "mitre_unmapped_reason": UNMAPPED_ACCESS_REASON,
                })

        if mapping_key is not None:
            return alert.model_copy(update={
                "mitre_mapping_status": MITREMappingStatus.MAPPED,
                "mitre_mappings": [MAPPINGS[mapping_key]],
                "mitre_unmapped_reason": None,
            })

        reason = UNMAPPED_REASONS.get(
            alert.rule_id,
            "No ATT&CK mapping is configured for this detection rule.",
        )
        return alert.model_copy(update={
            "mitre_mapping_status": MITREMappingStatus.UNMAPPED,
            "mitre_mappings": [],
            "mitre_unmapped_reason": reason,
        })

    def enrich_many(self, alerts: Iterable[SecurityAlert]) -> list[SecurityAlert]:
        """Enrich an iterable of alerts without changing the originals."""
        return [self.enrich(alert) for alert in alerts]
