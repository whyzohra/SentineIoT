"""Curated ATT&CK references used by the alert enrichment mapper."""

from detection_engine.models.alert import MITREDomain, MITRETactic, MITRETechniqueMapping


def _tactic(tactic_id: str, name: str) -> MITRETactic:
    return MITRETactic(
        tactic_id=tactic_id,
        name=name,
        url=f"https://attack.mitre.org/tactics/{tactic_id}/",
    )


MAPPINGS: dict[str, MITRETechniqueMapping] = {
    "network_recon": MITRETechniqueMapping(
        technique_id="T0846",
        name="Remote System Discovery",
        domain=MITREDomain.ICS,
        url="https://attack.mitre.org/techniques/T0846/",
        tactics=[_tactic("TA0102", "Discovery")],
        mapping_basis=("The rule detects one source referencing multiple distinct OT assets in a short "
                       "window, consistent with ICS remote-system discovery."),
    ),
    "brute_force": MITRETechniqueMapping(
        technique_id="T1110",
        name="Brute Force",
        domain=MITREDomain.ENTERPRISE,
        url="https://attack.mitre.org/techniques/T1110/",
        tactics=[_tactic("TA0006", "Credential Access")],
        mapping_basis=("Repeated failed authentication for a common account and target supports generic "
                       "credential brute-force behavior; ATT&CK Enterprise is used because the evidence "
                       "does not identify an ICS-specific I/O brute-force action."),
    ),
    "unauthorized_plc_command": MITRETechniqueMapping(
        technique_id="T1692.001",
        name="Unauthorized Message: Command Message",
        domain=MITREDomain.ICS,
        url="https://attack.mitre.org/techniques/T1692/001/",
        tactics=[
            _tactic("TA0103", "Evasion"),
            _tactic("TA0106", "Impair Process Control"),
        ],
        mapping_basis=("The unauthorized PLC alert specifically records command intent (such as a simulated "
                       "setpoint write), matching the ICS command-message sub-technique."),
    ),
}

UNMAPPED_REASONS: dict[str, str] = {
    "DET-004-PLC-COMMAND-FREQUENCY": (
        "Command volume above baseline does not establish that commands were unauthorized or adversarial."
    ),
    "DET-005-INSIDER-BEHAVIOR-ANOMALY": (
        "Behavioral deviations alone do not establish a specific ATT&CK technique or valid-account misuse."
    ),
}

UNMAPPED_ACCESS_REASON = (
    "The PLC access evidence does not identify command-message behavior; no technique is assigned."
)
