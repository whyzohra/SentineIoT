export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE'

export interface AssetSummary {
  asset_id: string
  hostname: string
  ip_address: string
  asset_type: string
  purdue_level: number
}

export interface Asset extends AssetSummary {
  manufacturer: string
  firmware_version: string
  criticality: number
  status: string
  zone: string
  protocols: string[]
  description?: string | null
  metadata: Record<string, unknown>
}

export interface Tactic { tactic_id: string; name: string; url: string }
export interface MitreMapping {
  technique_id: string
  name: string
  domain: 'ICS' | 'ENTERPRISE'
  url: string
  tactics: Tactic[]
  mapping_basis: string
}

export interface SecurityAlert {
  alert_id: string
  detection_id: string
  rule_id: string
  timestamp: string
  severity: Severity
  confidence: number
  title: string
  description: string
  source_assets: AssetSummary[]
  target_assets: AssetSummary[]
  evidence: Record<string, unknown>
  metadata: Record<string, unknown>
  mitre_mapping_status: string
  mitre_mappings: MitreMapping[]
  mitre_unmapped_reason?: string | null
}

export interface RiskFactor { value: number; weight: number; contribution: number; rationale: string }
export interface RiskAssessment {
  alert_id: string
  risk_score: number
  risk_level: Severity
  factors: Record<string, RiskFactor>
  formula: string
  explanation: string
}

export interface AlertRecord {
  alert: SecurityAlert
  risk_assessment: RiskAssessment
  incident_id: string
  incident_status: IncidentStatus
}

export interface TimelineEntry {
  entry_id: string
  timestamp: string
  kind: string
  summary: string
  actor: string
  alert_id?: string | null
  event_ids: string[]
  details: Record<string, unknown>
}
export interface IncidentNote { note_id: string; timestamp: string; actor: string; text: string }
export interface AuditRecord {
  audit_id: string
  timestamp: string
  actor: string
  action: string
  old_status?: IncidentStatus | null
  new_status?: IncidentStatus | null
  reason?: string | null
  details: Record<string, unknown>
}
export interface Incident {
  incident_id: string
  title: string
  status: IncidentStatus
  created_at: string
  updated_at: string
  last_alert_timestamp: string
  severity: Severity
  risk_score: number
  risk_level: Severity
  alert_records: Array<{ alert: SecurityAlert; risk_assessment: RiskAssessment }>
  event_ids: string[]
  timeline: TimelineEntry[]
  analyst_notes: IncidentNote[]
  evidence_attachments: Array<{ attachment_id: string; timestamp: string; actor: string; label: string; metadata: Record<string, unknown> }>
  audit_trail: AuditRecord[]
  response_actions: ResponseAction[]
}

export type ResponseActionStatus = 'PENDING_AUTHORIZATION' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED' | 'ROLLED_BACK'
export interface ResponseAction {
  action_id: string
  incident_id: string
  playbook_id: string
  action_type: string
  target?: string | null
  status: ResponseActionStatus
  simulation_only: boolean
  created_at: string
  updated_at: string
  authorized_at?: string | null
  completed_at?: string | null
  analyst: string
  authorized_by?: string | null
  reason: string
  authorization_reason?: string | null
  simulation_outcome?: 'SUCCESS' | 'FAILURE' | null
  result: string
  result_details: Record<string, unknown>
}
export interface ResponsePlaybook {
  playbook_id: string
  title: string
  description: string
  action_type: string
  target_options: string[]
  safety_boundary: string
}

export interface TelemetryEvent {
  event_id: string
  timestamp: string
  source_asset: AssetSummary
  destination_asset: AssetSummary | null
  event_type: string
  severity: string
  message: string
  metadata: Record<string, unknown>
}

export interface Overview {
  incident_counts_by_severity: Record<Severity, number>
  active_incident_count: number
  total_incident_count: number
  recent_alerts: AlertRecord[]
  affected_assets: Array<{ asset_id: string; hostname: string; asset_type: string }>
  mitre_techniques: Array<MitreMapping & { alert_count: number; alert_ids: string[]; incident_ids: string[] }>
  event_timeline: TelemetryEvent[]
}
