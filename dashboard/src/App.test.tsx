import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const asset = {
  asset_id: 'PLC-001', hostname: 'plc01.water.ot.local', ip_address: '192.168.10.11',
  asset_type: 'PLC', manufacturer: 'Rockwell Automation', firmware_version: 'v32.011',
  criticality: 5, status: 'ONLINE', purdue_level: 1, zone: 'ZONE_PROCESS_INTAKE',
  protocols: ['MODBUS_TCP'], description: 'Primary intake controller', metadata: {},
}
const mapping = {
  technique_id: 'T0846', name: 'Remote System Discovery', domain: 'ICS',
  url: 'https://attack.mitre.org/techniques/T0846/', tactics: [{ tactic_id: 'TA0102', name: 'Discovery', url: '#' }],
  mapping_basis: 'Evidence references multiple OT assets.',
}
const alert = {
  alert_id: 'alert-1', detection_id: 'detect-1', rule_id: 'DET-001-NETWORK-RECON',
  timestamp: '2026-09-30T12:00:00Z', severity: 'HIGH', confidence: 0.9,
  title: 'OT network reconnaissance', description: 'Several OT assets were referenced.',
  source_assets: [{ asset_id: 'ENGINEERING-001', hostname: 'eng01', ip_address: '192.168.30.41', asset_type: 'ENGINEERING_WORKSTATION', purdue_level: 3 }],
  target_assets: [{ asset_id: 'PLC-001', hostname: asset.hostname, ip_address: asset.ip_address, asset_type: 'PLC', purdue_level: 1 }],
  evidence: { event_ids: ['event-1'], affected_assets: ['PLC-001'] }, metadata: {},
  mitre_mapping_status: 'MAPPED', mitre_mappings: [mapping], mitre_unmapped_reason: null,
}
const risk = { alert_id: 'alert-1', risk_score: 82, risk_level: 'CRITICAL', factors: {
  severity: { value: 66, weight: 0.3, contribution: 20, rationale: 'High severity contributes to risk.' },
}, formula: 'risk_score = weighted factors', explanation: 'CRITICAL risk (82.00/100) due to asset criticality.' }
const incident = {
  incident_id: 'incident-12345678', title: 'OT network reconnaissance', status: 'INVESTIGATING',
  created_at: '2026-09-30T12:00:00Z', updated_at: '2026-09-30T12:05:00Z', last_alert_timestamp: '2026-09-30T12:00:00Z',
  severity: 'HIGH', risk_score: 82, risk_level: 'CRITICAL', alert_records: [{ alert, risk_assessment: risk }],
  event_ids: ['event-1'], timeline: [{ entry_id: 'timeline-1', timestamp: '2026-09-30T12:00:00Z', kind: 'ALERT_OPENED', summary: 'Incident created from detection alert', actor: 'system', event_ids: ['event-1'], details: {} }],
  analyst_notes: [{ note_id: 'note-1', timestamp: '2026-09-30T12:04:00Z', actor: 'analyst', text: 'Review process access.' }],
  evidence_attachments: [], audit_trail: [{ audit_id: 'audit-1', timestamp: '2026-09-30T12:05:00Z', actor: 'analyst', action: 'STATUS_CHANGED', old_status: 'OPEN', new_status: 'INVESTIGATING', details: {} }],
}

function response(value: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(value) })
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const path = String(input)
    if (path.endsWith('/overview')) return response({
      incident_counts_by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0 }, active_incident_count: 1,
      total_incident_count: 1, recent_alerts: [], affected_assets: [], mitre_techniques: [], event_timeline: [],
    })
    if (path.includes('/api/events')) return response([])
    if (path.includes('/api/alerts')) return response([])
    if (path.includes('/api/incidents/incident-12345678')) return response(incident)
    if (path.includes('/api/incidents')) return response([incident])
    if (path.includes('/api/assets')) return response([asset])
    if (path.includes('/api/mitre')) return response([{ ...mapping, alert_count: 1, alert_ids: ['alert-1'], incident_ids: [incident.incident_id] }])
    return response({ error: 'offline' }, 503)
  }))
})

describe('SOC dashboard', () => {
  it('renders live overview values and navigates to the OT asset registry', async () => {
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'SOC Overview' })).toBeInTheDocument()
    expect(screen.getByText('ACTIVE INCIDENTS').parentElement?.parentElement).toHaveTextContent('01')
    fireEvent.click(screen.getByRole('button', { name: 'OT Assets' }))
    expect(await screen.findByText('PLC-001')).toBeInTheDocument()
    expect(screen.getByText('Primary intake controller')).toBeInTheDocument()
  })

  it('shows incident investigation evidence, mappings, risk, notes, and audit history', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'SOC Overview' })
    fireEvent.click(within(screen.getByRole('navigation')).getByRole('button', { name: /Incidents/ }))
    fireEvent.click(await screen.findByText('OT network reconnaissance'))
    expect(await screen.findByText('Incident Investigation')).toBeInTheDocument()
    expect(screen.getAllByText('82.0')).toHaveLength(2)
    expect(screen.getByText('event-1')).toBeInTheDocument()
    expect(screen.getAllByText('T0846')).toHaveLength(2)
    expect(screen.getByText('Review process access.')).toBeInTheDocument()
    expect(screen.getByText(/High severity contributes/)).toBeInTheDocument()
    expect(screen.getByText('STATUS CHANGED')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Analyst note' }), { target: { value: 'Check historian events' } })
    fireEvent.click(screen.getByRole('button', { name: /Add note/ }))
    expect(await screen.findByText('Investigation note added')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith(
      '/api/incidents/incident-12345678/notes',
      expect.objectContaining({ method: 'POST', body: JSON.stringify({ text: 'Check historian events', actor: 'soc analyst' }) }),
    )
  })

  it('presents an actionable loading error if the local API is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response({ error: 'connection refused' }, 503)))
    render(<App />)
    expect(await screen.findByText('Dashboard API unavailable')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('shows empty states when backend data has no incidents or alerts', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/overview')) return response({
        incident_counts_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, active_incident_count: 0,
        total_incident_count: 0, recent_alerts: [], affected_assets: [], mitre_techniques: [], event_timeline: [],
      })
      if (path.includes('/api/assets') || path.includes('/api/mitre') || path.includes('/api/incidents') || path.includes('/api/alerts') || path.includes('/api/events')) return response([])
      return response({})
    }))
    render(<App />)
    expect(await screen.findByText('No alerts yet')).toBeInTheDocument()
    expect(screen.getByText('No affected assets')).toBeInTheDocument()
    expect(screen.getByText('Event stream is clear')).toBeInTheDocument()
    expect(screen.getByText('No mapped techniques')).toBeInTheDocument()
  })
})
