import type { AlertRecord, Asset, Incident, IncidentStatus, MitreMapping, Overview, ResponsePlaybook, TelemetryEvent } from './types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.error ?? `Request failed (${response.status})`)
  return body as T
}

const query = (values: Record<string, string>) => {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => { if (value) params.set(key, value) })
  return params.size ? `?${params.toString()}` : ''
}

export const api = {
  overview: () => request<Overview>('/overview'),
  events: (search = '') => request<TelemetryEvent[]>(`/events${query({ search, limit: '100' })}`),
  alerts: (search = '', severity = '') => request<AlertRecord[]>(`/alerts${query({ search, severity })}`),
  incidents: (search = '', status = '', severity = '') => request<Incident[]>(`/incidents${query({ search, status, severity })}`),
  incident: (id: string) => request<Incident>(`/incidents/${encodeURIComponent(id)}`),
  assets: (search = '') => request<Asset[]>(`/assets${query({ search })}`),
  techniques: () => request<Array<MitreMapping & { alert_count: number; alert_ids: string[]; incident_ids: string[] }>>('/mitre'),
  fortigateDemo: () => request<{ events: TelemetryEvent[]; alerts: AlertRecord[]; incident_ids: string[] }>('/fortigate/demo', { method: 'POST', body: '{}' }),
  responsePlaybooks: (id: string) => request<ResponsePlaybook[]>(`/incidents/${encodeURIComponent(id)}/response-playbooks`),
  requestResponse: (id: string, input: { playbook_id: string; target?: string; analyst: string; reason: string }) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}/responses`, { method: 'POST', body: JSON.stringify(input) }),
  authorizeResponse: (id: string, actionId: string, input: { authorized: boolean; analyst: string; reason: string; simulation_outcome: 'SUCCESS' | 'FAILURE' }) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}/responses/${encodeURIComponent(actionId)}/authorize`, { method: 'POST', body: JSON.stringify(input) }),
  cancelResponse: (id: string, actionId: string, analyst: string, reason: string) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}/responses/${encodeURIComponent(actionId)}/cancel`, { method: 'POST', body: JSON.stringify({ analyst, reason }) }),
  rollbackResponse: (id: string, actionId: string, analyst: string, reason: string) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}/responses/${encodeURIComponent(actionId)}/rollback`, { method: 'POST', body: JSON.stringify({ analyst, reason }) }),
  updateStatus: (id: string, status: IncidentStatus) => request<Incident>(`/incidents/${encodeURIComponent(id)}/status`, {
    method: 'POST', body: JSON.stringify({ status, actor: 'soc analyst' }),
  }),
  addNote: (id: string, text: string) => request<Incident>(`/incidents/${encodeURIComponent(id)}/notes`, {
    method: 'POST', body: JSON.stringify({ text, actor: 'soc analyst' }),
  }),
}
