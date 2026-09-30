import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertOctagon, AlertTriangle, ArrowUpRight, Bell, Boxes,
  Check, ChevronDown, ChevronLeft, CircleDot, Clock3, Command, FileClock, Filter,
  Gauge, GitBranch, ListFilter, LoaderCircle, LockKeyhole, Menu, MessageSquareText,
  Network, Radio, RefreshCw, Search, Shield, ShieldAlert, Siren, SlidersHorizontal,
  Target, Wifi, X,
} from 'lucide-react'
import { api } from './api'
import type {
  AlertRecord, Asset, Incident, IncidentStatus, MitreMapping, Overview, Severity, TelemetryEvent,
} from './types'

type View = 'overview' | 'events' | 'alerts' | 'incidents' | 'investigation' | 'assets' | 'mitre'
const statusOptions: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']
const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function formatTime(value?: string, withSeconds = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', ...(withSeconds ? { second: '2-digit' } : {}),
  }).format(date)
}
function compactId(value: string) { return value.slice(0, 8).toUpperCase() }
function SeverityBadge({ value }: { value: string }) {
  return <span className={`severity severity-${value.toLowerCase()}`}><i />{value}</span>
}
function StatusBadge({ value }: { value: string }) {
  return <span className={`status status-${value.toLowerCase()}`}><span />{value.replace('_', ' ')}</span>
}
function PageHeading({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{detail}</p></div>{action}</div>
}
function EmptyState({ icon: Icon, title, detail }: { icon: typeof Activity; title: string; detail: string }) {
  return <div className="empty-state"><span className="empty-icon"><Icon size={21} /></span><strong>{title}</strong><p>{detail}</p></div>
}
function LoadingState() {
  return <div className="loading-state"><LoaderCircle size={22} className="spin" /><span>Loading SentinelOT data…</span></div>
}
function AssetChips({ assets }: { assets: Array<{ asset_id: string; asset_type?: string }> }) {
  return <div className="asset-chips">{assets.slice(0, 3).map(asset => <span key={asset.asset_id}><Boxes size={12} />{asset.asset_id}</span>)}{assets.length > 3 && <span className="chip-more">+{assets.length - 3}</span>}</div>
}
function RiskMeter({ score, level }: { score: number; level: string }) {
  return <div className="risk-meter"><div className="risk-track"><div className={`risk-fill risk-${level.toLowerCase()}`} style={{ width: `${Math.max(0, Math.min(100, score))}%` }} /></div><strong>{score.toFixed(1)}</strong><span>{level} RISK</span></div>
}

function App() {
  const [view, setView] = useState<View>('overview')
  const [mobileNav, setMobileNav] = useState(false)
  const [overview, setOverview] = useState<Overview | null>(null)
  const [events, setEvents] = useState<TelemetryEvent[]>([])
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [techniques, setTechniques] = useState<Array<MitreMapping & { alert_count: number; alert_ids: string[]; incident_ids: string[] }>>([])
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [incidentQuery, setIncidentQuery] = useState('')
  const [alertQuery, setAlertQuery] = useState('')
  const [eventQuery, setEventQuery] = useState('')
  const [assetQuery, setAssetQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [note, setNote] = useState('')
  const [toast, setToast] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [summary, live, alertRows, incidentRows, assetRows, techniqueRows] = await Promise.all([
        api.overview(), api.events(), api.alerts(), api.incidents(), api.assets(), api.techniques(),
      ])
      setOverview(summary); setEvents(live); setAlerts(alertRows); setIncidents(incidentRows)
      setAssets(assetRows); setTechniques(techniqueRows); setError('')
      if (selectedIncident) {
        const fresh = await api.incident(selectedIncident.incident_id)
        setSelectedIncident(fresh)
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to reach the local dashboard API')
    } finally { setLoading(false) }
  }, [selectedIncident?.incident_id])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    const timer = window.setInterval(() => { void refresh() }, 15000)
    return () => window.clearInterval(timer)
  }, [refresh])
  useEffect(() => {
    const timer = window.setInterval(() => {
      api.events(eventQuery).then(setEvents).catch(() => undefined)
    }, 4000)
    return () => window.clearInterval(timer)
  }, [eventQuery])
  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(''), 3200)
    return () => window.clearTimeout(timer)
  }, [toast])

  const openIncident = async (incidentId: string) => {
    try { setSelectedIncident(await api.incident(incidentId)); setView('investigation'); setMobileNav(false) }
    catch (cause) { setToast(cause instanceof Error ? cause.message : 'Incident could not be loaded') }
  }
  const go = (target: View) => { setView(target); setMobileNav(false) }
  const updateStatus = async (status: IncidentStatus) => {
    if (!selectedIncident) return
    try {
      setSelectedIncident(await api.updateStatus(selectedIncident.incident_id, status))
      await refresh()
      setToast(`Incident status updated to ${status.replace('_', ' ')}`)
    } catch (cause) { setToast(cause instanceof Error ? cause.message : 'Status update failed') }
  }
  const addNote = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!selectedIncident || !note.trim()) return
    try {
      setSelectedIncident(await api.addNote(selectedIncident.incident_id, note.trim()))
      setNote(''); setToast('Investigation note added')
    } catch (cause) { setToast(cause instanceof Error ? cause.message : 'Note could not be saved') }
  }

  const filteredIncidents = useMemo(() => incidents.filter(item => {
    const query = incidentQuery.toLowerCase()
    return (!query || `${item.incident_id} ${item.title} ${item.event_ids.join(' ')}`.toLowerCase().includes(query))
      && (!severityFilter || item.severity === severityFilter)
      && (!statusFilter || item.status === statusFilter)
  }), [incidents, incidentQuery, severityFilter, statusFilter])
  const filteredAlerts = useMemo(() => alerts.filter(row => {
    const alert = row.alert
    return (!alertQuery || `${alert.title} ${alert.description} ${alert.rule_id}`.toLowerCase().includes(alertQuery.toLowerCase()))
      && (!severityFilter || alert.severity === severityFilter)
  }), [alerts, alertQuery, severityFilter])
  const filteredEvents = useMemo(() => events.filter(event => !eventQuery ||
    `${event.event_type} ${event.message} ${event.source_asset.asset_id} ${event.destination_asset?.asset_id ?? ''}`
      .toLowerCase().includes(eventQuery.toLowerCase())), [events, eventQuery])
  const filteredAssets = useMemo(() => assets.filter(asset =>
    !assetQuery || `${asset.asset_id} ${asset.hostname} ${asset.asset_type} ${asset.zone}`.toLowerCase().includes(assetQuery.toLowerCase())), [assets, assetQuery])

  const navItems = [
    { id: 'overview' as const, label: 'SOC Overview', icon: Gauge },
    { id: 'events' as const, label: 'Live Events', icon: Radio, count: events.length },
    { id: 'alerts' as const, label: 'Alerts', icon: AlertOctagon, count: alerts.length },
    { id: 'incidents' as const, label: 'Incidents', icon: Siren, count: incidents.filter(item => !['RESOLVED', 'FALSE_POSITIVE'].includes(item.status)).length },
  ]
  const systemItems = [
    { id: 'assets' as const, label: 'OT Assets', icon: Boxes },
    { id: 'mitre' as const, label: 'MITRE ATT&CK', icon: Target },
  ]

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
      <div className="brand"><span className="brand-mark"><Shield size={20} strokeWidth={2.1} /><i /></span><div><b>SENTINEL<span>OT</span></b><small>SECURITY OPERATIONS</small></div><button className="close-nav" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button></div>
      <div className="workspace-label"><span>LOCAL LAB</span><span className="online-dot" /> PRODUCTION LINE 01</div>
      <nav aria-label="Main navigation">
        <div className="nav-section-label">MONITORING</div>
        {navItems.map(item => <button key={item.id} onClick={() => go(item.id)} className={`nav-item ${view === item.id || (item.id === 'incidents' && view === 'investigation') ? 'active' : ''}`}><item.icon size={17} /><span>{item.label}</span>{item.count !== undefined && <small>{item.count}</small>}</button>)}
        <div className="nav-section-label nav-gap">INTELLIGENCE</div>
        {systemItems.map(item => <button key={item.id} onClick={() => go(item.id)} className={`nav-item ${view === item.id ? 'active' : ''}`}><item.icon size={17} /><span>{item.label}</span></button>)}
      </nav>
      <div className="sidebar-bottom"><div className="api-status"><span className={error ? 'offline-dot' : 'online-dot'} /><span>{error ? 'API disconnected' : 'Local API connected'}</span><Wifi size={14} /></div><div className="profile"><div className="avatar">SA</div><div><b>Security Analyst</b><small>OT OPERATIONS</small></div><ChevronDown size={15} /></div></div>
    </aside>
    {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="Close menu" />}
    <main className="main-shell">
      <header className="topbar"><div className="topbar-left"><button className="menu-button" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button><span className="breadcrumb-root">Security Operations</span><ChevronDown size={13} className="crumb-chevron" /><span>{view === 'investigation' ? 'Incident Investigation' : navItems.find(item => item.id === view)?.label ?? systemItems.find(item => item.id === view)?.label}</span></div><div className="topbar-right"><div className="connection-pill"><span /> ISOLATED LAB</div><span className="top-divider" /><div className="clock-label"><Clock3 size={14} />{new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }).format(new Date())}</div><button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button><button className="refresh-button" onClick={() => void refresh()} title="Refresh data"><RefreshCw size={15} /></button></div></header>
      <div className="content-shell">
        {error && <div className="error-banner" role="alert"><AlertTriangle size={17} /><div><b>Dashboard API unavailable</b><span>{error}. Start the local API and retry.</span></div><button onClick={() => void refresh()}>Retry</button></div>}
        {loading ? <LoadingState /> : !overview ? <EmptyState icon={Network} title="Waiting for SentinelOT API" detail="Connect the local API to load simulated operations data." /> : <>
          {view === 'overview' && <OverviewPage overview={overview} events={events} onIncident={openIncident} onView={go} />}
          {view === 'events' && <EventsPage events={filteredEvents} query={eventQuery} setQuery={setEventQuery} />}
          {view === 'alerts' && <AlertsPage alerts={filteredAlerts} query={alertQuery} setQuery={setAlertQuery} severity={severityFilter} setSeverity={setSeverityFilter} onIncident={openIncident} />}
          {view === 'incidents' && <IncidentsPage incidents={filteredIncidents} query={incidentQuery} setQuery={setIncidentQuery} severity={severityFilter} setSeverity={setSeverityFilter} status={statusFilter} setStatus={setStatusFilter} onIncident={openIncident} />}
          {view === 'investigation' && (selectedIncident ? <InvestigationPage incident={selectedIncident} note={note} setNote={setNote} onAddNote={addNote} onStatus={updateStatus} onBack={() => go('incidents')} /> : <EmptyState icon={Siren} title="Select an incident" detail="Choose an incident from the incident queue to begin investigation." />)}
          {view === 'assets' && <AssetsPage assets={filteredAssets} query={assetQuery} setQuery={setAssetQuery} />}
          {view === 'mitre' && <MitrePage techniques={techniques} onIncident={openIncident} />}
        </>}
      </div>
      <footer className="footer"><span><LockKeyhole size={12} /> SENTINELOT LOCAL DEFENSIVE LAB</span><span>SIMULATED OT TELEMETRY <i /> NO EXTERNAL CONNECTIONS</span><span>PHASE 7 · SOC DASHBOARD</span></footer>
    </main>
    {toast && <div className="toast" role="status"><Check size={16} />{toast}<button onClick={() => setToast('')} aria-label="Dismiss notification"><X size={14} /></button></div>}
  </div>
}

function OverviewPage({ overview, events, onIncident, onView }: { overview: Overview; events: TelemetryEvent[]; onIncident: (id: string) => void; onView: (view: View) => void }) {
  return <>
    <PageHeading eyebrow="COMMAND CENTER / 01" title="SOC Overview" detail="Operational security posture across the simulated control environment." action={<span className="updated-label"><span className="online-dot" /> LIVE TELEMETRY</span>} />
    <section className="overview-stat-grid" aria-label="Incident counts by severity">
      <div className="overview-stat active-stat"><div className="stat-topline"><span>ACTIVE INCIDENTS</span><Activity size={15} /></div><div className="stat-value">{overview.active_incident_count.toString().padStart(2, '0')}</div><div className="stat-foot"><span className="stat-pulse" />Requiring analyst attention</div></div>
      {severityOrder.map(level => <div className={`overview-stat severity-stat stat-${level.toLowerCase()}`} key={level}><div className="stat-topline"><span>{level} SEVERITY</span><span className="severity-icon"><i /></span></div><div className="stat-value">{overview.incident_counts_by_severity[level].toString().padStart(2, '0')}</div><div className="stat-foot">Incident classification</div></div>)}
    </section>
    <div className="overview-grid top-overview-grid">
      <section className="panel recent-alerts-panel"><PanelHeader icon={ShieldAlert} title="Recent alerts" detail="Latest detections from the incident store" action={<button className="text-action" onClick={() => onView('alerts')}>All alerts <ArrowUpRight size={14} /></button>} />
        {overview.recent_alerts.length ? <div className="alert-feed">{overview.recent_alerts.slice(0, 5).map(row => <button key={row.alert.alert_id} className="alert-feed-row" onClick={() => onIncident(row.incident_id)}><div className={`feed-edge edge-${row.alert.severity.toLowerCase()}`} /><div className="feed-main"><div className="feed-title-line"><SeverityBadge value={row.alert.severity} /><strong>{row.alert.title}</strong></div><span>{row.alert.rule_id} <i /> {formatTime(row.alert.timestamp)}</span></div><div className="feed-assets"><AssetChips assets={[...row.alert.source_assets, ...row.alert.target_assets]} /></div><ArrowUpRight size={15} className="row-arrow" /></button>)}</div> : <EmptyState icon={ShieldAlert} title="No alerts yet" detail="Detection alerts appear here when the local pipeline creates an incident." />}
      </section>
      <section className="panel affected-panel"><PanelHeader icon={Boxes} title="Affected OT assets" detail={`${overview.affected_assets.length} assets across active incidents`} action={<button className="text-action" onClick={() => onView('assets')}>Inventory <ArrowUpRight size={14} /></button>} />
        {overview.affected_assets.length ? <div className="affected-list">{overview.affected_assets.slice(0, 6).map(asset => <div className="affected-row" key={asset.asset_id}><div className="asset-glyph"><Boxes size={16} /></div><div><b>{asset.asset_id}</b><small>{asset.hostname}</small></div><span>{asset.asset_type}</span></div>)}</div> : <EmptyState icon={Boxes} title="No affected assets" detail="Active incident asset impact will be summarized here." />}
      </section>
    </div>
    <div className="overview-grid bottom-overview-grid">
      <section className="panel timeline-panel"><PanelHeader icon={FileClock} title="Event timeline" detail="Chronological activity from the synthetic OT stream" action={<span className="panel-meta">{overview.event_timeline.length} EVENTS</span>} />
        {overview.event_timeline.length ? <div className="timeline-list">{overview.event_timeline.slice(0, 7).map(event => <div className="timeline-row" key={event.event_id}><time>{formatTime(event.timestamp)}</time><span className="timeline-marker"><CircleDot size={13} /></span><div className="timeline-copy"><b>{event.message}</b><span>{event.source_asset.asset_id} → {event.destination_asset?.asset_id ?? 'LOCAL'} · {compactId(event.event_id)}</span></div><span className="timeline-kind">{event.event_type.replaceAll('_', ' ')}</span></div>)}</div> : <EmptyState icon={FileClock} title="Event stream is clear" detail="New synthetic telemetry will populate this timeline." />}
      </section>
      <section className="panel technique-panel"><PanelHeader icon={Target} title="MITRE techniques" detail="Observed in mapped detections" action={<button className="text-action" onClick={() => onView('mitre')}>Explore <ArrowUpRight size={14} /></button>} />
        {overview.mitre_techniques.length ? <div className="technique-list">{overview.mitre_techniques.slice(0, 5).map(technique => <div className="technique-row" key={technique.technique_id}><span className="technique-glyph"><Target size={14} /></span><div><b>{technique.technique_id} <span>{technique.domain}</span></b><small>{technique.name}</small></div><strong>{technique.alert_count}<small> alerts</small></strong></div>)}</div> : <EmptyState icon={Target} title="No mapped techniques" detail="Supported ATT&CK mappings will appear with detected alerts." />}
      </section>
    </div>
    <section className="panel live-strip"><div className="live-strip-head"><div><span className="live-indicator"><i /> STREAMING</span><b>Live event stream</b><small>Normal synthetic OT telemetry · refreshes every 4 seconds</small></div><button className="text-action" onClick={() => onView('events')}>Open event explorer <ArrowUpRight size={14} /></button></div>
      <div className="event-strip">{events.slice(0, 5).map(event => <div className="event-strip-card" key={event.event_id}><span className="event-type-icon"><Activity size={14} /></span><div><b>{event.event_type.replaceAll('_', ' ')}</b><small>{event.source_asset.asset_id} → {event.destination_asset?.asset_id ?? 'LOCAL'}</small></div><time>{formatTime(event.timestamp, true)}</time></div>)}</div>
    </section>
  </>
}

function PanelHeader({ icon: Icon, title, detail, action }: { icon: typeof Activity; title: string; detail: string; action?: React.ReactNode }) {
  return <div className="panel-header"><div className="panel-icon"><Icon size={16} /></div><div className="panel-heading-copy"><h2>{title}</h2><p>{detail}</p></div><div className="panel-action">{action}</div></div>
}

function EventsPage({ events, query, setQuery }: { events: TelemetryEvent[]; query: string; setQuery: (value: string) => void }) {
  return <><PageHeading eyebrow="TELEMETRY / STREAM" title="Live Events" detail="Streaming synthetic OT events generated by the existing SentinelOT simulators." action={<span className="live-indicator"><i /> LIVE · 4 SEC</span>} />
    <section className="panel data-panel"><div className="table-toolbar"><div className="toolbar-search"><Search size={15} /><input aria-label="Search events" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search events, assets, event type…" /></div><span className="result-count"><Radio size={14} />{events.length} EVENTS IN BUFFER</span></div>
      {events.length ? <div className="table-scroll"><table><thead><tr><th>EVENT / TIME</th><th>TYPE</th><th>SOURCE</th><th>DESTINATION</th><th>SEVERITY</th><th>MESSAGE</th></tr></thead><tbody>{events.map(event => <tr key={event.event_id}><td><b className="mono">{compactId(event.event_id)}</b><small>{formatTime(event.timestamp, true)}</small></td><td><span className="event-type"><Activity size={13} />{event.event_type.replaceAll('_', ' ')}</span></td><td><AssetLink id={event.source_asset.asset_id} type={event.source_asset.asset_type} /></td><td>{event.destination_asset ? <AssetLink id={event.destination_asset.asset_id} type={event.destination_asset.asset_type} /> : <span className="muted">Internal</span>}</td><td><SeverityBadge value={event.severity} /></td><td className="message-cell">{event.message}</td></tr>)}</tbody></table></div> : <EmptyState icon={Radio} title="No matching telemetry" detail="Change your search filter or wait for the next simulator refresh." />}
    </section>
  </>
}

function AlertsPage({ alerts, query, setQuery, severity, setSeverity, onIncident }: { alerts: AlertRecord[]; query: string; setQuery: (value: string) => void; severity: string; setSeverity: (value: string) => void; onIncident: (id: string) => void }) {
  return <><PageHeading eyebrow="DETECTION / SIGNALS" title="Alerts" detail="Rule-based detections enriched with ATT&CK context and risk assessments." action={<span className="count-tag"><ShieldAlert size={14} />{alerts.length} MATCHING ALERTS</span>} />
    <section className="panel data-panel"><div className="table-toolbar"><div className="toolbar-search"><Search size={15} /><input aria-label="Search alerts" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search title, rule, asset…" /></div><div className="toolbar-filter"><Filter size={14} /><select aria-label="Filter severity" value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option>{severityOrder.map(level => <option key={level}>{level}</option>)}</select><span className="result-count">{alerts.length} RESULTS</span></div></div>
      {alerts.length ? <div className="table-scroll"><table><thead><tr><th>ALERT</th><th>SEVERITY</th><th>RISK</th><th>ASSETS</th><th>ATT&CK</th><th>TIME</th><th>INCIDENT</th></tr></thead><tbody>{alerts.map(row => <tr key={row.alert.alert_id}><td className="alert-title-cell"><b>{row.alert.title}</b><small>{row.alert.rule_id}</small></td><td><SeverityBadge value={row.alert.severity} /></td><td><div className="table-risk"><b>{row.risk_assessment.risk_score.toFixed(1)}</b><span>{row.risk_assessment.risk_level}</span></div></td><td><AssetChips assets={[...row.alert.source_assets, ...row.alert.target_assets]} /></td><td>{row.alert.mitre_mappings.length ? <span className="table-technique">{row.alert.mitre_mappings.map(map => map.technique_id).join(', ')}</span> : <span className="muted">Unmapped</span>}</td><td className="time-cell">{formatTime(row.alert.timestamp)}</td><td><button className="incident-link" onClick={() => onIncident(row.incident_id)}>{compactId(row.incident_id)} <ArrowUpRight size={12} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={ShieldAlert} title="No alerts match" detail="Alerts are populated from detections persisted in the local incident store." />}
    </section>
  </>
}

function IncidentsPage({ incidents, query, setQuery, severity, setSeverity, status, setStatus, onIncident }: { incidents: Incident[]; query: string; setQuery: (value: string) => void; severity: string; setSeverity: (value: string) => void; status: string; setStatus: (value: string) => void; onIncident: (id: string) => void }) {
  return <><PageHeading eyebrow="CASE MANAGEMENT / QUEUE" title="Incidents" detail="Correlated alert investigations with preserved event evidence and analyst history." action={<span className="count-tag"><Siren size={14} />{incidents.length} INCIDENTS</span>} />
    <section className="panel data-panel"><div className="table-toolbar"><div className="toolbar-search"><Search size={15} /><input aria-label="Search incidents" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search incident, event ID, affected asset…" /></div><div className="toolbar-filter"><ListFilter size={14} /><select aria-label="Filter status" value={status} onChange={event => setStatus(event.target.value)}><option value="">All statuses</option>{statusOptions.map(state => <option key={state}>{state}</option>)}</select><select aria-label="Filter severity" value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option>{severityOrder.map(level => <option key={level}>{level}</option>)}</select></div></div>
      {incidents.length ? <div className="table-scroll"><table><thead><tr><th>INCIDENT</th><th>STATUS</th><th>SEVERITY</th><th>RISK SCORE</th><th>ALERTS</th><th>EVENT IDS</th><th>LAST ACTIVITY</th><th /></tr></thead><tbody>{incidents.map(incident => <tr key={incident.incident_id} className="clickable-row" onClick={() => onIncident(incident.incident_id)}><td className="incident-title-cell"><b>{incident.title}</b><small>INC-{compactId(incident.incident_id)}</small></td><td><StatusBadge value={incident.status} /></td><td><SeverityBadge value={incident.severity} /></td><td><RiskMeter score={incident.risk_score} level={incident.risk_level} /></td><td>{incident.alert_records.length.toString().padStart(2, '0')}</td><td><span className="event-id-count"><GitBranch size={13} />{incident.event_ids.length} events</span></td><td className="time-cell">{formatTime(incident.updated_at)}</td><td><ChevronDown size={15} className="rotate-left" /></td></tr>)}</tbody></table></div> : <EmptyState icon={Siren} title="Incident queue is clear" detail="No incidents match the current filters. Ingest a simulation through the incident CLI to populate this queue." />}
    </section>
  </>
}

function InvestigationPage({ incident, note, setNote, onAddNote, onStatus, onBack }: { incident: Incident; note: string; setNote: (value: string) => void; onAddNote: (event: React.FormEvent) => void; onStatus: (status: IncidentStatus) => void; onBack: () => void }) {
  const allAssets = new Map<string, { asset_id: string; asset_type: string }>()
  incident.alert_records.forEach(({ alert }) => [...alert.source_assets, ...alert.target_assets].forEach(asset => allAssets.set(asset.asset_id, asset)))
  const primaryRisk = [...incident.alert_records].sort((a, b) => b.risk_assessment.risk_score - a.risk_assessment.risk_score)[0]?.risk_assessment
  return <><button className="back-link" onClick={onBack}><ChevronLeft size={15} />Incident queue</button>
    <div className="investigation-heading"><div><div className="eyebrow">CASE FILE / INC-{compactId(incident.incident_id)}</div><h1>{incident.title}</h1><div className="incident-subline"><span>{incident.incident_id}</span><i />Opened {formatTime(incident.created_at)}<i /><span>{incident.alert_records.length} related alert{incident.alert_records.length === 1 ? '' : 's'}</span></div></div><div className="investigation-actions"><StatusBadge value={incident.status} /><select aria-label="Update incident status" value={incident.status} onChange={event => onStatus(event.target.value as IncidentStatus)}>{statusOptions.map(state => <option key={state}>{state}</option>)}</select></div></div>
    <div className="investigation-summary"><div className="summary-severity"><span>INCIDENT SEVERITY</span><SeverityBadge value={incident.severity} /><small>Highest correlated alert</small></div><div className="summary-risk"><span>RISK ASSESSMENT</span><RiskMeter score={incident.risk_score} level={incident.risk_level} /><small>{primaryRisk?.explanation ?? 'Risk assessment explanation is unavailable.'}</small></div><div className="summary-assets"><span>AFFECTED OT ASSETS</span><div><AssetChips assets={[...allAssets.values()]} /></div><small>{allAssets.size} unique assets across linked alerts</small></div><div className="summary-events"><span>TELEMETRY EVIDENCE</span><b>{incident.event_ids.length.toString().padStart(2, '0')}</b><small>Original event IDs preserved</small></div></div>
    <div className="investigation-grid">
      <div className="investigation-main">
        <section className="panel investigation-panel"><PanelHeader icon={ShieldAlert} title="Related alerts" detail="Detection records linked to this incident" />
          {incident.alert_records.length ? <div className="related-alert-list">{incident.alert_records.map(({ alert, risk_assessment }) => <article className="related-alert" key={alert.alert_id}><div className={`related-edge edge-${alert.severity.toLowerCase()}`} /><div className="related-alert-top"><SeverityBadge value={alert.severity} /><span>{alert.rule_id}</span><time>{formatTime(alert.timestamp)}</time></div><h3>{alert.title}</h3><p>{alert.description}</p><div className="related-alert-foot"><AssetChips assets={[...alert.source_assets, ...alert.target_assets]} /><span>RISK <b>{risk_assessment.risk_score.toFixed(1)}</b></span></div><details className="evidence-details"><summary>Detection evidence <ChevronDown size={13} /></summary><pre>{JSON.stringify(alert.evidence, null, 2)}</pre></details></article>)}</div> : <EmptyState icon={ShieldAlert} title="No alert records" detail="This incident has no linked alerts." />}
        </section>
        <section className="panel investigation-panel"><PanelHeader icon={Network} title="MITRE ATT&CK mapping" detail="Structured technique and tactic metadata from the alert records" />
          {incident.alert_records.some(record => record.alert.mitre_mappings.length) ? <div className="mapping-grid">{incident.alert_records.flatMap(record => record.alert.mitre_mappings.map(mapping => <TechniqueCard key={`${record.alert.alert_id}-${mapping.technique_id}`} technique={mapping} />))}</div> : <EmptyState icon={Target} title="No supported technique mapping" detail="The associated detection evidence does not currently support a configured ATT&CK technique." />}
        </section>
        <section className="panel investigation-panel"><PanelHeader icon={GitBranch} title="Telemetry event IDs" detail="Traceable source events retained by the detection and risk pipeline" action={<span className="panel-meta">{incident.event_ids.length} EVENTS</span>} />
          {incident.event_ids.length ? <div className="event-id-grid">{incident.event_ids.map(id => <div className="event-id-card" key={id}><span><Activity size={14} /></span><code>{id}</code><button title="Copy event ID" onClick={() => void navigator.clipboard?.writeText(id)}><Command size={13} /></button></div>)}</div> : <EmptyState icon={GitBranch} title="No event references" detail="Telemetry source IDs will be listed here." />}
        </section>
      </div>
      <div className="investigation-side">
        <section className="panel investigation-panel"><PanelHeader icon={FileClock} title="Investigation timeline" detail="Chronological incident activity" />
          {incident.timeline.length ? <div className="case-timeline">{incident.timeline.map(entry => <div className="case-timeline-row" key={entry.entry_id}><span className="case-timeline-dot"><CircleDot size={13} /></span><div><time>{formatTime(entry.timestamp, true)}</time><b>{entry.summary}</b><small>{entry.kind.replaceAll('_', ' ')} · {entry.actor}</small></div></div>)}</div> : <EmptyState icon={FileClock} title="No timeline entries" detail="Incident events will appear here." />}
        </section>
        <section className="panel notes-panel"><PanelHeader icon={MessageSquareText} title="Analyst notes" detail={`${incident.analyst_notes.length} investigation notes`} />
          <form className="note-form" onSubmit={onAddNote}><textarea aria-label="Analyst note" value={note} onChange={event => setNote(event.target.value)} placeholder="Record an observation or next step…" rows={3} /><button type="submit" disabled={!note.trim()}>Add note <ArrowUpRight size={13} /></button></form>
          {incident.analyst_notes.length ? <div className="notes-list">{[...incident.analyst_notes].reverse().map(item => <div className="note-entry" key={item.note_id}><div className="note-avatar">{item.actor.slice(0, 1).toUpperCase()}</div><div><p>{item.text}</p><small>{item.actor} · {formatTime(item.timestamp)}</small></div></div>)}</div> : <div className="notes-empty">No notes have been recorded for this incident.</div>}
        </section>
        <section className="panel audit-panel"><PanelHeader icon={LockKeyhole} title="Audit history" detail="Status and analyst actions" />
          {incident.audit_trail.length ? <div className="audit-list">{[...incident.audit_trail].reverse().map(entry => <div key={entry.audit_id} className="audit-row"><span className="audit-action-icon"><FileClock size={13} /></span><div><b>{entry.action.replaceAll('_', ' ')}</b><small>{entry.old_status && entry.new_status ? `${entry.old_status} → ${entry.new_status}` : entry.reason ?? entry.actor}</small><time>{formatTime(entry.timestamp, true)}</time></div></div>)}</div> : <EmptyState icon={LockKeyhole} title="No audit actions" detail="Incident actions are recorded here." />}
        </section>
        {primaryRisk && <section className="panel risk-factors-panel"><PanelHeader icon={SlidersHorizontal} title="Risk explanation" detail={primaryRisk.formula} />{Object.entries(primaryRisk.factors).map(([name, factor]) => <div className="risk-factor" key={name}><div><b>{name.replaceAll('_', ' ')}</b><span>{factor.rationale}</span></div><strong>{factor.contribution.toFixed(1)}</strong></div>)}</section>}
      </div>
    </div>
  </>
}

function TechniqueCard({ technique }: { technique: MitreMapping }) {
  return <article className="technique-card"><div className="technique-card-top"><span>{technique.domain} MATRIX</span><span>{technique.technique_id}</span></div><h3>{technique.technique_id}</h3><b>{technique.name}</b><div className="tactic-pills">{technique.tactics.map(tactic => <span key={tactic.tactic_id}>{tactic.name}</span>)}</div><p>{technique.mapping_basis}</p></article>
}
function AssetLink({ id, type }: { id: string; type: string }) {
  return <span className="asset-link"><span><Boxes size={12} /></span><b>{id}</b><small>{type}</small></span>
}

function AssetsPage({ assets, query, setQuery }: { assets: Asset[]; query: string; setQuery: (value: string) => void }) {
  return <><PageHeading eyebrow="INVENTORY / OT ENVIRONMENT" title="OT Assets" detail="Simulated industrial assets sourced from the SentinelOT AssetRegistry." action={<span className="count-tag"><Boxes size={14} />{assets.length} ASSETS</span>} />
    <section className="panel data-panel"><div className="table-toolbar"><div className="toolbar-search"><Search size={15} /><input aria-label="Search assets" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search asset, hostname, zone…" /></div><span className="result-count"><LockKeyhole size={13} />PRIVATE LAB SUBNET</span></div>
      {assets.length ? <div className="asset-card-grid">{assets.map(asset => <article className="asset-card" key={asset.asset_id}><div className="asset-card-heading"><span className={`asset-type-glyph type-${asset.asset_type.toLowerCase()}`}><Boxes size={18} /></span><span className={`asset-status asset-status-${asset.status.toLowerCase()}`}><i />{asset.status}</span></div><div className="asset-card-title"><h2>{asset.asset_id}</h2><span>{asset.asset_type.replaceAll('_', ' ')}</span></div><p>{asset.description}</p><div className="asset-identity"><span>{asset.hostname}</span><code>{asset.ip_address}</code></div><div className="asset-card-foot"><div><small>CRITICALITY</small><b>{asset.criticality}<span> / 5</span></b></div><div><small>PURDUE LEVEL</small><b>L{asset.purdue_level}</b></div><div><small>FIRMWARE</small><b>{asset.firmware_version}</b></div></div><div className="protocol-list">{asset.protocols.map(protocol => <span key={protocol}>{protocol}</span>)}</div><div className="asset-zone"><span>{asset.zone}</span><span>{asset.manufacturer}</span></div></article>)}</div> : <EmptyState icon={Boxes} title="No assets match" detail="Try a different asset or zone filter." />}
    </section>
  </>
}

function MitrePage({ techniques, onIncident }: { techniques: Array<MitreMapping & { alert_count: number; alert_ids: string[]; incident_ids: string[] }>; onIncident: (id: string) => void }) {
  return <><PageHeading eyebrow="THREAT INTELLIGENCE / ATT&CK" title="MITRE ATT&CK" detail="Observed techniques supported by SentinelOT detection evidence." action={<span className="count-tag"><Target size={14} />{techniques.length} TECHNIQUES</span>} />
    <div className="mitre-note"><Target size={16} /><span>Technique mappings are attached by the backend mapper when alert evidence supports them. Unmapped alerts remain unmapped.</span></div>
    {techniques.length ? <div className="mitre-page-grid">{techniques.map(technique => <article className="mitre-technique-card" key={technique.technique_id}><div className="mitre-card-header"><div className="mitre-card-domain"><span>{technique.domain === 'ICS' ? 'OT / ICS' : 'ENTERPRISE'}</span><b>{technique.technique_id}</b></div></div><h2>{technique.name}</h2><div className="mitre-tactic-list">{technique.tactics.map(tactic => <span key={tactic.tactic_id}><span>{tactic.tactic_id}</span>{tactic.name}</span>)}</div><p>{technique.mapping_basis}</p><div className="mitre-card-footer"><span><ShieldAlert size={14} />{technique.alert_count} mapped alerts</span><div>{technique.incident_ids.map(id => <button key={id} onClick={() => onIncident(id)}>INC-{compactId(id)} <ArrowUpRight size={12} /></button>)}</div></div></article>)}</div> : <div className="panel mitre-empty"><EmptyState icon={Target} title="No observed technique mappings" detail="Run a synthetic attack scenario through detection and MITRE enrichment. Supported mappings will appear here." /></div>}
  </>
}

export default App
