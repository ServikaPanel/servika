import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import SystemHistoryCharts from '@/components/SystemHistoryCharts'
import {
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type CPU = { percent: number; cores: number; load_1m: number; load_5m: number; load_15m: number }
type Memory = { total_kb: number; used_kb: number; free_kb: number; percent: number }
type Swap = { total_kb: number; used_kb: number; percent: number }
type Disk = { total_byte: number; used_byte: number; free_byte: number; percent: number; mount: string; fs?: string }
type Network = { interface: string; rx_bytes_sec: number; tx_bytes_sec: number; rx_total_byte: number; tx_total_byte: number }
type Service = { name: string; label: string; enabled: boolean }
type SystemInfo = { hostname: string; ip: string; os_name: string; kernel: string; cpu_model: string; cpu_cores: number; panel_version: string }

type Usage = {
  system: SystemInfo; cpu: CPU; memory: Memory; swap: Swap
  disk: Disk; disks: Disk[]; network: Network; services: Service[]
  uptime_sec: number
}

type Process = { pid: number; user: string; cpu_percent: number; mem_percent: number; command: string }

type Domain = { id: number; domain_name: string; system_user: string; status: string }

type SSLInfo = { valid: boolean; end_date: string; remaining_days: number; issuer?: string; subject?: string }
type Health = {
  url: string; status_code: number; response_time_ms: number; reachable: boolean
  error?: string; scheme: string; ssl?: SSLInfo; size_byte: number; server?: string
}

type DataPoint = { t: number; cpu: number; mem: number; swap: number; load: number; rx: number; tx: number }

const MAX_DATA_POINTS = 60 // Sixty samples at five-second intervals cover five minutes.
const POLL_MS = 5000

export default function MonitoringPage() {
  const { t } = useTranslation('MonitoringPage')
  const [tab, setTab] = useState<'server' | 'domain' | 'logs'>('server')
  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.monitoring') }]} />
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <span className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-500">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          {t('liveRefresh', { seconds: POLL_MS / 1000 })}
        </span>
      </div>

      <div className="flex gap-1 mb-5 border-b border-slate-200 dark:border-slate-700">
        <TabButton enabled={tab === 'server'}  onClick={() => setTab('server')}>{t('tabs.server')}</TabButton>
        <TabButton enabled={tab === 'domain'} onClick={() => setTab('domain')}>{t('tabs.domain')}</TabButton>
        <TabButton enabled={tab === 'logs'} onClick={() => setTab('logs')}>{t('tabs.logs')}</TabButton>
      </div>

      {tab === 'server' ? <ServerMonitoring /> : tab === 'domain' ? <DomainMonitoring /> : <ServerLogs />}
    </div>
  )
}

function TabButton({ enabled, onClick, children }: { enabled: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition ${
      enabled ? 'border-brand-600 text-brand-700 dark:text-brand-300' : 'border-transparent text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 dark:text-slate-300'
    }`}>{children}</button>
  )
}

// ============================================================================
// SERVER MONITORING
// ============================================================================
function ServerMonitoring() {
  const { t } = useTranslation('MonitoringPage')
  const report = useReportError()
  const [u, setU] = useState<Usage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dataPoints, setDataPoints] = useState<DataPoint[]>([])
  const [procs, setProcs] = useState<Process[]>([])
  const [procSort, setProcSort] = useState<'cpu' | 'mem'>('cpu')

  useEffect(() => {
    function load() {
      api.get<Usage>('/system/usage').then(r => {
        setU(r.data)
        setDataPoints(prev => {
          const dataPoint: DataPoint = {
            t: Date.now(),
            cpu: r.data.cpu.percent,
            mem: r.data.memory.percent,
            swap: r.data.swap.percent || 0,
            load: Math.min(100, (r.data.cpu.load_1m / Math.max(1, r.data.cpu.cores)) * 100),
            rx: r.data.network.rx_bytes_sec || 0,
            tx: r.data.network.tx_bytes_sec || 0,
          }
          const newItem = [...prev, dataPoint]
          return newItem.length > MAX_DATA_POINTS ? newItem.slice(-MAX_DATA_POINTS) : newItem
        })
      }).catch(e => setError(apiError(e)))
    }
    load()
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    function loadProcs() {
      api.get<Process[]>(`/system/processes?n=15&sort=${procSort}`).then(r => setProcs(r.data)).catch(report('processes'))
    }
    loadProcs()
    const t = setInterval(loadProcs, POLL_MS * 2)
    return () => clearInterval(t)
  }, [procSort, report])

  return (
    <>
      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {/* Snapshot grid */}
      {u && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
          <Snap title={t('snap.cpu')} value={u.cpu.percent.toFixed(1) + '%'} alt={t('snap.cpuCores', { count: u.cpu.cores })} color="indigo" />
          <Snap title={t('snap.memory')} value={u.memory.percent.toFixed(1) + '%'}
            alt={`${(u.memory.used_kb/1024).toFixed(0)} / ${(u.memory.total_kb/1024).toFixed(0)} MB`} color="emerald" />
          <Snap title={t('snap.load1m')} value={u.cpu.load_1m.toFixed(2)}
            alt={t('snap.loadAlt', { load5m: u.cpu.load_5m.toFixed(2), load15m: u.cpu.load_15m.toFixed(2) })} color="amber" />
          <Snap title={t('snap.diskRoot')} value={u.disk.percent.toFixed(1) + '%'}
            alt={`${fmtByte(u.disk.used_byte)} / ${fmtByte(u.disk.total_byte)}`} color="violet" />
        </div>
      )}

      {/* Multi-series line chart */}
      <Card title={t('chart.systemResources')} right={t('chart.samples', { count: dataPoints.length, max: MAX_DATA_POINTS, minutes: (dataPoints.length*POLL_MS/1000/60).toFixed(1) })}>
        <div className="flex items-center gap-4 mb-2 text-xs">
          <Legend color="bg-indigo-500" label={t('chart.legendCpu')} />
          <Legend color="bg-emerald-500" label={t('chart.legendMemory')} />
          <Legend color="bg-violet-500" label={t('chart.legendSwap')} />
          <Legend color="bg-amber-500" label={t('chart.legendLoad')} />
        </div>
        <MultiSeriesChart dataPoints={dataPoints} series={[
          { key: 'cpu', color: '#6366f1' },
          { key: 'mem', color: '#10b981' },
          { key: 'swap', color: '#8b5cf6' },
          { key: 'load', color: '#f59e0b' },
        ]} yMax={100} suffix="(%)" />
      </Card>

      <div className="h-5" />

      {/* Network traffic chart */}
      <Card title={t('chart.networkTraffic')} right={u?.network?.interface ? t('chart.interface', { name: u.network.interface }) : ''}>
        <div className="flex items-center gap-4 mb-2 text-xs">
          <Legend color="bg-sky-500" label={t('chart.legendRx')} />
          <Legend color="bg-pink-500" label={t('chart.legendTx')} />
        </div>
        <MultiSeriesChart
          dataPoints={dataPoints.map(n => ({ ...n, rx: n.rx/1024, tx: n.tx/1024 }))}
          series={[
            { key: 'rx', color: '#0ea5e9' },
            { key: 'tx', color: '#ec4899' },
          ]}
          yMax={Math.max(10, ...dataPoints.map(n => Math.max(n.rx, n.tx)/1024) ) * 1.2}
          suffix="KB/s"
        />
      </Card>

      <div className="h-5" />

      {/* Stored history — survives a reload, unlike the two live charts above */}
      <SystemHistoryCharts />

      <div className="h-5" />

      {/* Services */}
      {u && (
        <Card title={t('services.title')} right={t('services.enabledCount', { enabled: u.services.filter(s => s.enabled).length, total: u.services.length })}>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {u.services.map(s => (
              <div key={s.name} className={`flex items-center gap-2 px-3 py-2 rounded-md border text-xs ${
                s.enabled ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20' : 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
              }`}>
                <span className={`w-2 h-2 rounded-full ${s.enabled ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-slate-800 dark:text-slate-200 truncate">{s.label}</div>
                  <div className="text-[10px] font-mono text-slate-500 dark:text-slate-500 truncate">{s.name}</div>
                </div>
                <span className={`text-[10px] font-semibold uppercase ${s.enabled ? 'text-emerald-700 dark:text-emerald-300' : 'text-red-700 dark:text-red-300'}`}>
                  {s.enabled ? t('services.active') : t('services.stopped')}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="h-5" />

      {/* Top processes */}
      <Card title={t('processes.title')} right={
        <div className="flex items-center gap-1">
          <button onClick={() => setProcSort('cpu')}
            className={`text-[11px] px-2 py-1 rounded ${procSort === 'cpu' ? 'bg-indigo-600 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-200'}`}>{t('processes.sortCpu')}</button>
          <button onClick={() => setProcSort('mem')}
            className={`text-[11px] px-2 py-1 rounded ${procSort === 'mem' ? 'bg-emerald-600 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-200'}`}>{t('processes.sortMem')}</button>
        </div>
      }>
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="text-left font-medium px-4 py-2.5">{t('processes.colPid')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('processes.colUser')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('processes.colCpu')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('processes.colMem')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('processes.colCommand')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {procs.length === 0 && (
                <tr><td colSpan={5} className="py-6 text-center text-xs text-slate-400 dark:text-slate-500">{t('processes.loading')}</td></tr>
              )}
              {procs.map(p => (
                <tr key={p.pid} className={responsiveTableRowClass}>
                  <td data-label={t('processes.colPid')} className={responsiveTableCodeCellClass}>{p.pid}</td>
                  <td data-label={t('processes.colUser')} className={responsiveTableCodeCellClass}>{p.user}</td>
                  <td data-label={t('processes.colCpu')} className={`${responsiveTableCodeCellClass} lg:text-right ${p.cpu_percent >= 50 ? 'text-red-600 dark:text-red-400 font-semibold' : p.cpu_percent >= 20 ? 'text-amber-600 dark:text-amber-400' : ''}`}>{p.cpu_percent.toFixed(1)}</td>
                  <td data-label={t('processes.colMem')} className={`${responsiveTableCodeCellClass} lg:text-right ${p.mem_percent >= 30 ? 'text-red-600 dark:text-red-400 font-semibold' : p.mem_percent >= 10 ? 'text-amber-600 dark:text-amber-400' : ''}`}>{p.mem_percent.toFixed(1)}</td>
                  <td data-label={t('processes.colCommand')} className={`${responsiveTableCellClass} font-mono text-xs break-all`} title={p.command}>{p.command}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

// ============================================================================
// DOMAIN MONITORING
// ============================================================================
function DomainMonitoring() {
  const { t } = useTranslation('MonitoringPage')
  const report = useReportError()
  const [domains, setDomains] = useState<Domain[]>([])
  const [selected, setSelected] = useState<number | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [probingHealth, setProbingHealth] = useState(false)
  const [accessLog, setAccessLog] = useState<string[]>([])
  const [errorLog, setErrorLog] = useState<string[]>([])
  const [logError, setLogError] = useState<string | null>(null)
  const accessRef = useRef<HTMLDivElement>(null)
  const errorRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    api.get<Domain[]>('/domains').then(r => {
      const enabled = r.data.filter(d => d.status === 'active')
      setDomains(enabled)
      // Functional so the current selection stays out of this closure: the
      // effect must run once, not on every selection change.
      setSelected(current => current === null && enabled.length > 0 ? enabled[0].id : current)
    }).catch(report('domains'))
  }, [report])

  const probe = useCallback((domainID: number) => {
    api.get<Health>(`/domains/${domainID}/health`).then(r => setHealth(r.data))
      .catch(e => setHealth({ url: '', status_code: 0, response_time_ms: 0, reachable: false, error: apiError(e), scheme: '', size_byte: 0 }))
      .finally(() => setProbingHealth(false))
  }, [])

  // Cleared during render rather than in an effect: these panels belong to the
  // selected domain, so one frame of the previous domain's health and log lines
  // would show the wrong host's data, not just paint late.
  const [shownFor, setShownFor] = useState(selected)
  if (selected !== shownFor) {
    setShownFor(selected)
    setHealth(null)
    setProbingHealth(true)
    setAccessLog([])
    setErrorLog([])
    setLogError(null)
  }

  useEffect(() => {
    if (!selected) return
    probe(selected)

    function fetchLogs() {
      api.get<{ lines: string[]; current: boolean }>(`/domains/${selected}/logs/read?file=access&last=80`)
        .then(response => setAccessLog(response.data.lines || []))
        .catch(e => setLogError(apiError(e)))
      api.get<{ lines: string[]; current: boolean }>(`/domains/${selected}/logs/read?file=error&last=40`)
        .then(response => setErrorLog(response.data.lines || []))
        .catch(report('errorLog'))
    }
    fetchLogs()
    const t = setInterval(fetchLogs, POLL_MS)
    return () => clearInterval(t)
  }, [selected, probe, report])

  // Auto-scroll to bottom on log update
  useEffect(() => { if (accessRef.current) accessRef.current.scrollTop = accessRef.current.scrollHeight }, [accessLog])
  useEffect(() => { if (errorRef.current) errorRef.current.scrollTop = errorRef.current.scrollHeight }, [errorLog])

  const selectedDomain = useMemo(() => domains.find(d => d.id === selected), [domains, selected])

  return (
    <>
      <Card title={t('domain.selectionTitle')}>
        <div className="flex items-center gap-3 flex-wrap">
          <select value={selected ?? ''} onChange={e => setSelected(Number(e.target.value))}
            className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm bg-white dark:bg-slate-800 min-w-[280px] focus:border-brand-500 outline-none">
            {domains.length === 0 && <option value="">{t('domain.noActiveDomains')}</option>}
            {domains.map(d => <option key={d.id} value={d.id}>{d.domain_name}</option>)}
          </select>
          {selected && (
            <button onClick={() => probe(selected)} disabled={probingHealth}
              className="text-sm px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 rounded">
              {probingHealth ? t('domain.probing') : t('domain.healthProbe')}
            </button>
          )}
          {selectedDomain && (
            <a href={`https://${selectedDomain.domain_name}`} target="_blank" rel="noreferrer"
              className="text-sm text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300">{t('domain.openSite')}</a>
          )}
        </div>
      </Card>

      <div className="h-5" />

      {/* HTTP health and SSL */}
      {health && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-5">
          <HealthCard h={health} />
          <SSLCard ssl={health.ssl} scheme={health.scheme} />
          <ResponseCard h={health} />
        </div>
      )}

      <DomainLogPanels accessLog={accessLog} errorLog={errorLog} logError={logError} accessRef={accessRef} errorRef={errorRef} />
    </>
  )
}

type DomainLogPanelsProps = {
  accessLog: string[]
  errorLog: string[]
  logError: string | null
  accessRef: React.RefObject<HTMLDivElement | null>
  errorRef: React.RefObject<HTMLDivElement | null>
}

function DomainLogPanels({ accessLog, errorLog, logError, accessRef, errorRef }: DomainLogPanelsProps) {
  const { t } = useTranslation('MonitoringPage')
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      <Card title={t('domain.accessLog')} right={t('domain.lastLines', { count: accessLog.length })}>
        <div ref={accessRef} className="bg-slate-950 text-emerald-300 font-mono text-[11px] p-3 rounded h-80 overflow-auto whitespace-pre">
          {accessLog.length === 0
            ? <div className="text-slate-500 dark:text-slate-500 italic">{t('domain.noAccessEntries')}</div>
            : accessLog.join('\n')}
        </div>
      </Card>
      <Card title={t('domain.errorLog')} right={t('domain.lastLines', { count: errorLog.length })}>
        <div ref={errorRef} className="bg-slate-950 text-rose-300 font-mono text-[11px] p-3 rounded h-80 overflow-auto whitespace-pre">
          {errorLog.length === 0
            ? <div className="text-slate-500 dark:text-slate-500 italic">{logError || t('domain.noErrorEntries')}</div>
            : errorLog.join('\n')}
        </div>
      </Card>
    </div>
  )
}

// ============================================================================
// COMPONENTS
// ============================================================================
// ============================================================================
// Server logs from journald: panel, nginx, MariaDB, named, sshd, cron, and system.
// ============================================================================
const LOG_SOURCE_LABELS: Record<string, string> = {
  panel: 'Panel', nginx: 'nginx', mariadb: 'MariaDB', named: 'DNS (named)',
  sshd: 'SSH', cron: 'Cron', system: 'Entire System',
}

function ServerLogs() {
  const { t } = useTranslation('MonitoringPage')
  const sourceLabel = (name: string) => t(`logSources.${name}`, { defaultValue: LOG_SOURCE_LABELS[name] || name })
  const [source, setSource] = useState('panel')
  const [sources, setSources] = useState<string[]>(['panel', 'nginx', 'mariadb', 'named', 'sshd', 'cron', 'system'])
  const [lines, setLines] = useState<string[]>([])
  const [lastLineCount, setLastLineCount] = useState(200)
  const [reloadToken, setReloadToken] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)

  // Derived instead of stored: loading means the request for the CURRENT source,
  // line count and refresh has not settled, so any of the three shows the
  // spinner on the same render rather than one frame of the previous log.
  const requestKey = `${source}:${lastLineCount}:${reloadToken}`
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  const loading = loadedFor !== requestKey

  useEffect(() => {
    let cancelled = false
    api.get<{ lines?: string[]; sources?: string[] }>('/admin/system/logs', { params: { source, last: lastLineCount } })
      .then(response => {
        if (cancelled) return
        setLines(response.data.lines || [])
        if (response.data.sources) setSources(response.data.sources)
        setError(null)
      })
      .catch(caughtError => { if (!cancelled) setError(apiError(caughtError)) })
      .finally(() => { if (!cancelled) setLoadedFor(requestKey) })
    return () => { cancelled = true }
  }, [source, lastLineCount, requestKey])
  const visibleLines = useMemo(() => {
    const q = search.trim().toLowerCase()
    return q ? lines.filter(s => s.toLowerCase().includes(q)) : lines
  }, [lines, search])
  useEffect(() => { if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight }, [visibleLines])

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="flex flex-wrap gap-1">
          {sources.map(sourceName => (
            <button key={sourceName} onClick={() => setSource(sourceName)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border transition ${source === sourceName
                ? 'bg-brand-600 border-brand-600 text-white'
                : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'}`}>
              {sourceLabel(sourceName)}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('logs.searchPlaceholder')}
            className="px-2.5 py-1.5 text-xs w-40 border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 placeholder:text-slate-400 outline-none focus:border-brand-500" />
          <select value={lastLineCount} onChange={event => setLastLineCount(Number(event.target.value))}
            className="px-2 py-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300">
            {[100, 200, 500, 1000].map(lineCount => <option key={lineCount} value={lineCount}>{t('logs.lastLineCount', { count: lineCount })}</option>)}
          </select>
          <button onClick={() => setReloadToken(n => n + 1)} disabled={loading} className="px-3 py-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">{t('logs.refresh')}</button>
        </div>
      </div>
      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}
      <div ref={scrollRef} className="bg-slate-900 border border-slate-800 rounded-2xl overflow-auto p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all" style={{ height: 560 }}>
        {loading ? <div className="text-slate-500 py-4">{t('logs.loading')}</div>
          : visibleLines.length === 0 ? <div className="text-slate-500 py-4">{search ? t('logs.notFound', { query: search }) : t('logs.noEntries')}</div>
            : visibleLines.map((line, index) => <div key={index} className={logColor(line)}>{line}</div>)}
      </div>
      <p className="text-xs text-slate-400 mt-2">{search ? t('logs.footerFiltered', { filtered: visibleLines.length, total: lines.length, source: sourceLabel(source) }) : t('logs.footer', { total: lines.length, source: sourceLabel(source) })}</p>
    </div>
  )
}

function logColor(s: string): string {
  if (/error|fail|fatal|denied|refused|panic|segfault/i.test(s)) return 'text-red-400'
  if (/warn/i.test(s)) return 'text-amber-400'
  if (/notice|started|listening|active/i.test(s)) return 'text-sky-400'
  return 'text-slate-300'
}

function Card({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
        {right && <div className="text-xs text-slate-500 dark:text-slate-500">{right}</div>}
      </div>
      {children}
    </div>
  )
}
function Snap({ title, value, alt, color }: { title: string; value: string; alt?: string; color: string }) {
  const m: Record<string, string> = {
    indigo: 'border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/20',
    emerald: 'border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20',
    amber: 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20',
    violet: 'border-violet-200 dark:border-violet-800 bg-violet-50 dark:bg-violet-900/20',
  }
  return (
    <div className={`border rounded-2xl p-3 ${m[color]}`}>
      <div className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider">{title}</div>
      <div className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1 font-mono">{value}</div>
      {alt && <div className="text-[11px] text-slate-500 dark:text-slate-500 mt-0.5">{alt}</div>}
    </div>
  )
}
function Legend({ color, label }: { color: string; label: string }) {
  return <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400 dark:text-slate-500"><span className={`w-3 h-3 rounded ${color}`}></span>{label}</span>
}

function MultiSeriesChart({
  dataPoints, series, yMax, suffix,
}: {
  dataPoints: Record<string, number>[]; series: { key: string; color: string }[]; yMax: number; suffix?: string
}) {
  const { t } = useTranslation('MonitoringPage')
  const W = 1000, H = 180, P = 8
  const innerW = W - P * 2, innerH = H - P * 2
  if (dataPoints.length < 2) {
    return <div className="text-xs text-slate-400 dark:text-slate-500 italic py-12 text-center">{t('chart.collecting')}</div>
  }
  function path(key: string) {
    return dataPoints.map((n, i) => {
      const x = P + (innerW * i) / Math.max(1, MAX_DATA_POINTS - 1)
      const v = Math.max(0, Math.min(yMax, n[key] || 0))
      const y = P + innerH - (v / yMax) * innerH
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  }
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[180px]" preserveAspectRatio="none">
      {/* grid */}
      {[0, 25, 50, 75, 100].map(p => {
        const y = P + innerH - (p / 100) * innerH
        return <line key={p} x1={P} y1={y} x2={W - P} y2={y} stroke="#f1f5f9" strokeWidth="1" />
      })}
      {series.map(a => (
        <path key={a.key} d={path(a.key)} stroke={a.color} strokeWidth="2" fill="none" />
      ))}
      {/* Y-axis labels */}
      <text x={P + 2} y={P + 10} fontSize="9" fill="#94a3b8">{yMax.toFixed(0)}{suffix || ''}</text>
      <text x={P + 2} y={H - P + 1} fontSize="9" fill="#94a3b8">0</text>
    </svg>
  )
}

function HealthCard({ h }: { h: Health }) {
  const { t } = useTranslation('MonitoringPage')
  const ok = h.reachable && h.status_code >= 200 && h.status_code < 400
  return (
    <div className={`rounded-2xl p-4 border ${ok ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20' : 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={`w-2.5 h-2.5 rounded-full ${ok ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></span>
        <span className={`text-sm font-semibold ${ok ? 'text-emerald-800 dark:text-emerald-200' : 'text-red-800 dark:text-red-200'}`}>
          {ok ? t('health.reachable') : t('health.unreachable')}
        </span>
      </div>
      <div className="text-3xl font-bold font-mono mt-1">
        {h.status_code > 0 ? h.status_code : '-'}
      </div>
      <div className="text-xs text-slate-600 dark:text-slate-400 dark:text-slate-500 mt-1 truncate" title={h.url}>{h.url}</div>
      {h.error && <div className="mt-2 text-[11px] text-red-700 dark:text-red-300 break-words">{h.error}</div>}
      {h.server && <div className="mt-2 text-[11px] text-slate-500 dark:text-slate-500">{t('health.server')}<span className="font-mono">{h.server}</span></div>}
    </div>
  )
}
function SSLCard({ ssl, scheme }: { ssl?: SSLInfo; scheme: string }) {
  const { t } = useTranslation('MonitoringPage')
  if (scheme !== 'https' || !ssl) {
    return (
      <div className="rounded-2xl p-4 border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20">
        <div className="text-sm font-semibold text-amber-800 dark:text-amber-200 mb-2">{t('health.noSslTitle')}</div>
        <div className="text-xs text-slate-600 dark:text-slate-400 dark:text-slate-500">{t('health.noSslBody')}</div>
      </div>
    )
  }
  const critical = !ssl.valid || ssl.remaining_days < 15
  return (
    <div className={`rounded-2xl p-4 border ${critical ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' : 'border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20'}`}>
      <div className={`text-sm font-semibold mb-2 ${critical ? 'text-red-800 dark:text-red-200' : 'text-emerald-800 dark:text-emerald-200'}`}>
        {ssl.valid ? t('health.sslValid') : t('health.sslInvalid')}
      </div>
      <div className="text-2xl font-bold text-slate-900 dark:text-slate-100 font-mono">{ssl.remaining_days}<span className="text-base ml-1 text-slate-500 dark:text-slate-500">{t('health.days')}</span></div>
      <div className="text-[11px] text-slate-500 dark:text-slate-500 mt-1">{t('health.expires')}<span className="font-mono">{ssl.end_date}</span></div>
      {ssl.issuer && <div className="text-[11px] text-slate-500 dark:text-slate-500">{t('health.issuer')}<span className="font-mono">{ssl.issuer}</span></div>}
    </div>
  )
}
function ResponseCard({ h }: { h: Health }) {
  const { t } = useTranslation('MonitoringPage')
  const ms = h.response_time_ms
  const color = ms < 300 ? 'emerald' : ms < 1000 ? 'amber' : 'red'
  const m: Record<string, string> = {
    emerald: 'border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-800 dark:text-emerald-200',
    amber: 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 text-amber-800 dark:text-amber-200',
    red: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200',
  }
  return (
    <div className={`rounded-2xl p-4 border ${m[color]}`}>
      <div className="text-sm font-semibold mb-2">{t('health.responseTime')}</div>
      <div className="text-3xl font-bold text-slate-900 dark:text-slate-100 font-mono">{ms.toFixed(0)}<span className="text-base ml-1 text-slate-500 dark:text-slate-500">{t('health.ms')}</span></div>
      <div className="text-[11px] text-slate-500 dark:text-slate-500 mt-1">
        {ms < 300 ? t('health.fast') : ms < 1000 ? t('health.acceptable') : t('health.slow')}, {h.scheme.toUpperCase()}
      </div>
    </div>
  )
}

function fmtByte(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + ' MB'
  if (b < 1024 * 1024 * 1024 * 1024) return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB'
  return (b / 1024 / 1024 / 1024 / 1024).toFixed(2) + ' TB'
}