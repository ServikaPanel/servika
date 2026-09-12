import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import { useResourceScope } from '@/lib/scope'
import {
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Domain = { id: number; domain_name: string; system_user: string }
type LogFile = { key: string; label: string; path: string; size_b: number; changed: string; current: boolean }
type ReadResp = { file: string; path: string; lines: string[]; current: boolean }

const MAX_WINDOW = 1000

type SSEBlock = { data: string; isError: boolean }

// takeBlocks splits the complete SSE blocks off the front of the buffer and
// returns the partial one that is left. A block with no `data:` line is a
// comment keepalive and is dropped; `event: error` is reported, because the
// server sends it once the headers are out and no status code is left to use.
function takeBlocks(buf: string): { blocks: SSEBlock[]; rest: string } {
  const blocks: SSEBlock[] = []
  let idx
  while ((idx = buf.indexOf('\n\n')) >= 0) {
    const blkLines = buf.slice(0, idx).split('\n')
    buf = buf.slice(idx + 2)
    const data = blkLines.filter(l => l.startsWith('data: ')).map(l => l.slice(6))
    if (data.length === 0) continue
    blocks.push({ data: data.join('\n'), isError: blkLines.some(l => l.startsWith('event: error')) })
  }
  return { blocks, rest: buf }
}

export default function DomainLogsPage() {
  const { t } = useTranslation('DomainLogsPage')
  const report = useReportError()
  const { id, base, isSubdomain, backHref } = useResourceScope()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [files, setFiles] = useState<LogFile[]>([])
  const [activeFile, setActive] = useState<string>('access')
  const [lines, setLines] = useState<string[]>([])
  const [live, setLive] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [view, setView] = useState<'table' | 'raw'>('table')
  const [search, setSearch] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  const errorTab = activeFile === 'error' || activeFile.includes('error')

  // Client-side case-insensitive substring search over raw lines.
  const visibleLines = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return lines
    return lines.filter(l => l.toLowerCase().includes(q))
  }, [lines, search])

  useEffect(() => {
    if (!id) return
    // A subdomain scope reads its own FQDN from the subdomain detail endpoint so the
    // header and log paths name the subdomain instead of its parent.
    const detail = isSubdomain
      ? api.get<{ fqdn: string }>(base).then(r => ({ data: { domain_name: r.data.fqdn } }))
      : api.get<Domain>(`/domains/${id}`)
    detail.then(r => setDomain(r.data as Domain)).catch(report('subscription'))
    api.get<LogFile[]>(`${base}/logs`).then(r => setFiles(r.data)).catch(e => setError(apiError(e)))
  }, [id, base, isSubdomain, report])

  // Load the last N lines when the active file changes. Promise callbacks rather
  // than await/try: this is what the effect below calls, and writes in an awaited
  // body still count as the effect's own continuation.
  const initialLoad = useCallback(() => {
    if (!id || !activeFile) return
    api.get<ReadResp>(`${base}/logs/read`, { params: { file: activeFile, last: 200 } })
      .then(({ data }) => { setLines(data.lines || []); setError(null) })
      .catch(e => setError(apiError(e)))
  }, [id, base, activeFile])

  // Stopped during render rather than in an effect: a tail still bound to the
  // previous file would append its lines to the newly selected one for a frame.
  const tailTarget = `${base}:${activeFile}`
  const [tailedTarget, setTailedTarget] = useState(tailTarget)
  if (tailTarget !== tailedTarget) {
    setTailedTarget(tailTarget)
    setLive(false)
  }

  useEffect(() => { initialLoad() }, [initialLoad])

  // Start or stop live tailing.
  useEffect(() => {
    if (!live || !id) return
    const ctrl = new AbortController()
    abortRef.current = ctrl

    ;(async () => {
      try {
        // Auth via the HttpOnly session cookie (same-origin); no bearer header.
        const res = await fetch(`/api/v1${base}/logs/live?file=${activeFile}`, {
          credentials: 'include',
          signal: ctrl.signal,
        })
        if (!res.ok || !res.body) {
          setError(t('streamFailed', { status: res.status }))
          setLive(false)
          return
        }
        const reader = res.body.getReader()
        const dec = new TextDecoder()
        let buf = ''
        while (true) {
          const { value, done } = await reader.read()
          if (done) {
            // The server closed the stream. Nothing will arrive again, so the
            // screen must stop reporting a live tail.
            setError(t('streamEnded'))
            setLive(false)
            break
          }
          buf += dec.decode(value, { stream: true })
          const { blocks, rest } = takeBlocks(buf)
          buf = rest
          for (const block of blocks) {
            if (block.isError) {
              setError(block.data)
              setLive(false)
              return
            }
            setLines(prev => {
              const next = [...prev, block.data]
              return next.length > MAX_WINDOW ? next.slice(-MAX_WINDOW) : next
            })
          }
        }
      } catch (e) {
        if (e instanceof Error && e.name !== 'AbortError') setError(e.message)
      }
    })()
    return () => ctrl.abort()
  }, [live, activeFile, id, base, t])

  // Automatic scrolling.
  useEffect(() => {
    if (!autoScroll || !scrollRef.current) return
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [lines, autoScroll, view])

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: backHref },
        { label: t('breadcrumb.logs') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && (
        <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
          <Link to={backHref} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
          {', '}
          <span className="font-mono">/var/log/nginx/{domain.domain_name}.*.log</span>
        </p>
      )}

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {/* Tabs */}
      <div className="flex items-center flex-wrap gap-y-2 border-b border-slate-200 dark:border-slate-700 mb-3">
        {files.map(d => (
          <button
            key={d.key}
            onClick={() => setActive(d.key)}
            className={`px-4 py-2.5 text-sm transition border-b-2 -mb-px ${
              activeFile === d.key
                ? 'border-brand-500 text-slate-900 dark:text-slate-100 font-semibold'
                : 'border-transparent text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
          >
            {d.label}
            {d.current && (
              <span className="ml-2 text-[10px] font-mono text-slate-400 dark:text-slate-500">
                {formatSize(d.size_b)}
              </span>
            )}
          </button>
        ))}

        <div className="w-full flex flex-col gap-2 sm:ml-auto sm:w-auto sm:flex-row sm:items-center">
          {/* View toggle */}
          <div className="flex rounded-md border border-slate-200 dark:border-slate-700 overflow-hidden text-xs">
            <button
              onClick={() => setView('table')}
              className={`px-2.5 py-1.5 font-medium transition ${view === 'table' ? 'bg-brand-600 text-white' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
            >{t('view.table')}</button>
            <button
              onClick={() => setView('raw')}
              className={`px-2.5 py-1.5 font-medium transition ${view === 'raw' ? 'bg-brand-600 text-white' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
            >{t('view.raw')}</button>
          </div>

          <label className="text-xs text-slate-500 dark:text-slate-500 flex items-center gap-1.5 select-none cursor-pointer">
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="rounded" />
            {t('autoScroll')}
          </label>
          <button
            onClick={() => {
              if (live) { setLive(false); return }
              setLines([]) // The live tail sends its own initial 200 lines.
              setLive(true)
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition ${
              live
                ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-900/50'
                : 'bg-emerald-600 text-white hover:bg-emerald-700'
            }`}
          >
            {live ? t('stop') : t('liveTail')}
          </button>
          <button
            onClick={initialLoad}
            disabled={live}
            className="px-3 py-1.5 text-xs font-medium bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md transition disabled:opacity-50"
          >
            {t('last200')}
          </button>
          <button
            onClick={() => setLines([])}
            className="px-3 py-1.5 text-xs font-medium bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md transition"
          >
            {t('clear')}
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="flex flex-col gap-2 mb-2 sm:flex-row sm:items-center">
        <div className="relative flex-1 max-w-md">
          <svg className="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z" />
          </svg>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('searchPlaceholder')}
            className="w-full pl-8 pr-8 py-1.5 text-sm bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-800 dark:text-slate-200 placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              aria-label={t('clearSearch')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-lg leading-none"
            >×</button>
          )}
        </div>
        {search && (
          <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
            {t('matches', { visible: visibleLines.length, total: lines.length })}
          </span>
        )}
      </div>

      {/* Log content */}
      <div
        ref={scrollRef}
        className="bg-slate-900 border border-slate-800 rounded-2xl overflow-auto"
        style={{ height: 540 }}
      >
        {lines.length === 0 ? (
          <div className="p-6 text-sm text-slate-500 font-mono">{live ? t('waiting') : t('emptyFile')}</div>
        ) : visibleLines.length === 0 ? (
          <div className="p-6 text-sm text-slate-500 font-mono">{t('noMatch', { search })}</div>
        ) : view === 'raw' ? (
          <div className="p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
            {visibleLines.map((s, i) => (
              <div key={i} className={selectColor(s)}>{s}</div>
            ))}
          </div>
        ) : errorTab ? (
          <ErrorTable lines={visibleLines} />
        ) : (
          <AccessTable lines={visibleLines} />
        )}
      </div>

      <div className="mt-2 text-xs text-slate-500 dark:text-slate-500 flex items-center justify-between">
        <span>{search ? t('linesFiltered', { visible: visibleLines.length, total: lines.length }) : t('lines', { count: lines.length })}{t('windowSuffix', { max: MAX_WINDOW })}</span>
        {live && <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>{t('liveStream')}</span>}
      </div>
    </div>
  )
}

/* ---------------- Access log table ---------------- */

type AccessLine = {
  ip: string; time: string; method: string; path: string; proto: string
  status: number; size: string; referer: string; ua: string; raw: string
}

// nginx "combined": $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua"
const ACCESS_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/

function parseAccess(line: string): AccessLine | null {
  const m = ACCESS_RE.exec(line)
  if (!m) return null
  const req = m[4]
  const parts = req.split(' ')
  let method = '', path = req, proto = ''
  if (parts.length >= 2) {
    method = parts[0]
    proto = parts[parts.length - 1]
    path = parts.slice(1, -1).join(' ') || parts[1]
  }
  return {
    ip: m[1], time: m[3], method, path, proto,
    status: parseInt(m[5], 10), size: m[6], referer: m[7], ua: m[8], raw: line,
  }
}

function AccessTable({ lines }: { lines: string[] }) {
  const { t } = useTranslation('DomainLogsPage')
  const parsedLines = useMemo(() => lines.map(parseAccess), [lines])
  return (
    <table className={`${responsiveTableClass} text-xs`}>
      <thead className={`${responsiveTableHeadClass} sticky top-0 z-10 bg-slate-900/95 backdrop-blur text-slate-500 border-b border-slate-800`}>
        <tr>
          <th className="text-left font-medium px-3 py-2 whitespace-nowrap">{t('access.time')}</th>
          <th className="text-left font-medium px-3 py-2 whitespace-nowrap">{t('access.ip')}</th>
          <th className="text-left font-medium px-3 py-2">{t('access.method')}</th>
          <th className="text-left font-medium px-3 py-2 w-full">{t('access.path')}</th>
          <th className="text-left font-medium px-3 py-2">{t('access.status')}</th>
          <th className="text-right font-medium px-3 py-2 whitespace-nowrap">{t('access.size')}</th>
          <th className="text-left font-medium px-3 py-2">{t('access.browser')}</th>
        </tr>
      </thead>
      <tbody className={`${responsiveTableBodyClass} divide-slate-800/70`}>
        {lines.map((raw, i) => {
          const r = parsedLines[i]
          if (!r) {
            return (
              <tr key={i} className={responsiveTableRowClass}>
                <td colSpan={7} className="px-3 py-1.5 font-mono text-slate-500 break-all">{raw}</td>
              </tr>
            )
          }
          return (
            <tr key={i} className={`${responsiveTableRowClass} hover:bg-slate-800/40`}>
              <td data-label={t('access.time')} className={`${responsiveTableCodeCellClass} text-slate-400 lg:whitespace-nowrap`}>{shortTime(r.time)}</td>
              <td data-label={t('access.ip')} className={`${responsiveTableCodeCellClass} text-slate-300 lg:whitespace-nowrap`}>{r.ip}</td>
              <td data-label={t('access.method')} className={responsiveTableCellClass}>
                <span className={`inline-block px-1.5 py-0.5 rounded font-mono font-semibold text-[10px] ${methodColor(r.method)}`}>{r.method || '-'}</span>
              </td>
              <td data-label={t('access.path')} className={`${responsiveTableCodeCellClass} text-slate-200 break-all lg:max-w-0`}>
                <div className="lg:truncate" title={r.referer && r.referer !== '-' ? `${r.path}\n← ${r.referer}` : r.path}>{r.path}</div>
              </td>
              <td data-label={t('access.status')} className={responsiveTableCellClass}>
                <span className={`inline-block px-1.5 py-0.5 rounded font-mono font-semibold text-[10px] ${statusColor(r.status)}`}>{r.status}</span>
              </td>
              <td data-label={t('access.size')} className={`${responsiveTableCodeCellClass} text-slate-400 lg:text-right lg:whitespace-nowrap`}>{formatByteString(r.size)}</td>
              <td data-label={t('access.browser')} className={`${responsiveTableCellClass} text-slate-400 lg:max-w-[220px]`}>
                <div className="lg:truncate" title={r.ua}>{shortUserAgent(r.ua)}</div>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ---------------- Error log table ---------------- */

// 2026/07/03 22:40:31 [error] 12345#0: *67 message, client: 1.2.3.4, server: ...
const ERROR_RE = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$/
const CLIENT_RE = /client: (\S+?)[,\s]/

function ErrorTable({ lines }: { lines: string[] }) {
  const { t } = useTranslation('DomainLogsPage')
  return (
    <table className={`${responsiveTableClass} text-xs`}>
      <thead className={`${responsiveTableHeadClass} sticky top-0 z-10 bg-slate-900/95 backdrop-blur text-slate-500 border-b border-slate-800`}>
        <tr>
          <th className="text-left font-medium px-3 py-2 whitespace-nowrap">{t('error.time')}</th>
          <th className="text-left font-medium px-3 py-2">{t('error.level')}</th>
          <th className="text-left font-medium px-3 py-2 whitespace-nowrap">{t('error.client')}</th>
          <th className="text-left font-medium px-3 py-2 w-full">{t('error.message')}</th>
        </tr>
      </thead>
      <tbody className={`${responsiveTableBodyClass} divide-slate-800/70`}>
        {lines.map((raw, i) => {
          const m = ERROR_RE.exec(raw)
          if (!m) {
            return (
              <tr key={i} className={responsiveTableRowClass}>
                <td colSpan={4} className="px-3 py-1.5 font-mono text-slate-500 break-all">{raw}</td>
              </tr>
            )
          }
          const cm = CLIENT_RE.exec(m[3])
          const client = cm ? cm[1] : ''
          return (
            <tr key={i} className={`${responsiveTableRowClass} hover:bg-slate-800/40`}>
              <td data-label={t('error.time')} className={`${responsiveTableCodeCellClass} text-slate-400 lg:whitespace-nowrap`}>{m[1].slice(5)}</td>
              <td data-label={t('error.level')} className={responsiveTableCellClass}>
                <span className={`inline-block px-1.5 py-0.5 rounded font-mono font-semibold text-[10px] ${levelColor(m[2])}`}>{m[2]}</span>
              </td>
              <td data-label={t('error.client')} className={`${responsiveTableCodeCellClass} text-slate-300 lg:whitespace-nowrap`}>{client || '-'}</td>
              <td data-label={t('error.message')} className={`${responsiveTableCodeCellClass} text-slate-200 break-all lg:max-w-0`}>
                <div className="lg:truncate" title={m[3]}>{m[3]}</div>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ---------------- Helpers ---------------- */

function methodColor(m: string): string {
  switch (m) {
    case 'GET': return 'bg-slate-700 text-slate-200'
    case 'POST': return 'bg-sky-900/70 text-sky-200'
    case 'PUT':
    case 'PATCH': return 'bg-amber-900/70 text-amber-200'
    case 'DELETE': return 'bg-red-900/70 text-red-200'
    case 'HEAD':
    case 'OPTIONS': return 'bg-slate-700/60 text-slate-300'
    default: return 'bg-slate-800 text-slate-400'
  }
}

function statusColor(s: number): string {
  if (s >= 500) return 'bg-red-900/70 text-red-200'
  if (s >= 400) return 'bg-amber-900/70 text-amber-200'
  if (s >= 300) return 'bg-sky-900/70 text-sky-200'
  if (s >= 200) return 'bg-emerald-900/70 text-emerald-200'
  return 'bg-slate-700 text-slate-300'
}

function levelColor(s: string): string {
  const l = s.toLowerCase()
  if (l === 'emerg' || l === 'alert' || l === 'crit' || l === 'error') return 'bg-red-900/70 text-red-200'
  if (l === 'warn') return 'bg-amber-900/70 text-amber-200'
  if (l === 'notice') return 'bg-sky-900/70 text-sky-200'
  return 'bg-slate-700 text-slate-300'
}

// 03/Jul/2026:22:40:31 +0000  ->  03/Jul 22:40:31
function shortTime(z: string): string {
  const m = /^(\d{2})\/(\w{3})\/\d{4}:(\d{2}:\d{2}:\d{2})/.exec(z)
  return m ? `${m[1]}/${m[2]} ${m[3]}` : z
}

function formatByteString(b: string): string {
  const n = parseInt(b, 10)
  if (isNaN(n)) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

// Reduce the user agent to a short, readable summary.
function shortUserAgent(ua: string): string {
  if (!ua || ua === '-') return '-'
  const bot = /(bot|crawl|spider|zgrab|curl|wget|python|go-http|scan|nikto|masscan)/i.exec(ua)
  if (bot) return `🤖 ${bot[1]}`
  let os = ''
  if (/Windows NT 10/.test(ua)) os = 'Windows'
  else if (/Mac OS X/.test(ua)) os = 'macOS'
  else if (/iPhone|iPad/.test(ua)) os = 'iOS'
  else if (/Android/.test(ua)) os = 'Android'
  else if (/Linux/.test(ua)) os = 'Linux'
  let browser = ''
  if (/Edg\//.test(ua)) browser = 'Edge'
  else if (/Chrome\//.test(ua)) browser = 'Chrome'
  else if (/Firefox\//.test(ua)) browser = 'Firefox'
  else if (/Safari\//.test(ua)) browser = 'Safari'
  const parts = [browser, os].filter(Boolean)
  return parts.length ? parts.join(', ') : ua.slice(0, 40)
}

function selectColor(s: string): string {
  // Raw-view coloring.
  if (/\s5\d\d\s/.test(s)) return 'text-red-400'
  if (/\s4\d\d\s/.test(s)) return 'text-amber-400'
  if (/\[error\]|\[crit\]|\[emerg\]|\[alert\]/i.test(s)) return 'text-red-400'
  if (/\[warn\]/i.test(s)) return 'text-amber-400'
  if (/\[notice\]/i.test(s)) return 'text-sky-400'
  return 'text-slate-300'
}

function formatSize(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}
