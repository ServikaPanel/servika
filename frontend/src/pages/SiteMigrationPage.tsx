import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import { getCookie, setCookie } from '@/lib/cookies'
import {
  responsiveTableBodyClass, responsiveTableCellClass, responsiveTableClass,
  responsiveTableContainerClass, responsiveTableHeadClass, responsiveTableRowClass,
  tableHeadCellClass,
} from '@/lib/table'

/*
 * Site Migration — end-to-end import from cPanel / Plesk / DirectAdmin.
 * Three-step wizard:
 *   1) Source server details + control panel + connection test
 *   2) Site list (single/bulk) + ownership + migration settings
 *   3) Migration — live status, ETA, and the domain being migrated
 * The job runs on the server, so it continues even if this page is closed.
 */

type RemoteAccount = {
  source_account: string; domain_name: string; web_root: string; php_version: string
  databases: string[] | null; size_mb: number; note: string; exists: boolean
}
type MigrationItem = {
  id: number; source_account: string; domain_name: string
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped'
  domain_id: number; file_bytes: number; db_count: number; dns_count: number; error_text: string
}
type MigrationJob = {
  id: number; type: string; host: string; mode: string; status: string
  total: number; completed: number; failed: number; started_by: string; created_at: string
}
type Plan = { id: number; name: string }
type Customer = { id: number; name: string }
type SavedSession = {
  id: number; type: string; host: string; port: number; user: string
  credentials_stored: boolean; last_used: string
}

const PANELS = ['plesk', 'cpanel', 'directadmin']
const PHP_VERSIONS = ['', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4']

// The non-secret source fields survive a page reload. The password and the
// private key are NEVER stored in the browser.
const SOURCE_COOKIE = 'servika.migration.source'
type StoredSource = { type?: string; host?: string; port?: number; user?: string; auth?: 'password' | 'key' }

function readStoredSource(): StoredSource {
  try {
    const raw = getCookie(SOURCE_COOKIE)
    return raw ? JSON.parse(raw) : {}
  } catch { return {} }
}

const inputCls =
  'w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 ' +
  'placeholder:text-slate-400 transition focus:border-brand-400 focus:outline-none focus:ring-2 ' +
  'focus:ring-brand-500/15 disabled:cursor-not-allowed disabled:opacity-60 ' +
  'dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-100'
const labelCls = 'mb-1.5 block text-xs font-medium text-slate-500 dark:text-slate-400'
const selectCls =
  'rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-brand-400 ' +
  'focus:outline-none focus:ring-2 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-100'
const btnPrimary =
  'inline-flex items-center justify-center gap-2 rounded-full bg-slate-900 px-5 py-2.5 text-sm font-medium ' +
  'text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40 ' +
  'dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100'
const btnSecondary =
  'inline-flex items-center justify-center gap-2 rounded-full border border-slate-200 px-4 py-2.5 text-sm ' +
  'font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40 ' +
  'dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800'
const btnSmall =
  'inline-flex items-center gap-1.5 rounded-full border border-slate-200 px-3 py-1.5 text-xs font-medium ' +
  'text-slate-600 transition hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'

function Icon({ d }: { d: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
      strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4"><path d={d} /></svg>
  )
}
const ICON = {
  check: 'M20 6 9 17l-5-5',
  files: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
  db: 'M4 6c0-1.66 3.58-3 8-3s8 1.34 8 3-3.58 3-8 3-8-1.34-8-3M4 6v12c0 1.66 3.58 3 8 3s8-1.34 8-3V6M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3',
  dns: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20M2 12h20M12 2c2.5 2.7 3.9 6.3 4 10-.1 3.7-1.5 7.3-4 10-2.5-2.7-3.9-6.3-4-10 .1-3.7 1.5-7.3 4-10',
  ssl: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10M9 12l2 2 4-4',
  overwrite: 'M3 6h18M3 12h18M3 18h18',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  forward: 'M5 12h14M13 6l6 6-6 6',
  back: 'M19 12H5M11 18l-6-6 6-6',
  warning: 'M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  clock: 'M12 6v6l4 2M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20',
  panel: 'M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83zM2 12.5l8.58 3.91a2 2 0 0 0 1.66 0L21 12.5M2 17l8.58 3.91a2 2 0 0 0 1.66 0L21 17',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 0 0 0-8 4 4 0 0 0 0 8z',
  lock: 'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4',
  hash: 'M4 9h16M4 15h16M10 3 8 21M16 3l-2 18',
  key: 'M2.6 17.4A2 2 0 0 0 2 18.8V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 0 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 0 1-1h.2a2 2 0 0 0 1.4-.6l.8-.8a6.5 6.5 0 1 0-4-4z',
  eye: 'M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  eyeOff: 'M9.9 9.9a3 3 0 1 0 4.2 4.2M10.7 5.1A11 11 0 0 1 12 5c7 0 10 7 10 7a13 13 0 0 1-1.7 2.7M6.6 6.6A13 13 0 0 0 2 12s3 7 10 7a11 11 0 0 0 5.4-1.4M2 2l20 20',
}

function Card({ children }: { children: ReactNode }) {
  return (
    <section className="rounded-2xl border border-slate-200/70 bg-white p-5 sm:p-6 dark:border-slate-700/60 dark:bg-slate-800/40">
      {children}
    </section>
  )
}

export default function SiteMigrationPage() {
  const { t } = useTranslation('SiteMigrationPage')
  const report = useReportError()
  const stored = useMemo(() => readStoredSource(), [])

  // --- source server ---
  const [type, setType] = useState(stored.type && PANELS.includes(stored.type) ? stored.type : 'plesk')
  const [host, setHost] = useState(stored.host || '')
  const [port, setPort] = useState(stored.port || 22)
  const [user, setUser] = useState(stored.user || 'root')
  const [authMode, setAuthMode] = useState<'password' | 'key'>(stored.auth === 'key' ? 'key' : 'password')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  // --- flow ---
  const [step, setStep] = useState(1)
  const [testResult, setTestResult] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [discovering, setDiscovering] = useState(false)
  const [accounts, setAccounts] = useState<RemoteAccount[] | null>(null)
  const [selected, setSelected] = useState<Record<string, boolean>>({})
  const [error, setError] = useState<string | null>(null)

  // --- resumable session ---
  // A discovery result is saved on the server (2 h TTL) so a reload resumes it
  // without re-entering the credentials. sessionID carries the current one;
  // credsStored means the stored password can start the job with no re-typing.
  const [sessionID, setSessionID] = useState(0)
  const [credsStored, setCredsStored] = useState(false)
  const [savedSessions, setSavedSessions] = useState<SavedSession[]>([])

  // --- settings ---
  const [withFiles, setWithFiles] = useState(true)
  const [withDatabases, setWithDatabases] = useState(true)
  const [withDNS, setWithDNS] = useState(true)
  const [withSSL, setWithSSL] = useState(true)
  const [overwrite, setOverwrite] = useState(false)
  const [targetPHP, setTargetPHP] = useState('')
  const [plans, setPlans] = useState<Plan[]>([])
  const [planID, setPlanID] = useState(0)
  const [customers, setCustomers] = useState<Customer[]>([])
  const [customerID, setCustomerID] = useState(0)

  // --- running job ---
  const [jobID, setJobID] = useState<number | null>(null)
  const [running, setRunning] = useState(false)
  const [logText, setLogText] = useState('')
  const [items, setItems] = useState<MigrationItem[]>([])
  const [summary, setSummary] = useState({ total: 0, completed: 0, failed: 0, status: '' })
  const [history, setHistory] = useState<MigrationJob[]>([])
  const logRef = useRef<HTMLPreElement>(null)
  // State rather than a ref: the elapsed time and the ETA are rendered, and a
  // ref read during render would not re-render when the clock moves.
  const [startedAt, setStartedAt] = useState<number | null>(null) // start time in ms
  const [nowMS, setNowMS] = useState(() => Date.now())

  const sourceBody = useCallback(() => ({
    type, host: host.trim(), port: Number(port) || 22, user: user.trim(),
    password: authMode === 'password' ? password : '',
    key: authMode === 'key' ? privateKey : '',
  }), [type, host, port, user, authMode, password, privateKey])

  // Promise callbacks rather than await/try: the mount effect below calls this,
  // and writes in an awaited body still count as the effect's own continuation.
  const loadJobs = useCallback(() =>
    api.get<{ jobs: MigrationJob[]; active_job: number }>('/admin/migrations')
      .then(({ data }) => {
        setHistory(data.jobs || [])
        if (data.active_job > 0) {
          setJobID(data.active_job); setRunning(true); setStep(3)
          // Read outside the updater: a state updater must stay pure, and the
          // resumed job's start time is unknown, so the clock starts now.
          const resumedAt = Date.now()
          setStartedAt(current => current ?? resumedAt)
          setNowMS(resumedAt)
        }
      })
      .catch(() => { /* the panel may be restarting */ }),
  [])

  useEffect(() => { loadJobs() }, [loadJobs])

  // Promise callback, not await: this runs from a mount effect, so it must
  // settle only through the promise so it is not a synchronous setState.
  const loadSessions = useCallback(() =>
    api.get<SavedSession[]>('/admin/migrations/sessions')
      .then(({ data }) => setSavedSessions(data || []))
      .catch(() => { /* no resumable sessions is a normal state */ }),
  [])

  useEffect(() => { loadSessions() }, [loadSessions])

  // Continue a saved session: restore the form and the discovered sites without
  // re-entering the credentials. The password stays empty; the server decrypts
  // the stored one at start when session_id is sent.
  function resumeSession(id: number) {
    setError(null)
    api.get<{
      type: string; host: string; port: number; user: string
      credentials_stored: boolean; accounts: RemoteAccount[]
    }>(`/admin/migrations/sessions/${id}`)
      .then(({ data }) => {
        if (PANELS.includes(data.type)) setType(data.type)
        setHost(data.host); setPort(data.port); setUser(data.user)
        setPassword(''); setPrivateKey('')
        const list = data.accounts || []
        setAccounts(list)
        setSelected(Object.fromEntries(list.map(a => [a.domain_name, !a.exists])))
        setSessionID(id)
        setCredsStored(data.credentials_stored)
        setStep(list.length > 0 ? 2 : 1)
      })
      .catch(e => setError(apiError(e, t('errors.resumeFailed'))))
  }

  function forgetSession(id: number) {
    api.delete(`/admin/migrations/sessions/${id}`)
      .then(() => loadSessions())
      .catch(e => setError(apiError(e, t('errors.forgetFailed'))))
  }

  // Advance the clock only while a job runs, so a finished job's elapsed time
  // and ETA stop where they ended instead of creeping up on unrelated renders.
  useEffect(() => {
    if (!running) return
    const timer = window.setInterval(() => setNowMS(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [running])

  // Remember the non-secret source fields (never the password or the key).
  useEffect(() => {
    setCookie(SOURCE_COOKIE,
      JSON.stringify({ type, host, port, user, auth: authMode }), 60 * 60 * 24 * 30)
  }, [type, host, port, user, authMode])

  useEffect(() => {
    api.get<Plan[]>('/plans').then(r => setPlans(r.data || [])).catch(report('plans'))
    api.get<Customer[]>('/customers').then(r => setCustomers(r.data || [])).catch(report('customers'))
  }, [report])

  // Follow the running job (2 s polling).
  useEffect(() => {
    if (!jobID) return
    let stopped = false
    const tick = async () => {
      try {
        const [logRes, detailRes] = await Promise.all([
          api.get<{ log: string; running: boolean; status: string }>(`/admin/migrations/${jobID}/log`),
          api.get<{ items: MigrationItem[]; status: string; total: number; completed: number; failed: number }>(`/admin/migrations/${jobID}`),
        ])
        if (stopped) return
        setLogText(logRes.data.log || '')
        setItems(detailRes.data.items || [])
        setSummary({
          total: detailRes.data.total, completed: detailRes.data.completed,
          failed: detailRes.data.failed, status: detailRes.data.status,
        })
        if (!logRes.data.running) { setRunning(false); loadJobs() }
      } catch { /* transient error — swallow */ }
    }
    tick()
    const timer = running ? window.setInterval(tick, 2000) : 0
    return () => { stopped = true; if (timer) window.clearInterval(timer) }
  }, [jobID, running, loadJobs])

  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }) }, [logText])

  function formatMB(n: number) {
    if (!n) return '—'
    return n < 1024 ? `${n} MB` : `${(n / 1024).toFixed(1)} GB`
  }
  function formatBytes(n: number) {
    if (!n) return '—'
    const mb = n / (1024 * 1024)
    return mb < 1024 ? `${mb.toFixed(1)} MB` : `${(mb / 1024).toFixed(2)} GB`
  }
  function formatDuration(seconds: number) {
    if (!isFinite(seconds) || seconds <= 0) return '—'
    const minutes = Math.floor(seconds / 60)
    const rest = Math.round(seconds % 60)
    return minutes > 0 ? t('duration.minutesSeconds', { m: minutes, s: rest }) : t('duration.seconds', { s: rest })
  }
  function statusLabel(status: string) {
    return t(`status.${status}`, { defaultValue: status })
  }

  // --- actions ---
  async function testConnection() {
    setTesting(true); setError(null); setTestResult(null)
    try {
      const { data } = await api.post<{ server_name: string; detected: string; matches: boolean }>(
        '/admin/migrations/test', sourceBody())
      const base = t('step1.testOk', {
        server: data.server_name || t('step1.unknownServer'),
        panel: data.detected || t('step1.unknownPanel'),
      })
      setTestResult(data.matches ? base : `${base} ${t('step1.panelMismatch')}`)
    } catch (e) { setError(apiError(e, t('errors.testFailed'))) } finally { setTesting(false) }
  }

  async function discover() {
    setDiscovering(true); setError(null); setAccounts(null)
    try {
      const { data } = await api.post<{ accounts: RemoteAccount[]; session_id: number }>('/admin/migrations/discover', sourceBody())
      const list = data.accounts || []
      setAccounts(list)
      setSelected(Object.fromEntries(list.map(a => [a.domain_name, !a.exists])))
      // Fresh credentials were just typed; the new session holds them.
      setSessionID(data.session_id || 0)
      setCredsStored(false)
      loadSessions()
      if (list.length === 0) setError(t('errors.noSitesFound'))
      else setStep(2)
    } catch (e) { setError(apiError(e, t('errors.discoveryFailed'))) } finally { setDiscovering(false) }
  }

  async function start() {
    const picked = (accounts || []).filter(a => selected[a.domain_name])
    if (picked.length === 0) { setError(t('errors.selectAtLeastOne')); return }
    setError(null)
    try {
      const { data } = await api.post<{ job_id: number }>('/admin/migrations', {
        ...sourceBody(),
        session_id: sessionID,
        mode: picked.length === 1 ? 'single' : 'bulk',
        settings: {
          files: withFiles, databases: withDatabases, dns: withDNS, ssl: withSSL,
          overwrite, target_php: targetPHP, plan_id: planID, customer_id: customerID, accounts: [],
        },
        selected: picked,
      })
      const startNow = Date.now()
      setStartedAt(startNow); setNowMS(startNow)
      setJobID(data.job_id); setRunning(true); setLogText(''); setItems([]); setStep(3)
      // The server consumed the session at start; drop it from the resume list.
      setSessionID(0); setCredsStored(false); loadSessions()
    } catch (e) { setError(apiError(e, t('errors.startFailed'))) }
  }

  async function cancel() {
    if (!jobID) return
    try { await api.post(`/admin/migrations/${jobID}/cancel`, {}) }
    catch (e) { setError(apiError(e, t('errors.cancelFailed'))) }
  }

  function newMigration() {
    setJobID(null); setRunning(false); setItems([]); setLogText('')
    setSummary({ total: 0, completed: 0, failed: 0, status: '' })
    setStartedAt(null)
    setSessionID(0); setCredsStored(false); loadSessions()
    setStep(accounts && accounts.length > 0 ? 2 : 1)
  }

  // Retry — restart the same selection. The session was CONSUMED at the first
  // start (deleted server-side), so retry reuses the credentials still held in
  // this page's state. With no selection, or no credentials to send (a resumed
  // session whose password was never typed here), fall back to the form.
  async function retry() {
    const hasCreds = authMode === 'password' ? !!password : !!privateKey
    const hasSelection = !!(accounts && accounts.length) && selectedCount > 0
    if (!hasSelection || !hasCreds) {
      setStep(hasCreds && accounts && accounts.length ? 2 : 1)
      return
    }
    setJobID(null); setRunning(false); setItems([]); setLogText('')
    setSummary({ total: 0, completed: 0, failed: 0, status: '' })
    setStartedAt(null)
    await start()
  }

  const selectedCount = (accounts || []).filter(a => selected[a.domain_name]).length
  const finishedCount = summary.completed + summary.failed
  const percent = summary.total > 0 ? Math.round((finishedCount / summary.total) * 100) : 0
  const elapsed = startedAt ? Math.max(0, (nowMS - startedAt) / 1000) : 0
  const eta = running && finishedCount > 0 && startedAt
    ? (elapsed / finishedCount) * (summary.total - finishedCount) : 0
  const activeItem = items.find(i => i.status === 'running')
  const canOpenStep = (n: number) =>
    n === 1 || (n === 2 && !!(accounts && accounts.length > 0)) || (n === 3 && !!jobID)

  const toggles: [string, boolean, (v: boolean) => void, string][] = [
    ['files', withFiles, setWithFiles, ICON.files],
    ['databases', withDatabases, setWithDatabases, ICON.db],
    ['dns', withDNS, setWithDNS, ICON.dns],
    ['ssl', withSSL, setWithSSL, ICON.ssl],
    ['overwrite', overwrite, setOverwrite, ICON.overwrite],
  ]

  const stepTitles = [t('steps.source'), t('steps.sitesAndSettings'), t('steps.migration')]

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-6">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.siteMigration') },
      ]} />

      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-500 dark:text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Stepper */}
      <div className="mb-6 flex items-center">
        {stepTitles.map((title, i) => {
          const n = i + 1
          const state = n < step ? 'done' : n === step ? 'active' : 'todo'
          const open = canOpenStep(n)
          return (
            <div key={title} className={`flex items-center ${n < 3 ? 'flex-1' : ''}`}>
              <button type="button" disabled={!open} onClick={() => open && setStep(n)}
                className="flex items-center gap-2.5 disabled:cursor-default">
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-semibold transition ${
                  state === 'done' ? 'bg-emerald-500 text-white'
                  : state === 'active' ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
                  : 'bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500'}`}>
                  {state === 'done' ? <Icon d={ICON.check} /> : n}
                </span>
                <span className={`hidden text-sm font-medium sm:block ${state === 'todo' ? 'text-slate-400 dark:text-slate-500' : 'text-slate-800 dark:text-slate-100'}`}>{title}</span>
              </button>
              {n < 3 && <span className={`mx-3 h-px flex-1 ${n < step ? 'bg-emerald-400' : 'bg-slate-200 dark:bg-slate-700'}`} />}
            </div>
          )
        })}
      </div>

      {error && (
        <div className="mb-5 flex items-start gap-2.5 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800/60 dark:bg-red-900/20 dark:text-red-300">
          <span className="mt-0.5 shrink-0"><Icon d={ICON.warning} /></span>
          <span className="min-w-0 break-words">{error}</span>
        </div>
      )}

      {/* Resume banner — a saved discovery can be continued without re-typing. */}
      {step === 1 && !jobID && savedSessions.length > 0 && (
        <div className="mb-5 rounded-2xl border border-brand-200 bg-brand-50 px-4 py-3 dark:border-brand-800/60 dark:bg-brand-900/20">
          <div className="flex items-center gap-2 text-sm font-medium text-brand-800 dark:text-brand-200">
            <Icon d={ICON.clock} />
            <span>{t('resume.title')}</span>
          </div>
          <ul className="mt-2.5 space-y-2">
            {savedSessions.map(s => (
              <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-white/70 px-3 py-2 dark:bg-slate-800/50">
                <span className="min-w-0 break-words text-sm text-slate-700 dark:text-slate-200">
                  <span className="font-medium">{t(`panels.${s.type}`, { defaultValue: s.type })}</span>
                  {' · '}{s.user}@{s.host}
                  {s.credentials_stored && (
                    <span className="ml-2 rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">{t('resume.credentialsStored')}</span>
                  )}
                </span>
                <span className="flex shrink-0 items-center gap-2">
                  <button type="button" onClick={() => resumeSession(s.id)} className={btnSmall}>
                    <Icon d={ICON.forward} />{t('resume.continue')}
                  </button>
                  <button type="button" onClick={() => forgetSession(s.id)} className={btnSmall}>{t('resume.forget')}</button>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ==================== STEP 1 — source ==================== */}
      {step === 1 && (
        <div className="space-y-5">
          <Card>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('step1.title')}</h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{t('step1.description')}</p>
            <div className="mt-5 grid max-w-4xl gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-6">
              <label className="block lg:col-span-2">
                <span className={labelCls}>{t('step1.panel')}</span>
                <div className="relative">
                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.panel} /></span>
                  <select value={type} onChange={e => setType(e.target.value)} className={inputCls + ' pl-9'}>
                    {PANELS.map(p => <option key={p} value={p}>{t(`panels.${p}`)}</option>)}
                  </select>
                </div>
              </label>
              <label className="block sm:col-span-2 lg:col-span-3">
                <span className={labelCls}>{t('step1.host')}</span>
                <div className="relative">
                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.server} /></span>
                  <input value={host} onChange={e => setHost(e.target.value)} placeholder={t('step1.hostPlaceholder')} className={inputCls + ' pl-9'} />
                </div>
              </label>
              <label className="block lg:col-span-1">
                <span className={labelCls}>{t('step1.port')}</span>
                <div className="relative">
                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.hash} /></span>
                  <input type="number" value={port} onChange={e => setPort(Number(e.target.value))} className={inputCls + ' pl-9'} />
                </div>
              </label>
              <label className="block lg:col-span-2">
                <span className={labelCls}>{t('step1.user')}</span>
                <div className="relative">
                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.user} /></span>
                  <input value={user} onChange={e => setUser(e.target.value)} placeholder="root" className={inputCls + ' pl-9'} />
                </div>
              </label>
              <label className="block lg:col-span-2">
                <span className={labelCls}>{t('step1.auth')}</span>
                <div className="relative">
                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.key} /></span>
                  <select value={authMode} onChange={e => setAuthMode(e.target.value as 'password' | 'key')} className={inputCls + ' pl-9'}>
                    <option value="password">{t('step1.authPassword')}</option>
                    <option value="key">{t('step1.authKey')}</option>
                  </select>
                </div>
              </label>
              {authMode === 'password' ? (
                <label className="block lg:col-span-2">
                  <span className={labelCls}>{t('step1.password')}</span>
                  <div className="relative">
                    <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><Icon d={ICON.lock} /></span>
                    <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                      autoComplete="new-password" placeholder="********" className={inputCls + ' pl-9 pr-10'} />
                    <button type="button" onClick={() => setShowPassword(v => !v)}
                      title={showPassword ? t('step1.hide') : t('step1.show')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-0.5 text-slate-400 transition hover:text-slate-600 dark:hover:text-slate-200">
                      <Icon d={showPassword ? ICON.eyeOff : ICON.eye} />
                    </button>
                  </div>
                </label>
              ) : (
                <label className="block sm:col-span-2 lg:col-span-4">
                  <span className={labelCls}>{t('step1.privateKey')}</span>
                  <textarea value={privateKey} onChange={e => setPrivateKey(e.target.value)} rows={3}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" className={`${inputCls} font-mono text-xs`} />
                </label>
              )}
            </div>

            <div className="mt-4 inline-flex items-center gap-1.5 rounded-full bg-slate-50 px-3 py-1.5 text-[11px] font-medium text-slate-500 dark:bg-slate-800/60 dark:text-slate-400">
              <span className="text-emerald-500"><Icon d={ICON.ssl} /></span>
              {t('step1.credentialNote')}
            </div>

            {testResult && (
              <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-900/20 dark:text-emerald-300">
                <span className="mt-0.5 shrink-0"><Icon d={ICON.check} /></span>
                <span className="min-w-0 break-words">{testResult}</span>
              </div>
            )}

            <div className="mt-5 flex flex-wrap gap-2.5">
              <button type="button" onClick={testConnection} disabled={testing || !host} className={btnSecondary}>
                {testing ? t('step1.testing') : t('step1.testButton')}
              </button>
              <button type="button" onClick={discover} disabled={discovering || !host} className={btnPrimary}>
                <Icon d={ICON.server} />{discovering ? t('step1.discovering') : t('step1.discoverButton')}
              </button>
            </div>
          </Card>

          {history.length > 0 && (
            <HistoryCard history={history} statusLabel={statusLabel} onSelect={job => {
              setJobID(job.id); setRunning(job.status === 'running')
              const openedAt = Date.now()
              setStartedAt(current => current ?? openedAt)
              setNowMS(openedAt)
              setStep(3)
            }} />
          )}
        </div>
      )}

      {/* ==================== STEP 2 — sites + settings ==================== */}
      {step === 2 && accounts && (
        <div className="space-y-5">
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('step2.title')}</h2>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {t('step2.foundCount', { n: accounts.length, selected: selectedCount })}
                </p>
              </div>
              <div className="flex gap-2">
                <button type="button" className={btnSmall}
                  onClick={() => setSelected(Object.fromEntries(accounts.map(a => [a.domain_name, true])))}>
                  {t('step2.selectAll')}
                </button>
                <button type="button" className={btnSmall} onClick={() => setSelected({})}>{t('step2.clear')}</button>
              </div>
            </div>
            <div className={`mt-4 ${responsiveTableContainerClass}`}>
              <table className={responsiveTableClass}>
                <thead className={responsiveTableHeadClass}>
                  <tr>
                    <th className={tableHeadCellClass}>{t('step2.columns.select')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.domain')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.sourceAccount')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.php')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.size')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.databases')}</th>
                    <th className={tableHeadCellClass}>{t('step2.columns.state')}</th>
                  </tr>
                </thead>
                <tbody className={responsiveTableBodyClass}>
                  {accounts.map(a => {
                    const picked = !!selected[a.domain_name]
                    return (
                      <tr key={`${a.source_account}|${a.domain_name}`}
                        onClick={() => setSelected(s => ({ ...s, [a.domain_name]: !picked }))}
                        className={`${responsiveTableRowClass} cursor-pointer ${picked ? 'bg-brand-50/30 dark:bg-brand-900/10' : ''}`}>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.select')}>
                          <input type="checkbox" checked={picked} onClick={e => e.stopPropagation()}
                            onChange={e => setSelected(s => ({ ...s, [a.domain_name]: e.target.checked }))}
                            className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-brand-500/30 dark:border-slate-600 dark:bg-slate-800" />
                        </td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.domain')}>
                          <span className="font-medium text-slate-800 dark:text-slate-100">{a.domain_name}</span>
                          {a.note && <span className="ml-1.5 text-[11px] text-slate-400">({a.note})</span>}
                        </td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.sourceAccount')}>{a.source_account || '—'}</td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.php')}>{a.php_version || '—'}</td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.size')}>{formatMB(a.size_mb)}</td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.databases')}>{a.databases?.length || 0}</td>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.state')}>
                          {a.exists
                            ? <span className="inline-flex rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-300">{t('step2.alreadyExists')}</span>
                            : <span className="inline-flex rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">{t('step2.new')}</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>

          <Card>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('step2.settingsTitle')}</h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{t('step2.settingsDescription')}</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {toggles.map(([key, value, setValue, icon]) => (
                <button key={key} type="button" onClick={() => setValue(!value)}
                  className={`flex items-start gap-3 rounded-2xl border p-3.5 text-left transition ${
                    value ? 'border-slate-900/15 bg-slate-50 dark:border-white/15 dark:bg-slate-800/70'
                    : 'border-slate-200/70 hover:border-slate-300 dark:border-slate-700/60 dark:hover:border-slate-600'}`}>
                  <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition ${
                    value ? 'border-slate-900 bg-slate-900 text-white dark:border-white dark:bg-white dark:text-slate-900'
                    : 'border-slate-300 text-transparent dark:border-slate-600'}`}>
                    <Icon d={ICON.check} />
                  </span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-1.5 text-sm font-medium text-slate-800 dark:text-slate-100">
                      <span className="text-slate-400 dark:text-slate-500"><Icon d={icon} /></span>{t(`toggles.${key}.label`)}
                    </span>
                    <span className="mt-0.5 block text-[11px] leading-relaxed text-slate-400 dark:text-slate-500">{t(`toggles.${key}.hint`)}</span>
                  </span>
                </button>
              ))}
              <SelectCard label={t('step2.targetPHP')}>
                <select value={targetPHP} onChange={e => setTargetPHP(e.target.value)} className={selectCls}>
                  {PHP_VERSIONS.map(v => <option key={v} value={v}>{v || t('step2.sameAsSource')}</option>)}
                </select>
              </SelectCard>
              <SelectCard label={t('step2.plan')}>
                <select value={planID} onChange={e => setPlanID(Number(e.target.value))} className={selectCls}>
                  <option value={0}>{t('step2.noPlan')}</option>
                  {plans.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </SelectCard>
              <SelectCard label={t('step2.customer')}>
                <select value={customerID} onChange={e => setCustomerID(Number(e.target.value))} className={selectCls}>
                  <option value={0}>{t('step2.noCustomer')}</option>
                  {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </SelectCard>
            </div>

            {overwrite && (
              <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-xs text-amber-700 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-300">
                <span className="mt-0.5 shrink-0"><Icon d={ICON.warning} /></span>
                <span>{t('step2.overwriteWarning')}</span>
              </div>
            )}

            {credsStored && (
              <div className="mt-4 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-900/20 dark:text-emerald-300">
                <span className="mt-0.5 shrink-0"><Icon d={ICON.lock} /></span>
                <span>{t('resume.usingStored')}</span>
              </div>
            )}

            <div className="mt-5 flex flex-wrap items-center justify-between gap-2.5">
              <button type="button" onClick={() => setStep(1)} className={btnSecondary}>
                <Icon d={ICON.back} />{t('common.back')}
              </button>
              <button type="button" onClick={start} disabled={!selectedCount} className={btnPrimary}>
                <Icon d={ICON.forward} />{t('step2.startButton', { n: selectedCount })}
              </button>
            </div>
          </Card>
        </div>
      )}

      {/* ==================== STEP 3 — live migration ==================== */}
      {step === 3 && jobID && (
        <div className="space-y-5">
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('step3.title', { id: jobID })}</h2>
                <StatusBadge status={running ? 'running' : (summary.status || 'pending')} label={statusLabel} />
              </div>
              {running
                ? <button type="button" onClick={cancel}
                    className="inline-flex items-center gap-1.5 rounded-full border border-red-200 px-3.5 py-1.5 text-xs font-medium text-red-700 transition hover:bg-red-50 dark:border-red-800/60 dark:text-red-300 dark:hover:bg-red-900/20">
                    {t('step3.stop')}
                  </button>
                : <div className="flex items-center gap-2">
                    {accounts && accounts.length > 0 && (
                      <button type="button" onClick={retry} className={btnSmall}>{t('step3.retry')}</button>
                    )}
                    <button type="button" onClick={newMigration} className={btnSmall}>{t('step3.newMigration')}</button>
                  </div>}
            </div>

            {running && (
              <div className="mt-4 flex flex-wrap items-center gap-4 rounded-2xl border border-brand-200/60 bg-brand-50/50 px-4 py-3 dark:border-brand-800/40 dark:bg-brand-900/10">
                <span className="h-3 w-3 shrink-0 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
                <div className="min-w-0 flex-1">
                  <div className="text-[11px] font-medium uppercase tracking-wide text-brand-600 dark:text-brand-400">{t('step3.nowMigrating')}</div>
                  <div className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">{activeItem?.domain_name || t('step3.preparing')}</div>
                </div>
                <div className="text-right">
                  <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-400 dark:text-slate-500">
                    <Icon d={ICON.clock} />{t('step3.eta')}
                  </div>
                  <div className="text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">{formatDuration(eta)}</div>
                </div>
              </div>
            )}

            {summary.total > 0 && (
              <div className="mt-4">
                <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <StatTile label={t('step3.stats.total')} value={summary.total} tone="text-slate-900 dark:text-slate-100" />
                  <StatTile label={t('step3.stats.completed')} value={summary.completed} tone="text-emerald-600 dark:text-emerald-400" />
                  <StatTile label={t('step3.stats.failed')} value={summary.failed}
                    tone={summary.failed ? 'text-red-600 dark:text-red-400' : 'text-slate-400'} />
                  <StatTile label={t('step3.stats.elapsed')} value={formatDuration(elapsed)} tone="text-slate-900 dark:text-slate-100" />
                </div>
                <div className="mb-1.5 flex justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>{t('step3.progress', { done: finishedCount, total: summary.total })}</span>
                  <span className="tabular-nums">{percent}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                  <div className="h-full rounded-full bg-brand-500 transition-all duration-500" style={{ width: `${percent}%` }} />
                </div>
              </div>
            )}

            {items.length > 0 && (
              <div className={`mt-5 ${responsiveTableContainerClass}`}>
                <table className={responsiveTableClass}>
                  <thead className={responsiveTableHeadClass}>
                    <tr>
                      <th className={tableHeadCellClass}>{t('step2.columns.domain')}</th>
                      <th className={tableHeadCellClass}>{t('step3.columns.status')}</th>
                      <th className={tableHeadCellClass}>{t('step3.columns.files')}</th>
                      <th className={tableHeadCellClass}>{t('step3.columns.db')}</th>
                      <th className={tableHeadCellClass}>{t('step3.columns.dns')}</th>
                      <th className={tableHeadCellClass}>{t('step3.columns.note')}</th>
                    </tr>
                  </thead>
                  <tbody className={responsiveTableBodyClass}>
                    {items.map(item => (
                      <tr key={item.id} className={`${responsiveTableRowClass} ${item.status === 'running' ? 'bg-brand-50/40 dark:bg-brand-900/10' : ''}`}>
                        <td className={responsiveTableCellClass} data-label={t('step2.columns.domain')}>
                          <span className="font-medium text-slate-800 dark:text-slate-100">{item.domain_name}</span>
                        </td>
                        <td className={responsiveTableCellClass} data-label={t('step3.columns.status')}>
                          <StatusBadge status={item.status} label={statusLabel} />
                        </td>
                        <td className={responsiveTableCellClass} data-label={t('step3.columns.files')}>{formatBytes(item.file_bytes)}</td>
                        <td className={responsiveTableCellClass} data-label={t('step3.columns.db')}>{item.db_count || '—'}</td>
                        <td className={responsiveTableCellClass} data-label={t('step3.columns.dns')}>{item.dns_count || '—'}</td>
                        <td className={responsiveTableCellClass} data-label={t('step3.columns.note')}>
                          <span className="text-[11px] text-slate-500 dark:text-slate-400">{item.error_text || '—'}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <pre ref={logRef} className="mt-5 max-h-72 overflow-auto whitespace-pre-wrap rounded-xl bg-slate-950 p-3.5 font-mono text-[11px] leading-relaxed text-slate-300 ring-1 ring-slate-800">
              {logText || t('step3.waitingForLog')}
            </pre>
          </Card>

          {history.length > 0 && (
            <HistoryCard history={history} statusLabel={statusLabel} onSelect={job => {
              setJobID(job.id); setRunning(job.status === 'running')
            }} />
          )}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status, label }: { status: string; label: (s: string) => string }) {
  const tone =
    status === 'done' ? 'border-emerald-200 text-emerald-700 bg-emerald-50 dark:border-emerald-800/60 dark:text-emerald-300 dark:bg-emerald-900/20'
    : status === 'failed' ? 'border-red-200 text-red-700 bg-red-50 dark:border-red-800/60 dark:text-red-300 dark:bg-red-900/20'
    : status === 'running' ? 'border-brand-200 text-brand-700 bg-brand-50 dark:border-brand-800/60 dark:text-brand-300 dark:bg-brand-900/20'
    : 'border-slate-200 text-slate-600 bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:bg-slate-800'
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${tone}`}>
      {status === 'running' && <span className="h-2.5 w-2.5 shrink-0 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />}
      {label(status)}
    </span>
  )
}

function StatTile({ label, value, tone }: { label: string; value: ReactNode; tone: string }) {
  return (
    <div className="rounded-2xl bg-slate-50 px-3.5 py-3 dark:bg-slate-900/40">
      <div className="text-[11px] font-medium uppercase tracking-wide text-slate-400 dark:text-slate-500">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  )
}

function SelectCard({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-2xl border border-slate-200/70 p-3.5 dark:border-slate-700/60">
      <span className="text-sm font-medium text-slate-800 dark:text-slate-100">{label}</span>
      {children}
    </div>
  )
}

function HistoryCard({ history, statusLabel, onSelect }: {
  history: MigrationJob[]; statusLabel: (s: string) => string; onSelect: (job: MigrationJob) => void
}) {
  const { t } = useTranslation('SiteMigrationPage')
  return (
    <Card>
      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('history.title')}</h2>
      <div className={`mt-4 ${responsiveTableContainerClass}`}>
        <table className={responsiveTableClass}>
          <thead className={responsiveTableHeadClass}>
            <tr>
              <th className={tableHeadCellClass}>#</th>
              <th className={tableHeadCellClass}>{t('history.columns.source')}</th>
              <th className={tableHeadCellClass}>{t('history.columns.panel')}</th>
              <th className={tableHeadCellClass}>{t('history.columns.status')}</th>
              <th className={tableHeadCellClass}>{t('history.columns.result')}</th>
              <th className={tableHeadCellClass}>{t('history.columns.startedBy')}</th>
            </tr>
          </thead>
          <tbody className={responsiveTableBodyClass}>
            {history.map(job => (
              <tr key={job.id} className={`${responsiveTableRowClass} cursor-pointer`} onClick={() => onSelect(job)}>
                <td className={responsiveTableCellClass} data-label="#">{job.id}</td>
                <td className={responsiveTableCellClass} data-label={t('history.columns.source')}>{job.host}</td>
                <td className={responsiveTableCellClass} data-label={t('history.columns.panel')}>{t(`panels.${job.type}`, { defaultValue: job.type })}</td>
                <td className={responsiveTableCellClass} data-label={t('history.columns.status')}>
                  <StatusBadge status={job.status} label={statusLabel} />
                </td>
                <td className={responsiveTableCellClass} data-label={t('history.columns.result')}>
                  {job.completed}/{job.total}{job.failed ? ` (${t('history.failedSuffix', { n: job.failed })})` : ''}
                </td>
                <td className={responsiveTableCellClass} data-label={t('history.columns.startedBy')}>{job.started_by || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
