import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import SecurityFindingsTable, { type SecurityFinding } from '@/components/SecurityFindingsTable'
import SecurityInventoryTable, { type SecurityApp } from '@/components/SecurityInventoryTable'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'

type ScanStatus = {
  state: string
  started_at: string
  finished_at: string
  scanned_domains: number
  scanned_packages: number
  unparsed_packages: number
  finding_count: number
  last_error: string
}

type Inventory = {
  total: number
  items: SecurityApp[]
  unscanned_domains: string[]
}

/** Renders known vulnerabilities across every site this account can see. */
export default function WebsiteSecurityPage() {
  const { t } = useTranslation('SiteSecurity')
  const role = useAuth(state => state.username?.role)
  const [findings, setFindings] = useState<SecurityFinding[]>([])
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [inventory, setInventory] = useState<Inventory | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const poll = useRef<ReturnType<typeof setInterval> | null>(null)

  const isAdmin = role === 'admin'

  // Writes only from the promise callbacks, so the mount effect never sets
  // state synchronously.
  const load = useCallback(() => {
    api.get<SecurityFinding[]>('/admin/site-security')
      .then(response => setFindings(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.load'))))
      .finally(() => setLoading(false))
    api.get<ScanStatus>('/admin/site-security/status')
      .then(response => setStatus(response.data))
      .catch(() => setStatus(null))
    api.get<Inventory>('/admin/site-security/apps')
      .then(response => setInventory(response.data))
      .catch(cause => setError(apiError(cause, t('errors.inventory'))))
  }, [t])

  useEffect(() => { load() }, [load])

  // One effect owns the polling, so it starts and stops with the running state
  // rather than being restarted by every loader call.
  useEffect(() => {
    if (status?.state !== 'running') {
      if (poll.current) {
        clearInterval(poll.current)
        poll.current = null
      }
      return
    }
    if (poll.current) return
    poll.current = setInterval(load, 10000)
    return () => {
      if (poll.current) {
        clearInterval(poll.current)
        poll.current = null
      }
    }
  }, [status?.state, load])

  async function startScan() {
    setError(null)
    setStarting(true)
    try {
      await api.post('/admin/site-security/scan')
      load()
    } catch (cause) {
      setError(apiError(cause, '') === 'security_scan_already_running'
        ? t('errors.alreadyRunning')
        : apiError(cause, t('errors.scan')))
    } finally {
      setStarting(false)
    }
  }

  const needle = filter.trim().toLowerCase()
  const visible = needle
    ? findings.filter(finding =>
      finding.domain_name.toLowerCase().includes(needle) ||
      finding.package_name.toLowerCase().includes(needle) ||
      finding.cve_id.toLowerCase().includes(needle))
    : findings

  const running = status?.state === 'running'

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.current') },
      ]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      <div className="mb-5 rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/40">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">{t('status.title')}</h2>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">
              {status ? t(`status.state.${status.state}`, { defaultValue: status.state }) : t('status.unknown')}
              {status?.finished_at ? ` · ${t('status.finishedAt')}: ${status.finished_at}` : ''}
            </p>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={startScan}
              disabled={starting || running}
              className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
            >
              {running ? t('status.running') : starting ? t('status.starting') : t('status.scanNow')}
            </button>
          )}
        </div>

        {status && (
          <div className="mt-3 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
            <div><span className="text-slate-500 dark:text-slate-500">{t('status.domains')}</span><div className="font-medium text-slate-800 dark:text-slate-200">{status.scanned_domains}</div></div>
            <div><span className="text-slate-500 dark:text-slate-500">{t('status.packages')}</span><div className="font-medium text-slate-800 dark:text-slate-200">{status.scanned_packages}</div></div>
            <div><span className="text-slate-500 dark:text-slate-500">{t('status.findings')}</span><div className="font-medium text-slate-800 dark:text-slate-200">{status.finding_count}</div></div>
            <div><span className="text-slate-500 dark:text-slate-500">{t('status.unparsed')}</span><div className="font-medium text-slate-800 dark:text-slate-200">{status.unparsed_packages}</div></div>
          </div>
        )}

        {/* A sweep that could not judge some versions is not a clean one, so the
            screen says so instead of leaving the number in a corner. */}
        {status && status.unparsed_packages > 0 && (
          <p className="mt-3 text-xs text-amber-700 dark:text-amber-300">{t('status.unparsedNote')}</p>
        )}
        {status?.state === 'failed' && (
          <p className="mt-3 text-xs text-red-700 dark:text-red-300">
            {t('status.failedNote')}{status.last_error ? ` ${status.last_error}` : ''}
          </p>
        )}
      </div>

      <div className="mb-3 flex items-center justify-between gap-3">
        <input
          type="search"
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder={t('filterPlaceholder')}
          className="w-full max-w-xs rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-800 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
        />
        <span className="text-xs text-slate-500 dark:text-slate-500">{t('shown')}: {visible.length}</span>
      </div>

      <SecurityFindingsTable findings={visible} loading={loading} showDomain />

      <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('advisoryNote')}</p>

      {/* An empty findings list above says nothing on its own: it reads the same
          whether every site is clean or nothing was ever looked at. This section
          is what tells the two apart, so it is drawn even when the list is
          empty, never only when something was found. */}
      <div className="mt-8">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">{t('inventory.title')}</h2>
          <span className="text-xs text-slate-500 dark:text-slate-500">{t('shown')}: {inventory?.total ?? 0}</span>
        </div>
        <p className="mb-3 text-xs text-slate-500 dark:text-slate-500">{t('inventory.note')}</p>
        <SecurityInventoryTable apps={inventory?.items || []} loading={loading} />

        {inventory && inventory.unscanned_domains.length > 0 && (
          <div className="mt-4 rounded-2xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-900/20">
            <h3 className="text-sm font-semibold text-amber-800 dark:text-amber-200">
              {t('inventory.unscanned')} ({inventory.unscanned_domains.length})
            </h3>
            <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">{t('inventory.unscannedNote')}</p>
            <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-amber-900 dark:text-amber-100">
              {inventory.unscanned_domains.map(name => <li key={name} className="font-mono">{name}</li>)}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}
