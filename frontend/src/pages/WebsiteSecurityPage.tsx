import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
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

type DomainRow = {
  domain_id: number
  domain_name: string
  app_type: string
  install_path: string
  app_version: string
  package_count: number
  finding_count: number
  last_scanned: string
  status: 'scanning' | 'open' | 'clean' | 'no_app' | 'pending'
}

const badgeClass: Record<DomainRow['status'], string> = {
  scanning: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 animate-pulse',
  open: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  clean: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  no_app: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
  pending: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
}

/** Renders every domain on the server with the status of its last security scan. */
export default function WebsiteSecurityPage() {
  const { t } = useTranslation('SiteSecurity')
  const navigate = useNavigate()
  const role = useAuth(state => state.username?.role)
  const [domains, setDomains] = useState<DomainRow[]>([])
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [scanningRow, setScanningRow] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const poll = useRef<ReturnType<typeof setInterval> | null>(null)

  const isAdmin = role === 'admin'

  // Writes only from the promise callbacks, so the mount effect never sets
  // state synchronously.
  const load = useCallback(() => {
    api.get<DomainRow[]>('/admin/site-security/domains')
      .then(response => setDomains(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.load'))))
      .finally(() => setLoading(false))
    api.get<ScanStatus>('/admin/site-security/status')
      .then(response => setStatus(response.data))
      .catch(() => setStatus(null))
  }, [t])

  useEffect(() => { load() }, [load])

  // One effect owns the polling, so it starts and stops with the running state
  // rather than being restarted by every loader call. It refreshes the domain
  // rows too, so a "scanning" badge clears when the scan finishes.
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

  const running = status?.state === 'running'

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

  async function scanRow(domainID: number) {
    setError(null)
    setScanningRow(domainID)
    try {
      await api.post(`/admin/site-security/domain/${domainID}/scan`)
      load()
    } catch (cause) {
      setError(apiError(cause, '') === 'security_scan_already_running'
        ? t('errors.alreadyRunning')
        : apiError(cause, t('errors.scan')))
    } finally {
      setScanningRow(null)
    }
  }

  const needle = filter.trim().toLowerCase()
  const visible = needle
    ? domains.filter(row => row.domain_name.toLowerCase().includes(needle))
    : domains

  const appLabel = (row: DomainRow) => {
    if (!row.app_type) return t('domainTable.none')
    const type = t(`appType.${row.app_type}`, { defaultValue: row.app_type })
    return row.app_version ? `${type} ${row.app_version}` : type
  }

  const badgeLabel = (row: DomainRow) =>
    row.status === 'open'
      ? t('badge.open', { n: row.finding_count })
      : t(`badge.${row.status}`)

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

      <p className="mb-3 text-xs text-slate-500 dark:text-slate-500">{t('domainTable.note')}</p>

      <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-50 text-slate-600 dark:bg-slate-900/60 dark:text-slate-400">
            <tr>
              <th className="px-3 py-2 text-left">{t('domainTable.domain')}</th>
              <th className="px-3 py-2 text-left">{t('domainTable.app')}</th>
              <th className="px-3 py-2 text-left">{t('domainTable.findings')}</th>
              <th className="px-3 py-2 text-left">{t('domainTable.lastScanned')}</th>
              <th className="px-3 py-2 text-left">{t('domainTable.status')}</th>
              <th className="px-3 py-2 text-right">{t('domainTable.actions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {loading && (
              <tr><td className="px-3 py-6 text-center text-slate-500 dark:text-slate-500" colSpan={6}>{t('table.loading')}</td></tr>
            )}
            {!loading && visible.length === 0 && (
              <tr><td className="px-3 py-6 text-center text-slate-500 dark:text-slate-500" colSpan={6}>{t('domainTable.empty')}</td></tr>
            )}
            {!loading && visible.map(row => (
              <tr
                key={`${row.domain_id}-${row.install_path}`}
                onClick={() => navigate(`/site-security/domain/${row.domain_id}`)}
                className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-900/40"
              >
                <td className="px-3 py-2 font-medium text-slate-800 dark:text-slate-200">{row.domain_name}</td>
                <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{appLabel(row)}</td>
                <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{row.app_type ? row.finding_count : t('domainTable.none')}</td>
                <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{row.last_scanned || t('domainTable.none')}</td>
                <td className="px-3 py-2">
                  <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${badgeClass[row.status]}`}>
                    {badgeLabel(row)}
                  </span>
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    onClick={event => { event.stopPropagation(); scanRow(row.domain_id) }}
                    disabled={running || scanningRow !== null || row.status === 'scanning'}
                    className="rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-800"
                  >
                    {scanningRow === row.domain_id || row.status === 'scanning' ? t('domainTable.scanning') : t('domainTable.scan')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('advisoryNote')}</p>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('scheduleNote')}</p>
    </div>
  )
}
