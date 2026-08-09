// The slowest query shapes, shared by the admin's server-wide tab and by a site
// owner's performance page. One component so the twenty-odd labels are written
// once rather than twice, and so both screens rank and explain the same way.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import EmptyState from './EmptyState'
import {
  responsiveTableBodyClass, responsiveTableCellClass, responsiveTableClass,
  responsiveTableContainerClass, responsiveTableHeadClass, responsiveTableRowClass,
} from '@/lib/table'

export type SlowQueryRow = {
  domain_id?: number
  domain_name?: string
  db_user: string
  schema_name: string
  digest: string
  normalized_sql: string
  calls: number
  total_time_ms: number
  avg_time_ms: number
  max_time_ms: number
  lock_time_ms: number
  rows_sent: number
  rows_examined: number
  full_scan_calls: number
  first_seen: string
  last_seen: string
}

// The windows a reader can ask for. Hours rather than a date picker: the
// question is always "what has been happening", never "what happened on the
// fourteenth". Not exported, so this file exports only its component and Fast
// Refresh keeps working.
const WINDOWS = [1, 6, 24, 24 * 7] as const

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  const minutes = Math.floor(ms / 60_000)
  const seconds = Math.round((ms % 60_000) / 1000)
  return `${minutes} m ${seconds} s`
}

function formatCount(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`
  return `${(n / 1_000_000).toFixed(1)}M`
}

export default function SlowQueryTable({
  endpoint, showDomain = false, errorContext = 'slowQueries',
}: {
  /** Either /admin/slow-queries or /domains/:id/slow-queries. */
  endpoint: string
  /** The server-wide view names the tenant; a site owner's does not need to. */
  showDomain?: boolean
  errorContext?: string
}) {
  const { t } = useTranslation('SlowQueryTable')
  const report = useReportError()
  const [rows, setRows] = useState<SlowQueryRow[]>([])
  const [hours, setHours] = useState<number>(24)
  // Derived rather than stored: loading means the request for the CURRENT
  // endpoint and window has not settled, so a change shows the spinner on the
  // same render instead of one frame of the previous rows.
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const key = `${endpoint}?${hours}`
  const loading = loadedKey !== key

  useEffect(() => {
    let cancelled = false
    api.get<SlowQueryRow[]>(endpoint, { params: { hours } })
      .then(r => { if (!cancelled) setRows(r.data) })
      .catch(caught => { if (!cancelled) { setRows([]); report(errorContext)(caught) } })
      .finally(() => { if (!cancelled) setLoadedKey(`${endpoint}?${hours}`) })
    return () => { cancelled = true }
  }, [endpoint, hours, report, errorContext])

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-500 dark:text-slate-400">{t('window.label')}</span>
        <div className="inline-flex rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800">
          {WINDOWS.map(value => (
            <button
              key={value}
              type="button"
              onClick={() => setHours(value)}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                hours === value
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                  : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              {value < 24 ? t('window.hours', { count: value }) : t('window.days', { count: value / 24 })}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-slate-400 dark:text-slate-500">{t('ranking')}</span>
      </div>

      {loading && <div className="py-6 text-sm text-slate-400">{t('loading')}</div>}

      {!loading && rows.length === 0 && (
        <EmptyState title={t('empty.title')} description={t('empty.description')} />
      )}

      {!loading && rows.length > 0 && (
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                {showDomain && <th className="px-4 py-2.5 font-semibold">{t('column.domain')}</th>}
                <th className="px-4 py-2.5 font-semibold">{t('column.query')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.calls')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.total')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.average')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.max')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.examined')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {rows.map(row => (
                <tr key={`${row.digest}-${row.db_user}`} className={responsiveTableRowClass}>
                  {showDomain && (
                    <td className={responsiveTableCellClass} data-label={t('column.domain')}>
                      {row.domain_id ? (
                        <Link to={`/subscriptions/${row.domain_id}/performance`}
                          className="font-medium text-slate-900 transition hover:text-brand-600 dark:text-slate-100 dark:hover:text-brand-400">
                          {row.domain_name}
                        </Link>
                      ) : (
                        <span className="text-slate-400" title={t('system.hint')}>{t('system.label')}</span>
                      )}
                      <div className="font-mono text-xs text-slate-400">{row.db_user}</div>
                    </td>
                  )}
                  <td className={responsiveTableCellClass} data-label={t('column.query')}>
                    <code className="block max-w-xl break-all font-mono text-xs text-slate-700 dark:text-slate-300">
                      {row.normalized_sql}
                    </code>
                    {row.full_scan_calls > 0 && (
                      <span className="mt-1 inline-block rounded bg-amber-50 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                        {t('badge.fullScan')}
                      </span>
                    )}
                  </td>
                  <td className={responsiveTableCellClass} data-label={t('column.calls')}>{formatCount(row.calls)}</td>
                  <td className={responsiveTableCellClass} data-label={t('column.total')}>
                    <span className="font-medium text-slate-900 dark:text-slate-100">{formatDuration(row.total_time_ms)}</span>
                  </td>
                  <td className={responsiveTableCellClass} data-label={t('column.average')}>{formatDuration(row.avg_time_ms)}</td>
                  <td className={responsiveTableCellClass} data-label={t('column.max')}>{formatDuration(row.max_time_ms)}</td>
                  <td className={responsiveTableCellClass} data-label={t('column.examined')}>
                    {formatCount(row.rows_examined)}
                    <div className="text-xs text-slate-400">{t('returned', { count: row.rows_sent })}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-xs text-slate-400 dark:text-slate-500">{t('privacy')}</p>
    </div>
  )
}
