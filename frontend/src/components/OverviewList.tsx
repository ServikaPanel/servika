// Shared shell for the server-wide overview lists (DNS / SSL / Mail /
// Databases). All four do the same thing: fetch one read-only endpoint,
// search, show a table, link each row to the matching domain page. Only the
// column definitions differ, so the shell is shared.
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from './Breadcrumb'
import EmptyState from './EmptyState'
import {
  tableCellClass, tableClass, tableContainerClass, tableHeadCellClass,
} from '@/lib/table'

export type Column<T> = {
  title: string
  cell: (row: T) => React.ReactNode
  className?: string
}

export type Badge = { label: string; value: React.ReactNode; tone?: 'normal' | 'warn' | 'danger' }

const toneClass: Record<NonNullable<Badge['tone']>, string> = {
  normal: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  warn: 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300',
  danger: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
}

export default function OverviewList<T>({
  title, icon, description, endpoint, columns, searchField, rowKey, emptyMessage, summary, refreshKey,
  headerExtra, body,
}: {
  title: string
  icon: ReactNode
  description: string
  endpoint: string
  columns: Column<T>[]
  searchField: (row: T) => string
  rowKey: (row: T) => string | number
  emptyMessage: string
  summary?: (list: T[]) => Badge[]
  // Refetches when the value changes, for a page whose rows carry an action
  // that rewrites them. Because loading is derived from the endpoint rather
  // than stored, a refetch under the same endpoint replaces the rows in place
  // instead of blanking the table behind a spinner. Omitting it keeps the
  // read-only behaviour the other lists rely on.
  refreshKey?: number
  // Rendered directly under the description, for a page that offers more than
  // one view of the same subject. Tabs belong here rather than above the shell,
  // so one breadcrumb and one title serve every tab.
  headerExtra?: React.ReactNode
  // When present, replaces the search box and the table. The shell still owns
  // the breadcrumb, the title and headerExtra, so a second view does not have to
  // rebuild the page header to sit beside the first.
  body?: React.ReactNode
}) {
  const { t } = useTranslation('OverviewList')
  const [list, setList] = useState<T[]>([])
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  // Derived instead of stored: loading means the request for the CURRENT
  // endpoint has not settled, so switching endpoint shows the spinner on the
  // same render rather than one frame of the previous list.
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  const loading = loadedFor !== endpoint

  useEffect(() => {
    let cancelled = false
    api.get<T[]>(endpoint)
      .then((r) => { if (!cancelled) { setList(Array.isArray(r.data) ? r.data : []); setError(null) } })
      .catch((e) => { if (!cancelled) setError(apiError(e, t('errorLoad'))) })
      .finally(() => { if (!cancelled) setLoadedFor(endpoint) })
    return () => { cancelled = true }
  }, [endpoint, refreshKey, t])

  const filtered = useMemo(() => {
    const t = query.trim().toLowerCase()
    if (!t) return list
    return list.filter((s) => searchField(s).toLowerCase().includes(t))
  }, [list, query, searchField])

  const badges = summary && list.length > 0 ? summary(list) : []

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[{ label: t('home'), href: '/' }, { label: title }]} />
      <div className="flex items-center gap-2 mb-1">
        <span className="text-2xl">{icon}</span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{title}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">{description}</p>

      {headerExtra}

      {body !== undefined ? body : (<>

      {badges.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {badges.map((b, i) => (
            <span key={i} className={`px-3 py-1 rounded-full text-xs font-medium ${toneClass[b.tone ?? 'normal']}`}>
              {b.label}: <span className="font-semibold">{b.value}</span>
            </span>
          ))}
        </div>
      )}

      <div className="mb-3">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('searchDomain')}
          className="w-full sm:w-72 px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500/40"
        />
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300 text-sm">{error}</div>
      )}

      {loading ? (
        <div className="py-16 text-center text-sm text-slate-500 dark:text-slate-400">{t('loading')}</div>
      ) : filtered.length === 0 ? (
        <EmptyState title={emptyMessage} description={query ? t('noMatch') : undefined} />
      ) : (
        <div className={tableContainerClass}>
          <table className={tableClass}>
            <thead>
              <tr>
                {columns.map((c, i) => (<th key={i} className={tableHeadCellClass}>{c.title}</th>))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filtered.map((row) => (
                <tr key={rowKey(row)} className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition">
                  {columns.map((c, i) => (
                    <td key={i} className={`${tableCellClass} ${c.className ?? ''}`}>{c.cell(row)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      </>)}
    </div>
  )
}
