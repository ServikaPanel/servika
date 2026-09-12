// Application log — the readable face of app_logs. The same lines journald
// holds, kept in a table so an operator can read the panel's own failures
// without an SSH session.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import EmptyState from '@/components/EmptyState'

type Entry = {
  id: number
  ts: string
  level: string
  logger_name: string
  message: string
  context: string
  request_id: string
}

const LEVELS = ['INFO', 'WARN', 'ERROR']

function levelClass(level: string): string {
  if (level === 'ERROR') return 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300'
  if (level === 'WARN') return 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300'
  return 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
}

export default function AppLogPage() {
  const { t } = useTranslation('AppLogPage')
  const [list, setList] = useState<Entry[]>([])
  const [error, setError] = useState<string | null>(null)

  const [level, setLevel] = useState('')
  const [limit, setLimit] = useState(200)
  const [query, setQuery] = useState('')

  // Derived instead of stored, for the same reason as the request log: a filter
  // change shows the spinner on the same render.
  const filterKey = `${level}|${limit}`
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  const loading = loadedFor !== filterKey

  useEffect(() => {
    let cancelled = false
    const p = new URLSearchParams()
    p.set('limit', String(limit))
    if (level) p.set('level', level)
    api.get<Entry[]>(`/system/app-logs?${p.toString()}`)
      .then((r) => { if (!cancelled) { setList(Array.isArray(r.data) ? r.data : []); setError(null) } })
      .catch((e) => { if (!cancelled) setError(apiError(e, t('errors.loadFailed'))) })
      .finally(() => { if (!cancelled) setLoadedFor(filterKey) })
    return () => { cancelled = true }
  }, [level, limit, filterKey, t])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return list
    return list.filter((k) =>
      `${k.message} ${k.logger_name} ${k.request_id}`.toLowerCase().includes(q))
  }, [list, query])

  const errors = list.filter((k) => k.level === 'ERROR').length

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('title') }]} />

      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('subtitle')}</p>
      </div>

      {list.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          <div className="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-700 dark:text-slate-300">
            <span className="font-semibold">{list.length}</span> <span className="opacity-75">{t('stats.entries')}</span>
          </div>
          {errors > 0 && (
            <div className="px-3 py-2 rounded-lg border border-red-200 bg-red-50 text-red-700 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-300 text-sm">
              <span className="font-semibold">{errors}</span> <span className="opacity-75">{t('stats.errors')}</span>
            </div>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('searchPlaceholder')}
          className="w-full sm:w-64 px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-brand-500"
        />
        <select
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          <option value="">{t('filters.allLevels')}</option>
          {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          {[100, 200, 500, 1000].map((n) => <option key={n} value={n}>{t('filters.last', { n })}</option>)}
        </select>
      </div>

      {error && (
        <div className="mb-4 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm">{error}</div>
      )}

      {loading ? (
        <div className="py-16 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : list.length === 0 && !error ? (
        <EmptyState title={t('empty.title')} description={t('empty.description')} />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-sm text-slate-400">{t('noMatch')}</div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60">
              <tr>
                {['time', 'level', 'logger', 'message', 'requestId'].map((b) => (
                  <th key={b} className="px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {t(`columns.${b}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-950">
              {filtered.map((k) => (
                <tr key={k.id} className="hover:bg-slate-50 dark:hover:bg-slate-900/60 transition align-top">
                  <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{k.ts}</td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-xs ${levelClass(k.level)}`}>{k.level}</span>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{k.logger_name || '—'}</td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-300 break-all">{k.message}</td>
                  <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{k.request_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
