// Request log — the readable face of request_logs. Every /api/v1 call is
// recorded with its redacted body, so a support question can be answered from
// the panel instead of from a MySQL client on the host.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import EmptyState from '@/components/EmptyState'

type Entry = {
  id: number
  ts: string
  request_id: string
  user_id: number
  username: string
  ip: string
  user_agent: string
  method: string
  endpoint: string
  module: string
  action: string
  query_params: string
  request_body: string
  response_status: number
  response_ms: number
  error_message: string
}

// Status colouring by class, not by code: the panel answers with codes this
// screen has never seen, and a 4xx it does not know is still a 4xx.
function statusClass(status: number): string {
  if (status >= 500) return 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300'
  if (status >= 400) return 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300'
  if (status >= 300) return 'bg-sky-50 text-sky-700 dark:bg-sky-900/20 dark:text-sky-300'
  return 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300'
}

const STATUS_FILTERS = ['', '200', '400', '401', '403', '404', '500']

export default function RequestLogPage() {
  const { t } = useTranslation('RequestLogPage')
  const [list, setList] = useState<Entry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  const [status, setStatus] = useState('')
  const [method, setMethod] = useState('')
  const [limit, setLimit] = useState(200)
  const [query, setQuery] = useState('')

  // Derived instead of stored: loading means the request for the CURRENT filter
  // combination has not settled, so changing a filter shows the spinner on the
  // same render rather than one frame of the previous result set.
  const filterKey = `${status}|${method}|${limit}`
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  const loading = loadedFor !== filterKey

  useEffect(() => {
    let cancelled = false
    const p = new URLSearchParams()
    p.set('limit', String(limit))
    if (status) p.set('status', status)
    if (method) p.set('method', method)
    api.get<Entry[]>(`/system/request-logs?${p.toString()}`)
      .then((r) => { if (!cancelled) { setList(Array.isArray(r.data) ? r.data : []); setError(null) } })
      .catch((e) => { if (!cancelled) setError(apiError(e, t('errors.loadFailed'))) })
      .finally(() => { if (!cancelled) setLoadedFor(filterKey) })
    return () => { cancelled = true }
  }, [status, method, limit, filterKey, t])

  // Search is client-side: the server filters by status and method, free text
  // (endpoint, user, ip, request id) is matched over the already-fetched page.
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return list
    return list.filter((k) =>
      `${k.username} ${k.ip} ${k.endpoint} ${k.request_id} ${k.module}`.toLowerCase().includes(q))
  }, [list, query])

  const failed = list.filter((k) => k.response_status >= 400).length

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
          {failed > 0 && (
            <div className="px-3 py-2 rounded-lg border border-red-200 bg-red-50 text-red-700 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-300 text-sm">
              <span className="font-semibold">{failed}</span> <span className="opacity-75">{t('stats.failed')}</span>
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
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          <option value="">{t('filters.allMethods')}</option>
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          {STATUS_FILTERS.map((s) => (
            <option key={s || 'all'} value={s}>{s || t('filters.allStatuses')}</option>
          ))}
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
                {['time', 'status', 'method', 'endpoint', 'user', 'ip', 'duration'].map((b) => (
                  <th key={b} className="px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {t(`columns.${b}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-950">
              {filtered.map((k) => (
                <RequestRow
                  key={k.id}
                  entry={k}
                  open={expanded === k.id}
                  onToggle={() => setExpanded(expanded === k.id ? null : k.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// RequestRow renders one row, and its detail when opened. The detail carries the
// correlation id and the redacted body, which is what makes a row worth reading
// after the fact.
function RequestRow({ entry, open, onToggle }: { entry: Entry; open: boolean; onToggle: () => void }) {
  const { t } = useTranslation('RequestLogPage')
  return (
    <>
      <tr className="hover:bg-slate-50 dark:hover:bg-slate-900/60 transition cursor-pointer" onClick={onToggle}>
        <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{entry.ts}</td>
        <td className="px-3 py-2 whitespace-nowrap">
          <span className={`px-2 py-0.5 rounded text-xs ${statusClass(entry.response_status)}`}>{entry.response_status}</span>
        </td>
        <td className="px-3 py-2 whitespace-nowrap font-mono text-xs">{entry.method}</td>
        <td className="px-3 py-2 text-slate-600 dark:text-slate-400 font-mono text-xs">{entry.endpoint}</td>
        <td className="px-3 py-2 whitespace-nowrap">{entry.username || <span className="text-slate-400">—</span>}</td>
        <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{entry.ip || '—'}</td>
        <td className="px-3 py-2 whitespace-nowrap text-xs text-slate-500">{entry.response_ms} ms</td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/40">
          <td colSpan={7} className="px-3 py-3">
            <dl className="grid gap-2 text-xs sm:grid-cols-2">
              <Detail label={t('detail.requestId')} value={entry.request_id} />
              <Detail label={t('detail.userAgent')} value={entry.user_agent} />
              <Detail label={t('detail.module')} value={[entry.module, entry.action].filter(Boolean).join(' / ')} />
              <Detail label={t('detail.error')} value={entry.error_message} />
              <Detail label={t('detail.queryParams')} value={entry.query_params} />
              <Detail label={t('detail.body')} value={entry.request_body} />
            </dl>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">{t('detail.redacted')}</p>
          </td>
        </tr>
      )}
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-semibold text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="font-mono break-all text-slate-700 dark:text-slate-300">{value || '—'}</dd>
    </div>
  )
}
