import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError } from '@/lib/api'

type Event = {
  source: string
  stage: string
  stage_name: string
  level: string
  summary: string
  time: string
}
type Chain = {
  id: number
  domain_id: number | null
  domain: string
  stages: string[]
  stage_names: string[]
  confidence: number
  level: string
  time: string
  events: Event[]
}

// Stage → icon (kill-chain). The display NAMES come from the backend and stay in
// English (technical kill-chain terms); only the icon is chosen here.
const STAGE_ICON: Record<string, string> = {
  entry: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.7 5.7l-2.9 2.9a1 1 0 01-.7.3H8v1a1 1 0 01-1 1H6v1a1 1 0 01-1 1H4a1 1 0 01-1-1v-2.6a1 1 0 01.3-.7l6-6A6 6 0 1121 9z',
  file_write: 'M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.6a1 1 0 01.7.3l4.4 4.4a1 1 0 01.3.7V19a2 2 0 01-2 2z',
  execution: 'M13 10V3L4 14h7v7l9-11h-7z',
  c2: 'M8.1 12a4 4 0 015.7-5.7m2.1 2.1a4 4 0 01-5.7 5.7M3 12c2.4-4 5.6-6 9-6s6.6 2 9 6c-2.4 4-5.6 6-9 6s-6.6-2-9-6z',
  persistence: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
}

const POLL_MS = 15000

export default function AttackChainsPage() {
  const { t } = useTranslation('AttackChains')
  const [chains, setChains] = useState<Chain[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    function load() {
      api.get<{ chains: Chain[] }>('/antivirus/chains')
        .then(r => { setChains(r.data.chains || []); setError(null) })
        .catch(cause => setError(apiError(cause, t('errors.load'))))
        .finally(() => setLoading(false))
    }
    load()
    pollRef.current = setInterval(load, POLL_MS) // live: refresh every 15s
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [t])

  const activeCritical = chains.filter(c => c.level === 'critical').length

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <div className="max-w-5xl mx-auto">
        <Breadcrumb items={[{ label: t('home'), href: '/' }, { label: t('title') }]} />
        <div className="flex items-start gap-3 mb-1">
          <span className={`mt-1 w-2.5 h-2.5 rounded-full flex-shrink-0 ${activeCritical > 0 ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'}`} />
          <div>
            <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 leading-tight">{t('title')}</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">{t('subtitle')}</p>
          </div>
        </div>

        {activeCritical > 0 && (
          <div className="mt-3 mb-4 px-4 py-2.5 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm font-medium text-red-700 dark:text-red-300 flex items-center gap-2">
            <span className="font-mono">● {t('activeCritical', { count: activeCritical })}</span>
          </div>
        )}

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

        {loading ? (
          <div className="py-16 text-center text-sm text-slate-400">{t('loading')}</div>
        ) : chains.length === 0 ? (
          <div className="py-16 text-center">
            <svg className="w-12 h-12 mx-auto mb-3 text-emerald-400 dark:text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.6-4A12 12 0 0112 2.9 12 12 0 013.4 6 12 12 0 003 9c0 5.6 3.8 10.3 9 11.6 5.2-1.3 9-6 9-11.6 0-1-.1-2-.4-3z" /></svg>
            <p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">{t('empty.title')}</p>
            <p className="text-xs text-slate-400 mt-1">{t('empty.hint')}</p>
          </div>
        ) : (
          <div className="space-y-4">
            {chains.map(c => {
              const critical = c.level === 'critical'
              return (
                <div key={c.id} className={`rounded-2xl border overflow-hidden shadow-sm ${critical ? 'border-red-300 dark:border-red-800' : 'border-amber-200 dark:border-amber-800/60'}`}>
                  <div className={`px-4 py-3 flex flex-wrap items-center justify-between gap-2 ${critical ? 'bg-red-50 dark:bg-red-900/20' : 'bg-amber-50 dark:bg-amber-900/15'}`}>
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${critical ? 'bg-red-500 animate-pulse' : 'bg-amber-500'}`} />
                      <span className={`font-mono text-xs font-semibold uppercase tracking-wide ${critical ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'}`}>
                        {critical ? t('activeAttack') : t('suspiciousChain')}
                      </span>
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">· {c.domain || '—'}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <span className="text-xs text-slate-400 font-mono">{c.time}</span>
                      <span className={`text-sm font-mono font-bold ${critical ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400'}`}>{t('risk')} %{c.confidence}</span>
                    </div>
                  </div>

                  <div className="px-4 py-3 bg-white dark:bg-slate-800">
                    <div className="flex items-center gap-1 flex-wrap">
                      {c.stages.map((s, i) => (
                        <span key={`${s}-${i}`} className="flex items-center gap-1">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-700/60 text-xs font-medium text-slate-700 dark:text-slate-200">
                            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d={STAGE_ICON[s] || ''} /></svg>
                            {c.stage_names[i] || s}
                          </span>
                          {i < c.stages.length - 1 && <span className={`text-sm ${critical ? 'text-red-400' : 'text-amber-400'}`}>→</span>}
                        </span>
                      ))}
                    </div>

                    {c.events?.length > 0 && (
                      <div className="mt-3 border-t border-slate-100 dark:border-slate-700 pt-2 space-y-1">
                        {c.events.map((e, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs font-mono">
                            <span className="text-slate-400 whitespace-nowrap">{e.time?.slice(11)}</span>
                            <span className={`px-1.5 rounded ${e.source === 'file' ? 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300' : e.source === 'process' ? 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500'}`}>{e.source}</span>
                            <span className="text-slate-400">{e.stage_name}</span>
                            <span className="text-slate-600 dark:text-slate-300 break-all">{e.summary}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
