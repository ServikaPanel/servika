import { useEffect, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import SlowQueryTable from '@/components/SlowQueryTable'

type Item = { name: string; enabled: boolean; value: string; setting: string; description: string }
type Suggestion = { text: string; severity: string; setting: string }
type CacheStats = { hit: number; miss: number; expired?: number; bypass?: number; stale?: number; updating?: number; revalidated?: number; total: number; hit_rate: number }
type Summary = { domain_name: string; php_version: string; score: number; items: Item[]; suggestions: Suggestion[]; fastcgi_cache?: CacheStats; redis_cache?: CacheStats }

export default function DomainPerformancePage() {
  const { t } = useTranslation('DomainPerformancePage')
  const { id } = useParams()
  const navigate = useNavigate()
  const [summary, setSummary] = useState<Summary | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Derived instead of stored: loading means the request for the CURRENT domain
  // has not settled, so switching domain shows the spinner on the same render
  // rather than one frame of the previous summary.
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  const loading = loadedFor !== id

  useEffect(() => {
    if (!id) return
    let cancelled = false
    api.get<Summary>(`/domains/${id}/performance`)
      .then(r => { if (!cancelled) setSummary(r.data) })
      .catch(e => { if (!cancelled) setError(apiError(e)) })
      .finally(() => { if (!cancelled) setLoadedFor(id) })
    return () => { cancelled = true }
  }, [id])

  if (loading) return <div className="px-6 py-5 text-slate-400">{t('loading')}</div>
  if (!summary) return <div className="px-6 py-5"><div className="text-sm text-red-600">{error || t('notFound')}</div></div>

  const scoreColor = summary.score >= 80 ? 'emerald' : summary.score >= 60 ? 'amber' : 'rose'
  const scoreHex: Record<string, string> = { emerald: '#10b981', amber: '#f59e0b', rose: '#f43f5e' }
  const navigateToSetting = (slug: string) => navigate(`/subscriptions/${id}/${slug}`)
  const severityColor: Record<string, string> = { high: 'text-rose-500', medium: 'text-amber-500', info: 'text-emerald-500' }

  return (
    <div className="px-6 py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: summary.domain_name, href: `/subscriptions/${id}` },
          { label: t('breadcrumb.performance') },
        ]} />
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-5"><span className="font-mono">{summary.domain_name}</span>{t('subtitle.post')}</p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
          {/* Score ring */}
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm flex flex-col items-center justify-center">
            <div className="relative w-28 h-28">
              <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                <circle cx="18" cy="18" r="15.9" fill="none" className="stroke-slate-100 dark:stroke-slate-700" strokeWidth="3" />
                <circle cx="18" cy="18" r="15.9" fill="none" stroke={scoreHex[scoreColor]} strokeWidth="3" strokeLinecap="round"
                  strokeDasharray={`${summary.score} 100`} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold text-slate-800 dark:text-slate-100">{summary.score}</span>
                <span className="text-[10px] text-slate-400">/ 100</span>
              </div>
            </div>
            <div className="mt-2 text-sm font-medium text-slate-600 dark:text-slate-300">{t('scoreLabel')}</div>
          </div>

          {/* Accelerator statuses */}
          <div className="sm:col-span-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('acceleratorsTitle')}</h3>
            <div className="space-y-2">
              {summary.items.map(item => {
                const fcStats = item.name === 'FastCGI Cache' ? summary.fastcgi_cache : undefined
                const redisStats = item.name === 'Redis Cache' ? summary.redis_cache : undefined
                const cacheStats = fcStats || redisStats
                return (
                <div key={item.name} className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-50 dark:border-slate-800 last:border-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${item.enabled ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{item.name}</span>
                      <span className="text-xs font-mono text-slate-400">{item.value}</span>
                      {cacheStats && cacheStats.total > 0 && (
                        <span className={`text-xs font-mono ${cacheStats.hit_rate >= 80 ? 'text-emerald-500' : cacheStats.hit_rate >= 50 ? 'text-amber-500' : 'text-rose-500'}`}>
                          {t('cacheStat', { rate: cacheStats.hit_rate.toFixed(1), total: cacheStats.total.toLocaleString() })}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 ml-4 truncate">{item.description}</p>
                  </div>
                  {item.setting && <button onClick={() => navigateToSetting(item.setting)} className="shrink-0 text-xs text-brand-600 dark:text-brand-400 hover:underline">{t('configure')}</button>}
                </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Suggestions */}
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('suggestionsTitle')}</h3>
          <ul className="space-y-2">
            {summary.suggestions.map((suggestion, index) => (
              <li key={index} className="flex items-start gap-2 text-sm">
                <span className={`mt-0.5 ${severityColor[suggestion.severity] || 'text-slate-400'}`}>●</span>
                <span className="text-slate-600 dark:text-slate-300 flex-1">{suggestion.text}</span>
                {suggestion.setting && <button onClick={() => navigateToSetting(suggestion.setting)} className="shrink-0 text-xs text-brand-600 dark:text-brand-400 hover:underline">{t('open')}</button>}
              </li>
            ))}
          </ul>
        </div>

        {/* The slowest query shapes this domain's own database account ran.
            It lives here rather than on the databases page because a customer
            whose site is slow comes looking for the reason, not for a list of
            schemas. */}
        <div className="mt-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('slowQueriesTitle')}</h3>
          <SlowQueryTable endpoint={`/domains/${id}/slow-queries`} />
        </div>

        <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('back')}</Link></div>
      </div>
    </div>
  )
}
