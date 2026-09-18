import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'

type Domain = { id: number; domain_name: string }

// Phase codes are non-translatable identifiers; slugs missing here have no phase.
const TOOL_PHASE: Record<string, string> = {
  files: 'F6',
  databases: 'F5',
  ftp: 'F4',
  backups: 'F12',
  php: 'F3',
  logs: 'F10',
  cron: 'F8',
  git: 'F9',
  composer: 'F3',
  ssl: 'F7',
  'password-protection': 'F7',
  stats: 'F10',
}

type ToolMeta = { label: string; phase?: string; description: string }

function useToolMeta(slug: string | undefined): ToolMeta {
  const { t } = useTranslation('ToolPage')
  const key = slug || ''
  const fallbackLabel = slug || t('fallback.label')
  const known = Object.prototype.hasOwnProperty.call(TOOL_PHASE, key) || Boolean(t(`tool.${key}.label`, { defaultValue: '' }))
  if (!known) return { label: fallbackLabel, phase: TOOL_PHASE[key], description: t('fallback.description') }
  return {
    label: t(`tool.${key}.label`, { defaultValue: fallbackLabel }),
    phase: TOOL_PHASE[key],
    description: t(`tool.${key}.description`, { defaultValue: t('fallback.description') }),
  }
}

function ConstructionPanel({ phase, id }: { phase?: string; id?: string }) {
  const { t } = useTranslation('ToolPage')
  return (
    <div className="bg-white dark:bg-slate-800 border-2 border-dashed border-slate-200 dark:border-slate-700 rounded-2xl p-12 text-center">
      <div className="w-16 h-16 mx-auto rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-3">
        <svg className="w-8 h-8 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
      <h3 className="text-base font-semibold text-slate-700 dark:text-slate-300 mb-1">{t('construction.heading')}</h3>
      <p className="text-sm text-slate-500 dark:text-slate-500">
        {phase
          ? <>{t('construction.availablePrefix')}<span className="font-mono text-brand-700 dark:text-brand-300">{phase}</span>{t('construction.availableSuffix')}</>
          : t('construction.availableLater')}
      </p>
      <Link to={`/subscriptions/${id}`} className="inline-block mt-4 text-sm text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">
        {t('construction.returnToDashboard')}
      </Link>
    </div>
  )
}

export default function ToolPage() {
  const { t } = useTranslation('ToolPage')
  const { id, slug } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.get<Domain>(`/domains/${id}`).then(response => setDomain(response.data)).catch(requestError => setError(apiError(requestError)))
  }, [id])

  const meta = useToolMeta(slug)

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: meta.label },
      ]} />

      <div className="flex items-center gap-3 mb-2">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{meta.label}</h1>
        {meta.phase && (
          <span className="text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-200 px-2 py-0.5 rounded">
            {meta.phase} · {t('notReady')}
          </span>
        )}
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-1">
        {domain ? <>{t('domainLabel')}<Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link></> : '...'}
      </p>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">{meta.description}</p>
      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      <ConstructionPanel phase={meta.phase} id={id} />
    </div>
  )
}