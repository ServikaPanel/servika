import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import SecurityFindingsTable, { type SecurityFinding } from '@/components/SecurityFindingsTable'
import { api, apiError } from '@/lib/api'

/** Renders the known vulnerabilities of one domain's own site. */
export default function DomainSiteSecurityPage() {
  const { t } = useTranslation('SiteSecurity')
  const { id } = useParams()
  const [findings, setFindings] = useState<SecurityFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    if (!id) return
    api.get<SecurityFinding[]>(`/domains/${id}/site-security`)
      .then(response => setFindings(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.load'))))
      .finally(() => setLoading(false))
  }, [id, t])

  useEffect(() => { load() }, [load])

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.current') },
      ]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('domainSubtitle')}</p>

      {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      <SecurityFindingsTable findings={findings} loading={loading} />

      <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('advisoryNote')}</p>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('scheduleNote')}</p>
    </div>
  )
}
