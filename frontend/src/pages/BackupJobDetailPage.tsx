import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Job = {
  id: number; type: string; operation: string; status: string
  total: number; completed: number; succeeded: number; failed: number
  size_b: number; active_domain: string; restore_mode: string
  started_by: string; started_at: string; finished_at: string
}
type JobItem = {
  backup_id: number; domain_id: number; domain_name: string
  system_user: string; size_b: number; type: string
}
type RestoreResult = { domain_id: number; domain_name: string; status: string; message: string }
type Detail = { job: Job; domains?: JobItem[]; results?: RestoreResult[] | null }

export default function BackupJobDetailPage() {
  const { jid } = useParams()
  const { t } = useTranslation('BackupManagementPage')
  const [detail, setDetail] = useState<Detail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    api.get<Detail>(`/admin/backups/jobs/${jid}`)
      .then(r => setDetail(r.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [jid])
  useEffect(load, [load])

  // Keep polling only while the job is still running.
  const running = detail?.job.status === 'running'
  useEffect(() => {
    if (!running) return
    const timer = setInterval(load, 3000)
    return () => clearInterval(timer)
  }, [running, load])

  const job = detail?.job
  const percent = job && job.total > 0 ? Math.round((job.completed / job.total) * 100) : 0

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.backupManager'), href: '/backup-management' },
        { label: t('jobDetail.breadcrumb', { id: jid }) },
      ]} />

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {loading && !job && <p className="text-sm text-slate-500 dark:text-slate-400">{t('table.loading')}</p>}

      {job && (
        <>
          <div className="flex items-center gap-3 mb-1">
            <span><Icon d={job.operation === 'restore' ? ICON.refresh : ICON.save} className="h-6 w-6" /></span>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
              {t(job.operation === 'restore' ? 'jobs.opRestore' : 'jobs.opBackup')} #{job.id}
            </h1>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">
            {t('jobs.startedBy', { user: job.started_by || '-' })} · {job.started_at}
            {job.finished_at && ` · ${job.finished_at}`}
          </p>

          <div className="mb-5 rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-700/60 dark:bg-slate-800/60">
            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-600 dark:text-slate-300">
              <span>{t(`jobs.status.${job.status}`)}</span>
              <span>{job.completed}/{job.total}</span>
              <span className="text-emerald-600 dark:text-emerald-400">{t('jobDetail.succeeded', { n: job.succeeded })}</span>
              {job.failed > 0 && <span className="text-red-600 dark:text-red-400">{t('jobDetail.failed', { n: job.failed })}</span>}
              {job.size_b > 0 && <span className="ml-auto">{formatBytes(job.size_b)}</span>}
            </div>
            <div className="mt-2 h-1.5 w-full rounded-full bg-slate-100 dark:bg-slate-700">
              <div className={`h-1.5 rounded-full ${job.failed > 0 ? 'bg-amber-500' : 'bg-brand-600'}`} style={{ width: `${percent}%` }} />
            </div>
            {running && job.active_domain && (
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('jobs.active', { domain: job.active_domain })}</p>
            )}
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/60 dark:bg-slate-800/60">
            <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('jobDetail.itemsTitle')}</h3>
            </div>
            {job.operation === 'restore' ? (
              <RestoreResults results={detail?.results ?? []} empty={t('jobDetail.empty')} />
            ) : (
              <BackupItems items={detail?.domains ?? []} empty={t('jobDetail.empty')} manage={t('table.manage')} />
            )}
          </div>
        </>
      )}
    </div>
  )
}

function BackupItems({ items, empty, manage }: { items: JobItem[]; empty: string; manage: string }) {
  if (items.length === 0) return <p className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">{empty}</p>
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
      {items.map(it => (
        <li key={it.backup_id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
          <span className="font-medium text-slate-800 dark:text-slate-100">{it.domain_name}</span>
          <span className="text-xs text-slate-500 dark:text-slate-400">{formatBytes(it.size_b)}</span>
          <Link to={`/subscriptions/${it.domain_id}/backups`}
            className="ml-auto text-xs px-2.5 py-1 border border-slate-200 dark:border-slate-700 rounded-md text-brand-600 dark:text-brand-400 hover:bg-slate-50 dark:hover:bg-slate-700">
            {manage}
          </Link>
        </li>
      ))}
    </ul>
  )
}

function RestoreResults({ results, empty }: { results: RestoreResult[]; empty: string }) {
  if (!results || results.length === 0) return <p className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">{empty}</p>
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
      {results.map(r => (
        <li key={r.domain_id} className="flex items-start gap-3 px-4 py-2.5 text-sm">
          <span className="font-medium text-slate-800 dark:text-slate-100">{r.domain_name}</span>
          <span className={`ml-auto text-xs ${r.status === 'failed' ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
            {r.message}
          </span>
        </li>
      ))}
    </ul>
  )
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}
