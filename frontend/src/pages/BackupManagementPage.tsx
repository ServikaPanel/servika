import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type SummaryRow = { domain_id: number; domain_name: string; count: number; total_bytes: number; last_backup: string }
// The schedule is reported as facts rather than a sentence, because the sentence
// has to be written in twelve languages. schedule_hour is -1 when the domains do
// not share one hour, and every retention value is a COUNT of archives, not days.
type Summary = {
  domains: SummaryRow[]; total_size_bytes: number; total_backups: number; destination_count: number
  automatic_domains: number; schedule_hour: number; retention_min: number; retention_max: number
}

// scheduleLine renders the banner from those facts.
function scheduleLine(t: TFunction, o: Summary | null): string {
  if (!o || o.automatic_domains === 0) return t('schedule.none')
  const n = o.automatic_domains
  const when = o.schedule_hour < 0
    ? t('schedule.mixedHours', { n })
    : t('schedule.atHour', { n, hour: String(o.schedule_hour).padStart(2, '0') + ':00' })
  const keep = o.retention_min === o.retention_max
    ? t('schedule.keepOne', { n: o.retention_min })
    : t('schedule.keepRange', { min: o.retention_min, max: o.retention_max })
  return when + ' ' + keep
}
type Job = {
  id: number; type: string; operation: string; status: string
  total: number; completed: number; succeeded: number; failed: number
  size_b: number; active_domain: string; restore_mode: string
  started_by: string; started_at: string; finished_at: string
}

export default function BackupManagementPage() {
  const { t } = useTranslation('BackupManagementPage')
  const report = useReportError()
  const [o, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [backingUp, setBackingUp] = useState(false)
  const [jobs, setJobs] = useState<Job[]>([])
  const [selected, setSelected] = useState<number[]>([])

  // Split so the mount effect never writes state synchronously: fetchSummary
  // only settles through promise callbacks, and the spinner is raised by the
  // refresh button, which is the only caller that needs it.
  function fetchSummary() {
    api.get<Summary>('/admin/backups/summary')
      .then(r => setSummary(r.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }
  function reload() {
    setLoading(true)
    fetchSummary()
  }
  useEffect(fetchSummary, [])

  // Memoised because the polling effect below holds it across renders: a fresh
  // identity every render would tear down and rebuild the interval each time.
  const loadJobs = useCallback(() => {
    api.get<Job[]>('/admin/backups/jobs').then(r => setJobs(r.data)).catch(report('backupJobs'))
  }, [report])
  useEffect(loadJobs, [loadJobs])

  // Poll only while a job is running, so an idle page makes no requests.
  const running = jobs.some(j => j.status === 'running')
  useEffect(() => {
    if (!running) return
    const timer = setInterval(loadJobs, 3000)
    return () => clearInterval(timer)
  }, [running, loadJobs])

  function toggle(domainID: number) {
    setSelected(prev => prev.includes(domainID) ? prev.filter(x => x !== domainID) : [...prev, domainID])
  }

  async function startBackupJob() {
    setError(null); setSuccess(null); setBackingUp(true)
    try {
      const { data } = await api.post<{ total: number }>('/admin/backups/jobs',
        selected.length > 0 ? { domain_ids: selected } : {})
      setSuccess(t('toast.jobStarted', { n: data.total }))
      setSelected([])
      loadJobs()
    } catch (e) { setError(apiError(e, t('toast.jobFailed'))) }
    finally { setBackingUp(false) }
  }

  // There is deliberately no button for POST /admin/backups/tick. That endpoint
  // runs the nightly pass, which selects only domains whose own backup_hour is
  // the current hour and whose last backup is over 23 hours old, so pressed at
  // any other time it backed up nothing while the toast said it had. The button
  // beside this one starts a real job over every domain in scope.

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.toolsSettings'), href: '/tools-settings' },
        { label: t('breadcrumb.backupManager') },
      ]} />
      <div className="flex items-center gap-3 mb-1">
        <span className="text-brand-600 dark:text-brand-400"><Icon d={ICON.save} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {/* KPI */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
        <Kpi label={t('kpi.totalSize')} value={o ? formatBytes(o.total_size_bytes) : '-'} color="sky" icon={<Icon d={ICON.save} className="h-4 w-4" />} />
        <Kpi label={t('kpi.totalBackups')} value={o ? String(o.total_backups) : '-'} color="violet" icon={<Icon d={ICON.box} className="h-4 w-4" />} />
        <Kpi label={t('kpi.domainCount')} value={o ? String(o.domains.length) : '-'} color="teal" icon={<Icon d={ICON.globe} className="h-4 w-4" />} />
        <Kpi label={t('kpi.remoteDestinations')} value={o ? String(o.destination_count) : '-'} color="emerald" icon={<Icon d={ICON.cloud} className="h-4 w-4" />} subtitle={t('kpi.remoteSubtitle')} />
      </div>

      {/* Schedule and action */}
      <div className="mb-5 flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-700/60 dark:bg-slate-800/60 sm:flex-row sm:items-center">
        <span className="text-sm text-slate-600 dark:text-slate-300">{scheduleLine(t, o)}</span>
        <div className="flex flex-col gap-2 sm:ml-auto sm:flex-row sm:items-center">
          <button onClick={startBackupJob} disabled={backingUp}
            className="px-3.5 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-700 text-white rounded-lg disabled:opacity-50">
            {backingUp
              ? t('schedule.triggering')
              : selected.length > 0
                ? t('schedule.backupSelected', { n: selected.length })
                : t('schedule.backupAll')}
          </button>
          <button onClick={reload} disabled={loading} className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-700 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">{t('schedule.refresh')}</button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/60 dark:bg-slate-800/60">
        <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('table.title')}</h3>
        </div>
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="w-8 px-4 py-2.5"></th>
                <th className="text-left font-medium px-4 py-2.5">{t('table.colDomain')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('table.colCount')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('table.colSize')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('table.colLatest')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('table.colAction')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-400">{t('table.loading')}</td></tr>
              ) : !o || o.domains.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-500 dark:text-slate-400">{t('table.noDomains')}</td></tr>
              ) : (
                o.domains.map(d => (
                  <tr key={d.domain_id} className={responsiveTableRowClass}>
                    <td className="px-4 py-2.5">
                      <input type="checkbox" checked={selected.includes(d.domain_id)} onChange={() => toggle(d.domain_id)} />
                    </td>
                    <td data-label={t('table.colDomain')} className={`${responsiveTableCellClass} font-medium text-slate-800 dark:text-slate-100`}>{d.domain_name}</td>
                    <td data-label={t('table.colCount')} className={`${responsiveTableCodeCellClass} lg:text-right`}>{d.count}</td>
                    <td data-label={t('table.colSize')} className={`${responsiveTableCodeCellClass} lg:text-right`}>{d.count ? formatBytes(d.total_bytes) : '-'}</td>
                    <td data-label={t('table.colLatest')} className={responsiveTableCodeCellClass}>{d.last_backup || <span className="text-slate-400">{t('table.never')}</span>}</td>
                    <td className={responsiveTableActionCellClass}>
                      <Link to={`/subscriptions/${d.domain_id}/backups`} className="text-xs px-2.5 py-1 border border-slate-200 dark:border-slate-700 rounded-md text-brand-600 dark:text-brand-400 hover:bg-slate-50 dark:hover:bg-slate-700">{t('table.manage')}</Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      {/* Jobs */}
      <div className="mt-5 rounded-2xl border border-slate-200 bg-white dark:border-slate-700/60 dark:bg-slate-800/60">
        <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('jobs.title')}</h3>
        </div>
        {jobs.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">{t('jobs.empty')}</p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
            {jobs.map(j => (
              <li key={j.id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Link to={`/backup-management/job/${j.id}`}
                    className="text-sm font-medium text-brand-600 dark:text-brand-400 hover:underline">
                    {t(j.operation === 'restore' ? 'jobs.opRestore' : 'jobs.opBackup')} #{j.id}
                  </Link>
                  <JobStatusBadge status={j.status} label={t(`jobs.status.${j.status}`)} />
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {t('jobs.startedBy', { user: j.started_by || '-' })} · {j.started_at}
                  </span>
                  <span className="ml-auto text-xs text-slate-500 dark:text-slate-400">
                    {j.completed}/{j.total}
                    {j.failed > 0 && <span className="text-red-600 dark:text-red-400"> · {t('jobs.failedCount', { n: j.failed })}</span>}
                    {j.size_b > 0 && <span> · {formatBytes(j.size_b)}</span>}
                  </span>
                </div>
                <div className="mt-2 h-1.5 w-full rounded-full bg-slate-100 dark:bg-slate-700">
                  <div className={`h-1.5 rounded-full ${j.failed > 0 ? 'bg-amber-500' : 'bg-brand-600'}`}
                    style={{ width: `${j.total > 0 ? Math.round((j.completed / j.total) * 100) : 0}%` }} />
                </div>
                {j.status === 'running' && j.active_domain && (
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('jobs.active', { domain: j.active_domain })}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <p className="text-xs text-slate-400 dark:text-slate-500 mt-3">
        {t('footnote.pre')} <span className="font-mono">/var/backups/servika/&lt;domain&gt;/</span> {t('footnote.post')}
      </p>
    </div>
  )
}

function Kpi({ label, value, color, icon, subtitle }: { label: string; value: string; color: string; icon: ReactNode; subtitle?: string }) {
  const c: Record<string, string> = {
    sky: 'text-sky-600 dark:text-sky-400', violet: 'text-violet-600 dark:text-violet-400',
    teal: 'text-teal-600 dark:text-teal-400', emerald: 'text-emerald-600 dark:text-emerald-400',
  }
  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-4">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{icon} {label}</div>
      <div className={`text-2xl font-semibold mt-1 ${c[color] || 'text-slate-700 dark:text-slate-200'}`}>{value}</div>
      {subtitle && <div className="text-[11px] text-slate-400 mt-0.5">{subtitle}</div>}
    </div>
  )
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function JobStatusBadge({ status, label }: { status: string; label: string }) {
  const tone = status === 'done' ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
    : status === 'failed' ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'
    : status === 'partial' ? 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
    : 'bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300'
  return <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${tone}`}>{label}</span>
}
