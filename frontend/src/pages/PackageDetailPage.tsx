import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
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

type Plan = {
  id: number; name: string; description: string
  disk_quota_mb: number; traffic_quota_mb: number
  max_domain: number; max_db: number; max_email: number; max_ftp: number; max_app: number
  cpu_percent: number; ram_mb: number; max_process: number
  inode_quota: number; io_weight: number; mysql_max_connections: number
  pm_max_children: number
  io_read_mbps: number; io_write_mbps: number; io_read_iops: number; io_write_iops: number
  db_max_queries_per_hour: number; db_max_updates_per_hour: number; db_max_query_seconds: number
  php_version: string
  fastcgi_cache: boolean; client_max_body_mb: number; nginx_extra_directives: string
  is_default: boolean; created_at: string
}
type Domain = { id: number; domain_name: string; system_user: string; status: string; created_at: string }
type GetResponse = { plan: Plan; domain_count: number }
type Version = { version: string; description?: string }

export default function PackageDetailPage() {
  const { t } = useTranslation('PackageDetailPage')
  const report = useReportError()
  const { id } = useParams()
  const [plan, setPlan] = useState<Plan | null>(null)
  const [domainCount, setDomainCount] = useState(0)
  const [domains, setDomains] = useState<Domain[]>([])
  const [versions, setVersions] = useState<Version[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [processing, setProcessing] = useState(false)
  const [reapplyingId, setReapplyingId] = useState<number | null>(null)
  const [reapplyResult, setReapplyResult] = useState<{ id: number; ok: boolean } | null>(null)

  // Split so the mount effect never writes state synchronously: fetchPlan
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a write.
  const fetchPlan = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<GetResponse>(`/plans/${id}`),
      api.get<Domain[]>(`/plans/${id}/domains`),
    ]).then(([planResponse, domainsResponse]) => {
      setPlan(planResponse.data.plan)
      setDomainCount(planResponse.data.domain_count)
      setDomains(domainsResponse.data || [])
    }).catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchPlan()
  }, [fetchPlan])

  useEffect(() => { fetchPlan() }, [fetchPlan])
  useEffect(() => {
    api.get<Version[]>('/php/versions').then(response => setVersions(response.data || [])).catch(report('phpVersions'))
  }, [report])

  async function save() {
    if (!plan) return
    setProcessing(true); setError(null); setSuccess(null)
    try {
      await api.put(`/plans/${id}`, plan)
      setSuccess(t('saveSuccess', { name: plan.name }))
      setTimeout(() => setSuccess(null), 6000)
      load()
    } catch (e) {
      setError(apiError(e, t('saveFailed')))
    } finally {
      setProcessing(false)
    }
  }

  async function reapplyForDomain(domainId: number) {
    if (!plan) return
    setReapplyingId(domainId); setReapplyResult(null); setError(null)
    try {
      await api.put(`/domains/${domainId}/plan`, { plan_id: plan.id })
      setReapplyResult({ id: domainId, ok: true })
    } catch (e) {
      setReapplyResult({ id: domainId, ok: false }); setError(apiError(e))
    } finally {
      setReapplyingId(null)
      setTimeout(() => setReapplyResult(current => (current?.id === domainId ? null : current)), 3500)
    }
  }

  function updatePlan<K extends keyof Plan>(key: K, value: Plan[K]) {
    if (!plan) return
    setPlan({ ...plan, [key]: value })
  }

  if (loading) return <div className="px-4 py-4 text-slate-400 sm:px-6 sm:py-5">{t('loading')}</div>
  if (!plan) return <div className="px-4 py-4 sm:px-6 sm:py-5"><div className="text-sm text-red-600">{error || t('planNotFound')}</div></div>

  // Include installed PHP versions and the plan's current value even when it is not installed.
  const phpOptions = Array.from(new Set([
    ...versions.map(version => version.version),
    plan.php_version,
    ...(versions.length === 0 ? ['7.4', '8.1', '8.2', '8.3', '8.4'] : []),
  ].filter(Boolean)))

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.toolsSettings'), href: '/tools-settings' },
          { label: t('breadcrumb.servicePlans'), href: '/tools/packages' },
          { label: plan.name },
        ]} />

        {/* Sticky header and save action */}
        <div className="sticky top-0 z-10 -mx-2 px-2 py-3 mb-4 bg-slate-50/85 dark:bg-slate-900/85 backdrop-blur border-b border-slate-200/70 dark:border-slate-800 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2 truncate">
              {plan.name}
              {plan.is_default && <span className="shrink-0 text-[10px] uppercase font-semibold tracking-wider bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 px-1.5 py-0.5 rounded">{t('default')}</span>}
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">
              {plan.description || t('noDescription')}{t('usedBy')}<span className="font-mono">{domainCount}</span>{t('domainsSuffix')}
            </p>
          </div>
          <button onClick={save} disabled={processing}
            className="shrink-0 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-lg shadow-sm">
            {processing ? t('saving') : t('saveChanges')}
          </button>
        </div>

        {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
        {success && <div className="mb-4 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

        {/* General settings */}
        <Card title={t('general.title')} icon={<Icon d={ICON.settings} className="h-4 w-4" />}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label={t('general.planName')}>
              <input value={plan.name} onChange={e => updatePlan('name', e.target.value)} className={inputClass} />
            </Field>
            <Field label={t('general.defaultPlan')}>
              <label className="flex items-center gap-2 h-[38px] px-3 border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50/60 dark:bg-slate-900/40 cursor-pointer">
                <input type="checkbox" checked={plan.is_default} onChange={e => updatePlan('is_default', e.target.checked)} className="rounded" />
                <span className="text-sm text-slate-700 dark:text-slate-300">{t('general.assignAuto')}</span>
              </label>
            </Field>
            <Field label={t('general.description')} span={2}>
              <textarea value={plan.description} onChange={e => updatePlan('description', e.target.value)} rows={2} className={inputClass} />
            </Field>
          </div>
        </Card>

        {/* Defaults inherited by new domains */}
        <Card title={t('defaults.title')} icon={<Icon d={ICON.puzzle} className="h-4 w-4" />} subtitle={t('defaults.subtitle')}>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Field label={t('defaults.phpVersion')} hint={t('defaults.phpHint')}>
              <select value={plan.php_version} onChange={e => updatePlan('php_version', e.target.value)} className={inputClass}>
                {phpOptions.map(version => <option key={version} value={version}>PHP {version}</option>)}
              </select>
            </Field>
          </div>
        </Card>

        {/* Resource limits */}
        <Card title={t('resources.title')} icon={<Icon d={ICON.chart} className="h-4 w-4" />} subtitle={t('resources.subtitle')}>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Field label={t('resources.cpu')} hint={t('resources.cpuHint')}>
              <input type="number" min={10} max={2000} value={plan.cpu_percent} onChange={e => updatePlan('cpu_percent', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.ram')} hint={t('resources.ramHint')}>
              <input type="number" min={64} value={plan.ram_mb} onChange={e => updatePlan('ram_mb', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.maxProcesses')} hint={t('resources.maxProcessesHint')}>
              <input type="number" min={5} value={plan.max_process} onChange={e => updatePlan('max_process', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.mysqlConnections')} hint={t('resources.mysqlConnectionsHint')}>
              <input type="number" min={1} value={plan.mysql_max_connections} onChange={e => updatePlan('mysql_max_connections', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.fpmChildren')} hint={t('resources.fpmChildrenHint')}>
              <input type="number" min={0} value={plan.pm_max_children} onChange={e => updatePlan('pm_max_children', Number(e.target.value) || 0)} placeholder={t('resources.fpmChildrenPlaceholder')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.disk')} hint={t('resources.diskHint')}>
              <input type="number" min={0} value={plan.disk_quota_mb} onChange={e => updatePlan('disk_quota_mb', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.traffic')} hint={t('resources.trafficHint')}>
              <input type="number" min={0} value={plan.traffic_quota_mb} onChange={e => updatePlan('traffic_quota_mb', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.inode')} hint={t('resources.inodeHint')}>
              <input type="number" min={1000} value={plan.inode_quota} onChange={e => updatePlan('inode_quota', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('resources.ioWeight')} hint={t('resources.ioWeightHint')}>
              <input type="number" min={1} max={1000} value={plan.io_weight} onChange={e => updatePlan('io_weight', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
          </div>
          <div className="mt-4 text-xs font-medium text-slate-500">{t('resources.diskIoHeader')}</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-2">
            <Field label={t('resources.diskRead')} hint={t('resources.diskReadHint')}>
              <input type="number" min={0} value={plan.io_read_mbps} onChange={e => updatePlan('io_read_mbps', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.diskWrite')} hint={t('resources.diskWriteHint')}>
              <input type="number" min={0} value={plan.io_write_mbps} onChange={e => updatePlan('io_write_mbps', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.readIops')} hint={t('resources.readIopsHint')}>
              <input type="number" min={0} value={plan.io_read_iops} onChange={e => updatePlan('io_read_iops', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.writeIops')} hint={t('resources.writeIopsHint')}>
              <input type="number" min={0} value={plan.io_write_iops} onChange={e => updatePlan('io_write_iops', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
          </div>
          <div className="mt-4 text-xs font-medium text-slate-500">{t('resources.dbHeader')}</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-2">
            <Field label={t('resources.queriesPerHour')} hint={t('resources.queriesPerHourHint')}>
              <input type="number" min={0} value={plan.db_max_queries_per_hour} onChange={e => updatePlan('db_max_queries_per_hour', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.updatesPerHour')} hint={t('resources.updatesPerHourHint')}>
              <input type="number" min={0} value={plan.db_max_updates_per_hour} onChange={e => updatePlan('db_max_updates_per_hour', Number(e.target.value) || 0)} placeholder={t('resources.unlimited')} className={numberInputClass} />
            </Field>
            <Field label={t('resources.queryTime')} hint={t('resources.queryTimeHint')}>
              <input type="number" min={0} value={plan.db_max_query_seconds} onChange={e => updatePlan('db_max_query_seconds', Number(e.target.value) || 0)} placeholder={t('resources.disabled')} className={numberInputClass} />
            </Field>
          </div>
        </Card>

        {/* Numeric limits, excluding email */}
        <Card title={t('numeric.title')} icon={<Icon d={ICON.hash} className="h-4 w-4" />} subtitle={t('numeric.subtitle')}>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            <Field label={t('numeric.domains')}>
              <input type="number" min={0} value={plan.max_domain} onChange={e => updatePlan('max_domain', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('numeric.databases')}>
              <input type="number" min={0} value={plan.max_db} onChange={e => updatePlan('max_db', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('numeric.ftpAccounts')}>
              <input type="number" min={0} value={plan.max_ftp} onChange={e => updatePlan('max_ftp', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
            <Field label={t('numeric.applications')}>
              <input type="number" min={0} value={plan.max_app} onChange={e => updatePlan('max_app', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
          </div>
        </Card>

        {/* Web server settings for nginx */}
        <Card title={t('nginx.title')} icon={<Icon d={ICON.wrench} className="h-4 w-4" />} subtitle={t('nginx.subtitle')}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
            <Field label={t('nginx.fastcgiCache')} hint={t('nginx.fastcgiCacheHint')}>
              <label className="flex items-center gap-2 h-[38px] px-3 border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50/60 dark:bg-slate-900/40 cursor-pointer">
                <input type="checkbox" checked={plan.fastcgi_cache} onChange={e => updatePlan('fastcgi_cache', e.target.checked)} className="rounded" />
                <span className="text-sm text-slate-700 dark:text-slate-300">{t('nginx.enableForNew')}</span>
              </label>
            </Field>
            <Field label={t('nginx.uploadLimit')} hint={t('nginx.uploadLimitHint')}>
              <input type="number" min={1} max={4096} value={plan.client_max_body_mb} onChange={e => updatePlan('client_max_body_mb', Number(e.target.value) || 0)} className={numberInputClass} />
            </Field>
          </div>
          <Field label={t('nginx.extraDirectives')} hint={t('nginx.extraDirectivesHint')}>
            <textarea
              value={plan.nginx_extra_directives || ''}
              onChange={e => updatePlan('nginx_extra_directives', e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder={'# Example:\nadd_header X-Robots-Tag "noindex" always;\nlocation = /health { return 200 "ok"; }'}
              className={inputClass + ' font-mono text-xs leading-relaxed'}
            />
          </Field>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {t('nginx.testPre')}<code className="font-mono">nginx -t</code>{t('nginx.testMid')}<strong>{t('nginx.testBold')}</strong>{t('nginx.testPost')}
          </p>
        </Card>

        {/* Assigned domains */}
        <Card title={t('assigned.title', { count: domains.length })} icon={<Icon d={ICON.globe} className="h-4 w-4" />} subtitle={t('assigned.subtitle')}>
          {domains.length === 0 ? (
            <div className="text-sm text-slate-400 py-6 text-center">{t('assigned.empty')}</div>
          ) : (
            <div className={responsiveTableContainerClass}>
              <table className={responsiveTableClass}>
                <thead className={responsiveTableHeadClass}>
                  <tr>
                    <th className="text-left py-2">{t('assigned.domain')}</th>
                    <th className="text-left">{t('assigned.systemUser')}</th>
                    <th className="text-left">{t('assigned.status')}</th>
                    <th className="text-left">{t('assigned.created')}</th>
                    <th className="text-right">{t('assigned.action')}</th>
                  </tr>
                </thead>
                <tbody className={responsiveTableBodyClass}>
                  {domains.map(domain => (
                    <tr key={domain.id} className={responsiveTableRowClass}>
                      <td data-label={t('assigned.domain')} className={responsiveTableCellClass}><Link to={`/subscriptions/${domain.id}`} className="text-brand-600 dark:text-brand-400 font-medium">{domain.domain_name}</Link></td>
                      <td data-label={t('assigned.systemUser')} className={responsiveTableCodeCellClass}>{domain.system_user}</td>
                      <td data-label={t('assigned.status')} className={responsiveTableCellClass}>
                        <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded font-semibold ${
                          domain.status === 'active' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500'
                        }`}>{domain.status}</span>
                      </td>
                      <td data-label={t('assigned.created')} className={responsiveTableCodeCellClass}>{domain.created_at}</td>
                      <td className={responsiveTableActionCellClass}>
                        <button type="button" onClick={() => reapplyForDomain(domain.id)} disabled={reapplyingId !== null}
                          className={`text-xs px-2 py-1 border rounded-md disabled:opacity-60 transition ${
                            reapplyResult?.id === domain.id
                              ? (reapplyResult.ok
                                  ? 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-900/20'
                                  : 'border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20')
                              : 'border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                          {reapplyingId === domain.id ? t('assigned.reapplying') : reapplyResult?.id === domain.id ? (reapplyResult.ok ? t('assigned.applied') : t('assigned.failed')) : t('assigned.reapply')}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}

const inputClass = 'w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-800 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'
const numberInputClass = inputClass + ' font-mono'

function Card({ title, subtitle, icon, children }: { title: string; subtitle?: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4 shadow-sm">
      <div className="flex items-center gap-2 mb-1">
        {icon && <span className="text-slate-500 dark:text-slate-400" aria-hidden>{icon}</span>}
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
      </div>
      {subtitle && <p className="text-xs text-slate-500 dark:text-slate-400 mb-4 max-w-2xl">{subtitle}</p>}
      {children}
    </div>
  )
}

function Field({ label, hint, span, children }: { label: string; hint?: string; span?: number; children: React.ReactNode }) {
  return (
    <label className={`block ${span === 2 ? 'sm:col-span-2' : ''}`}>
      <span className="text-xs font-medium text-slate-600 dark:text-slate-400">{label}</span>
      {hint && <span className="text-[10px] text-slate-400 dark:text-slate-500 ml-1 cursor-help" title={hint}>ⓘ</span>}
      <div className="mt-1.5">{children}</div>
    </label>
  )
}
