import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import { useAuth } from '@/store/auth'
import Breadcrumb from '@/components/Breadcrumb'
import ListToolbar from '@/components/ListToolbar'
import EmptyState from '@/components/EmptyState'
import Modal from '@/components/Modal'
import ConfirmDialog from '@/components/ConfirmDialog'

type Plan = {
  id: number
  name: string
  description: string
  disk_quota_mb: number
  traffic_quota_mb: number
  max_domain: number
  max_db: number
  max_email: number
  mailbox_quota_mb: number
  mail_send_limit_hour: number
  mail_send_limit_day: number
  max_ftp: number
  max_app: number
  php_version: string
  fastcgi_cache: boolean
  client_max_body_mb: number
  nginx_extra_directives: string
  waf_enabled: boolean
  waf_mode: string
  waf_paranoia: number
  is_default: boolean
  created_at: string
}
type Version = { version: string; description?: string }

export default function ServicePlansPage() {
  const { t } = useTranslation('ServicePlansPage')
  const { notify } = useDialog()
  const report = useReportError()
  const isAdmin = useAuth((s) => s.username?.role) === 'admin'
  const [items, setItems] = useState<Plan[]>([])
  const [versions, setVersions] = useState<Version[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [modal, setModal] = useState<Plan | null>(null)
  const [planToDelete, setPlanToDelete] = useState<Plan | null>(null)

  // Split so the mount effect never writes state synchronously: fetchPlans
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchPlans = useCallback(() => {
    api.get<Plan[]>('/plans')
      .then(response => setItems(response.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchPlans()
  }, [fetchPlans])

  useEffect(() => { fetchPlans() }, [fetchPlans])
  useEffect(() => {
    api.get<Version[]>('/php/versions').then(response => setVersions(response.data || [])).catch(report('phpVersions'))
  }, [report])

  async function remove() {
    if (!planToDelete) return
    try {
      await api.delete(`/plans/${planToDelete.id}`)
      setPlanToDelete(null); load()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.deleteFailed')), tone: 'error' })
    }
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('breadcrumbTitle') }]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">
        {t('subtitle')}
      </p>

      <ListToolbar
        primary={isAdmin ? { label: t('addPlan'), onClick: () => setModal({} as Plan) } : undefined}
        buttons={[]}
      />

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {loading ? (
        <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
      ) : items.length === 0 ? (
        <EmptyState
          title={t('empty.title')}
          description={isAdmin ? t('empty.descriptionAdmin') : t('empty.descriptionUser')}
          button={isAdmin ? { label: t('addPlan'), onClick: () => setModal({} as Plan) } : undefined}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {items.map(plan => (
            <div key={plan.id} className={`bg-white dark:bg-slate-800 border rounded-2xl p-5 shadow-sm ${plan.is_default ? 'border-brand-400 ring-2 ring-brand-100 dark:ring-brand-900/40' : 'border-slate-200 dark:border-slate-700'}`}>
              <div className="flex items-start justify-between mb-2">
                <div className="min-w-0">
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    {plan.name}
                    {plan.is_default && <span className="text-[10px] uppercase tracking-wider bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 px-1.5 py-0.5 rounded font-semibold">{t('badge.default')}</span>}
                  </h3>
                  {plan.description && <p className="text-sm text-slate-500 dark:text-slate-500 mt-0.5">{plan.description}</p>}
                </div>
                {plan.php_version && <span className="shrink-0 text-[11px] font-mono font-semibold bg-slate-100 dark:bg-slate-700/60 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded">{t('phpVersion', { version: plan.php_version })}</span>}
              </div>

              <dl className="grid grid-cols-2 gap-y-1.5 text-sm mt-4">
                <Row label={t('rows.disk')} value={formatLimit(plan.disk_quota_mb, t('units.mb'), t('limit.unlimited'))} />
                <Row label={t('rows.traffic')} value={formatLimit(plan.traffic_quota_mb, t('units.mbPerMonth'), t('limit.unlimited'))} />
                <Row label={t('rows.domains')} value={formatLimit(plan.max_domain, t('units.domains'), t('limit.unlimited'))} />
                <Row label={t('rows.databases')} value={formatLimit(plan.max_db, t('units.databases'), t('limit.unlimited'))} />
                <Row label={t('rows.ftp')} value={formatLimit(plan.max_ftp, t('units.accounts'), t('limit.unlimited'))} />
                <Row label={t('rows.apps')} value={formatLimit(plan.max_app, t('units.apps'), t('limit.unlimited'))} />
              </dl>

              {/* Plan definition is the administrator's product; a reseller only
                  views them (the /plans write endpoints are AdminOnly too). */}
              {isAdmin && (
                <div className="mt-4 flex gap-2">
                  <Link to={`/tools/packages/${plan.id}`} className="flex-1 text-center text-sm px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-md">
                    {t('detailsButton')}
                  </Link>
                  <button onClick={() => setPlanToDelete(plan)} className="text-sm px-3 py-1.5 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 rounded-md">{t('delete')}</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {modal && (
        <PlanModal
          plan={modal}
          versions={versions}
          onClose={() => setModal(null)}
          onSave={() => { setModal(null); load() }}
        />
      )}

      <ConfirmDialog
        open={!!planToDelete}
        title={t('confirmDelete.title')}
        message={t('confirmDelete.message', { name: planToDelete?.name })}
        dangerous
        confirmText={t('confirmDelete.confirmText')}
        onConfirm={remove}
        onCancel={() => setPlanToDelete(null)}
      />
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-slate-500 dark:text-slate-500">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200 text-right font-mono">{value}</dd>
    </>
  )
}

function formatLimit(value: number, unit: string, unlimited: string) {
  if (value <= 0) return unlimited
  if (unit.startsWith('MB') && value >= 1024) return `${(value / 1024).toFixed(1)} G${unit.slice(2)}`
  return `${value.toLocaleString('en-US')} ${unit}`
}

function PlanModal({ plan, versions, onClose, onSave }: { plan: Plan; versions: Version[]; onClose: () => void; onSave: () => void }) {
  const newItem = !plan.id
  const [form, setForm] = useState<Plan>({
    id: plan.id || 0,
    name: plan.name || '',
    description: plan.description || '',
    disk_quota_mb: plan.disk_quota_mb || 1024,
    traffic_quota_mb: plan.traffic_quota_mb || 10240,
    max_domain: plan.max_domain || 1,
    max_db: plan.max_db || 1,
    max_email: plan.max_email || 0,
    mailbox_quota_mb: plan.mailbox_quota_mb || 0,
    mail_send_limit_hour: plan.mail_send_limit_hour || 0,
    mail_send_limit_day: plan.mail_send_limit_day || 0,
    max_ftp: plan.max_ftp || 2,
    max_app: plan.max_app || 0,
    php_version: plan.php_version || '8.3',
    fastcgi_cache: plan.fastcgi_cache || false,
    client_max_body_mb: plan.client_max_body_mb || 64,
    nginx_extra_directives: plan.nginx_extra_directives || '',
    waf_enabled: plan.waf_enabled || false,
    waf_mode: plan.waf_mode || 'on',
    waf_paranoia: plan.waf_paranoia || 1,
    is_default: plan.is_default || false,
    created_at: '',
  })
  const { t } = useTranslation('ServicePlansPage')
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const phpOptions = Array.from(new Set([
    ...versions.map(s => s.version),
    form.php_version,
    ...(versions.length === 0 ? ['7.4', '8.1', '8.2', '8.3', '8.4'] : []),
  ].filter(Boolean)))

  async function submit(e: React.SubmitEvent) {
    e.preventDefault()
    setProcessing(true); setError(null)
    try {
      if (newItem) await api.post('/plans', form)
      else await api.put(`/plans/${form.id}`, form)
      onSave()
    } catch (e) {
      setError(apiError(e, t('errors.saveFailed')))
    } finally {
      setProcessing(false)
    }
  }

  return (
    <Modal open={true} title={newItem ? t('modal.newTitle') : t('modal.editTitle')} onClose={onClose} width="lg">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <TextField label={t('modal.planName')} value={form.name} setValue={value => setForm({ ...form, name: value })} required />
          <TextField label={t('modal.description')} value={form.description} setValue={value => setForm({ ...form, description: value })} />
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Count label={t('modal.diskMb')} value={form.disk_quota_mb} setValue={value => setForm({ ...form, disk_quota_mb: value })} />
          <Count label={t('modal.trafficMb')} value={form.traffic_quota_mb} setValue={value => setForm({ ...form, traffic_quota_mb: value })} />
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('modal.phpVersionLabel')}</label>
            <select value={form.php_version} onChange={e => setForm({ ...form, php_version: e.target.value })}
              className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-800 rounded text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
              {phpOptions.map(v => <option key={v} value={v}>{t('phpVersion', { version: v })}</option>)}
            </select>
          </div>
          <Count label={t('modal.maxDomains')} value={form.max_domain} setValue={value => setForm({ ...form, max_domain: value })} />
          <Count label={t('modal.maxDatabases')} value={form.max_db} setValue={value => setForm({ ...form, max_db: value })} />
          <Count label={t('modal.maxFtp')} value={form.max_ftp} setValue={value => setForm({ ...form, max_ftp: value })} />
          <Count label={t('modal.maxApp')} value={form.max_app} setValue={value => setForm({ ...form, max_app: value })} />
          <Count label={t('modal.maxEmail')} value={form.max_email} setValue={value => setForm({ ...form, max_email: value })} />
          {/* Enforced by Dovecot through the mailbox row, not just displayed. */}
          <Count label={t('modal.mailboxQuotaMb')} value={form.mailbox_quota_mb} setValue={value => setForm({ ...form, mailbox_quota_mb: value })} />
          {/* 0 keeps the built-in per-mailbox default rather than removing the
              limit, because 0 on a mailbox row already means unlimited. */}
          <Count label={t('modal.mailSendLimitHour')} value={form.mail_send_limit_hour} setValue={value => setForm({ ...form, mail_send_limit_hour: value })} />
          <Count label={t('modal.mailSendLimitDay')} value={form.mail_send_limit_day} setValue={value => setForm({ ...form, mail_send_limit_day: value })} />
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
          <input type="checkbox" checked={form.is_default} onChange={e => setForm({ ...form, is_default: e.target.checked })} className="rounded" />
          {t('modal.isDefault')}
        </label>

        {/* WAF (ModSecurity + OWASP CRS) plan default */}
        <div className="border-t border-slate-200 dark:border-slate-700 pt-3">
          <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">{t('modal.wafHeading')}</h4>
          <div className="grid grid-cols-3 gap-3">
            <label className="flex items-center gap-2 h-[38px] px-3 border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50/60 dark:bg-slate-900/40 cursor-pointer">
              <input type="checkbox" checked={form.waf_enabled} onChange={e => setForm({ ...form, waf_enabled: e.target.checked })} className="rounded" />
              <span className="text-sm text-slate-700 dark:text-slate-300">{t('modal.wafEnabled')}</span>
            </label>
            <select value={form.waf_mode} onChange={e => setForm({ ...form, waf_mode: e.target.value })}
              disabled={!form.waf_enabled}
              className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-800 rounded text-sm disabled:opacity-50">
              <option value="on">{t('modal.wafMode.block')}</option>
              <option value="detect">{t('modal.wafMode.detect')}</option>
            </select>
            <select value={form.waf_paranoia} onChange={e => setForm({ ...form, waf_paranoia: Number(e.target.value) || 1 })}
              disabled={!form.waf_enabled}
              className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-800 rounded text-sm disabled:opacity-50">
              <option value={1}>{t('modal.wafParanoia.level1')}</option>
              <option value={2}>{t('modal.wafParanoia.level2')}</option>
              <option value={3}>{t('modal.wafParanoia.level3')}</option>
              <option value={4}>{t('modal.wafParanoia.level4')}</option>
            </select>
          </div>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-500">{t('modal.hint')}</p>

        {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-300">{error}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-md text-sm">{t('modal.cancel')}</button>
          <button type="submit" disabled={processing || !form.name.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded-md">{processing ? t('modal.saving') : (newItem ? t('modal.add') : t('modal.update'))}</button>
        </div>
      </form>
    </Modal>
  )
}

function TextField({ label, value, setValue, required }: { label: string; value: string; setValue: (value: string) => void; required?: boolean }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{label}</label>
      <input type="text" value={value} onChange={e => setValue(e.target.value)} required={required}
        className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
    </div>
  )
}
function Count({ label, value, setValue }: { label: string; value: number; setValue: (value: number) => void }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{label}</label>
      <input type="number" min={0} value={value} onChange={e => setValue(parseInt(e.target.value) || 0)}
        className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
    </div>
  )
}
