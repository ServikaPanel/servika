import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'

type MaintenanceIP = {
  id: number
  ip: string
  note: string
  created_at: string
}

type MaintenanceStatus = {
  enabled: boolean
  /** MySQL-formatted end time, empty when the mode is open-ended. */
  until: string
  title: string
  message: string
  accent: string
  logo_url: string
  /** The address this browser reached the panel from, offered as one click. */
  client_ip: string
  /** False when the domain renders a vhost the fragment can never reach. */
  available: boolean
  reason?: string
  ips: MaintenanceIP[]
}

// The durations the screen offers. 0 is open-ended: the mode lasts until
// someone turns it off, which is what an unplanned outage needs.
const DURATIONS = [0, 30, 60, 120, 240] as const

const DEFAULT_ACCENT = '#0f172a'

function ownIPListedOf(status: MaintenanceStatus | null): boolean {
  return Boolean(status && status.ips.some(entry => entry.ip === status.client_ip))
}

function isBlocked(status: MaintenanceStatus | null): boolean {
  return Boolean(status && !status.available)
}

function Banners({ error, success }: { error: string | null; success: string | null }) {
  return (
    <>
      {error && <div className="mt-4 text-sm px-3 py-2 rounded-lg border bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mt-4 text-sm px-3 py-2 rounded-lg border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300">{success}</div>}
    </>
  )
}

function BlockedNotice({ blocked, reason }: { blocked: boolean; reason?: string }) {
  const { t } = useTranslation('DomainMaintenancePage')
  if (!blocked) return null
  return (
    <div className="mt-4 text-sm px-3 py-2 rounded-lg border bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-300">
      {t([`reasons.${reason}`, 'reasons.unavailable'])}
    </div>
  )
}

function SwitchCard({ status, saving, blocked, duration, onDuration, onTurnOn, onTurnOff }: {
  status: MaintenanceStatus | null; saving: boolean; blocked: boolean
  duration: number; onDuration: (value: number) => void
  onTurnOn: () => void; onTurnOff: () => void
}) {
  const { t } = useTranslation('DomainMaintenancePage')
  const enabled = status?.enabled === true
  // The switch. Turning it on is one click; turning it off asks first, because a
  // customer who meant to change the message would otherwise publish the site
  // mid-edit.
  return (
    <div className="mt-5 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-slate-800 dark:text-slate-100">
            {enabled ? t('state.on') : t('state.off')}
          </div>
          {enabled && status && (
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {status.until ? t('state.until', { time: status.until }) : t('state.openEnded')}
            </div>
          )}
        </div>
        {enabled ? (
          <button type="button" onClick={onTurnOff} disabled={saving}
            className="text-sm px-4 py-2 rounded-lg bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:opacity-90 disabled:opacity-50">
            {t('action.off')}
          </button>
        ) : (
          <button type="button" onClick={onTurnOn} disabled={saving || blocked}
            className="text-sm px-4 py-2 rounded-lg bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-50">
            {t('action.on')}
          </button>
        )}
      </div>

      {!enabled && (
        <label className="block mt-4">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('duration.label')}</span>
          <select value={duration} onChange={event => onDuration(Number(event.target.value))} disabled={blocked}
            className="text-sm px-2 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200">
            {DURATIONS.map(minutes => (
              <option key={minutes} value={minutes}>
                {minutes === 0 ? t('duration.openEnded') : t('duration.minutes', { count: minutes })}
              </option>
            ))}
          </select>
          <span className="block text-xs text-slate-400 mt-1">{t('duration.hint')}</span>
        </label>
      )}
    </div>
  )
}

type PageFields = {
  title: string; onTitle: (value: string) => void
  message: string; onMessage: (value: string) => void
  accent: string; onAccent: (value: string) => void
  logoURL: string; onLogoURL: (value: string) => void
}

function PageCard({ fields, saving, onSave }: { fields: PageFields; saving: boolean; onSave: () => void }) {
  const { t } = useTranslation('DomainMaintenancePage')
  // The page visitors see. The panel builds the HTML from these fields, so
  // nothing here can produce a broken document.
  return (
    <div className="mt-5 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
      <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{t('page.title')}</h2>
      <div className="grid sm:grid-cols-2 gap-4 mt-3">
        <label className="block sm:col-span-2">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('page.heading')}</span>
          <input value={fields.title} onChange={event => fields.onTitle(event.target.value)} maxLength={160}
            placeholder={t('page.headingPlaceholder')}
            className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100" />
        </label>
        <label className="block sm:col-span-2">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('page.message')}</span>
          <textarea value={fields.message} onChange={event => fields.onMessage(event.target.value)} maxLength={600} rows={3}
            placeholder={t('page.messagePlaceholder')}
            className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100" />
        </label>
        <label className="block">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('page.accent')}</span>
          <input type="color" value={fields.accent} onChange={event => fields.onAccent(event.target.value)}
            className="h-9 w-20 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900" />
        </label>
        <label className="block">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('page.logo')}</span>
          <input value={fields.logoURL} onChange={event => fields.onLogoURL(event.target.value)} maxLength={512}
            placeholder="https://…"
            className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100" />
          <span className="block text-xs text-slate-400 mt-1">{t('page.logoHint')}</span>
        </label>
      </div>

      {/* A preview built from the same fields, so the customer sees the shape
          before any visitor does. */}
      <div className="mt-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 p-6 text-center">
        <div className="h-1 w-14 rounded mx-auto mb-5" style={{ background: fields.accent }} />
        <div className="text-base font-semibold" style={{ color: fields.accent }}>{fields.title || t('page.previewTitle')}</div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-2 whitespace-pre-line">{fields.message || t('page.previewMessage')}</p>
      </div>

      <div className="mt-4">
        <button type="button" onClick={onSave} disabled={saving}
          className="text-sm px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50">
          {saving ? t('action.saving') : t('action.savePage')}
        </button>
      </div>
    </div>
  )
}

function IPRow({ entry, clientIP, saving, onRemove }: {
  entry: MaintenanceIP; clientIP: string; saving: boolean; onRemove: (ipID: number) => void
}) {
  const { t } = useTranslation('DomainMaintenancePage')
  return (
    <li className="flex items-center justify-between py-2 gap-3">
      <div className="min-w-0">
        <span className="font-mono text-sm text-slate-800 dark:text-slate-100 break-all">{entry.ip}</span>
        {entry.ip === clientIP && (
          <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">{t('ips.yours')}</span>
        )}
        {entry.note && <span className="ml-2 text-xs text-slate-400">{entry.note}</span>}
      </div>
      <button type="button" onClick={() => onRemove(entry.id)} disabled={saving}
        className="text-xs px-2 py-1 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50">
        {t('ips.remove')}
      </button>
    </li>
  )
}

function IPsCard({ status, newIP, onNewIP, saving, onAdd, onRemove }: {
  status: MaintenanceStatus | null; newIP: string; onNewIP: (value: string) => void
  saving: boolean; onAdd: (value: string) => void; onRemove: (ipID: number) => void
}) {
  const { t } = useTranslation('DomainMaintenancePage')
  const clientIP = status?.client_ip || ''
  const showOwn = clientIP !== '' && !ownIPListedOf(status)
  const entries = status?.ips || []
  // The addresses that reach the real site while the mode is on.
  return (
    <div className="mt-5 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
      <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{t('ips.title')}</h2>
      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('ips.hint')}</p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input value={newIP} onChange={event => onNewIP(event.target.value)}
          placeholder={t('ips.placeholder')}
          className="px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100" />
        <button type="button" onClick={() => onAdd(newIP)} disabled={saving || !newIP.trim()}
          className="text-sm px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50">
          {t('ips.add')}
        </button>
        {showOwn && (
          <button type="button" onClick={() => onAdd(clientIP)} disabled={saving}
            className="text-sm px-3 py-2 rounded-lg bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:opacity-90 disabled:opacity-50">
            {t('ips.addOwn', { ip: clientIP })}
          </button>
        )}
      </div>

      {entries.length > 0 ? (
        <ul className="mt-3 divide-y divide-slate-100 dark:divide-slate-800">
          {entries.map(entry => (
            <IPRow key={entry.id} entry={entry} clientIP={clientIP} saving={saving} onRemove={onRemove} />
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-xs text-slate-400">{t('ips.empty')}</p>
      )}
    </div>
  )
}

export default function DomainMaintenancePage() {
  const { t } = useTranslation('DomainMaintenancePage')
  const { id } = useParams()
  const { confirm } = useDialog()
  const report = useReportError()

  const [status, setStatus] = useState<MaintenanceStatus | null>(null)
  const [title, setTitle] = useState('')
  const [message, setMessage] = useState('')
  const [accent, setAccent] = useState(DEFAULT_ACCENT)
  const [logoURL, setLogoURL] = useState('')
  const [duration, setDuration] = useState<number>(0)
  const [newIP, setNewIP] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Every state change settles through a promise callback. A mount effect that
  // called setState synchronously would trip the react-hooks
  // set-state-in-effect rule, which is a hard CI gate here.
  const apply = useCallback((data: MaintenanceStatus) => {
    setStatus(data)
    setTitle(data.title)
    setMessage(data.message)
    setAccent(data.accent || DEFAULT_ACCENT)
    setLogoURL(data.logo_url)
  }, [])

  useEffect(() => {
    if (!id) return
    api.get<MaintenanceStatus>(`/domains/${id}/maintenance`)
      .then(response => apply(response.data))
      .catch(report('maintenance'))
  }, [id, apply, report])

  // The backend answers a refusal with a stable reason code, because this
  // screen renders twelve languages and an English sentence from the API could
  // not be shown in the other eleven.
  function describe(caught: unknown, fallback: string): string {
    const reason = apiReason(caught)
    return reason ? t([`reasons.${reason}`, fallback]) : apiError(caught, t(fallback))
  }

  async function save(enabled: boolean) {
    if (!id) return
    setSaving(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.put<MaintenanceStatus>(`/domains/${id}/maintenance`, {
        enabled,
        title,
        message,
        accent,
        logo_url: logoURL,
        duration_minutes: enabled ? duration : 0,
      })
      apply(data)
      setSuccess(enabled ? t('saved.on') : t('saved.off'))
    } catch (caught) {
      setError(describe(caught, 'saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  async function turnOff() {
    const ok = await confirm({
      title: t('confirmOff.title'),
      message: t('confirmOff.message'),
      confirmLabel: t('confirmOff.confirm'),
    })
    if (ok) await save(false)
  }

  async function addIP(value: string) {
    if (!id) return
    setSaving(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.post<MaintenanceStatus>(`/domains/${id}/maintenance/ips`, { ip: value })
      apply(data)
      setNewIP('')
    } catch (caught) {
      setError(describe(caught, 'ipAddFailed'))
    } finally {
      setSaving(false)
    }
  }

  async function removeIP(ipID: number) {
    if (!id) return
    setSaving(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.delete<MaintenanceStatus>(`/domains/${id}/maintenance/ips/${ipID}`)
      apply(data)
    } catch (caught) {
      setError(describe(caught, 'ipRemoveFailed'))
    } finally {
      setSaving(false)
    }
  }

  const blocked = isBlocked(status)

  return (
    <div className="p-4 sm:p-6 max-w-4xl">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.maintenance') },
      ]} />

      <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100 mt-3">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('description')}</p>

      <Banners error={error} success={success} />

      <BlockedNotice blocked={blocked} reason={status?.reason} />

      <SwitchCard status={status} saving={saving} blocked={blocked} duration={duration}
        onDuration={setDuration} onTurnOn={() => save(true)} onTurnOff={turnOff} />

      <PageCard
        fields={{
          title, onTitle: setTitle,
          message, onMessage: setMessage,
          accent, onAccent: setAccent,
          logoURL, onLogoURL: setLogoURL,
        }}
        saving={saving}
        onSave={() => save(status?.enabled === true)}
      />

      <IPsCard status={status} newIP={newIP} onNewIP={setNewIP} saving={saving} onAdd={addIP} onRemove={removeIP} />

      {/* Two facts that are invisible from the screen and surprise people. */}
      <div className="mt-5 text-xs text-slate-500 dark:text-slate-400 space-y-1.5">
        <p>{t('notes.subdomains')}</p>
        <p>{t('notes.wordpress')}</p>
        <p>{t('notes.seo')}</p>
      </div>
    </div>
  )
}
