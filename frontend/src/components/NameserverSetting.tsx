import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'
import ConfirmDialog from './ConfirmDialog'
import { FormAlerts } from './FormAlerts'

type NameserverSettings = {
  ns1: string
  ns2: string
  source?: string
  suggested_ns1?: string
  suggested_ns2?: string
}

type MigrationResult = { total: number; updated: number; failed?: string[] }

// audienceScope resolves which pair this mount edits. The card is mounted twice
// with an explicit audience, so the signed-in role alone does not decide it.
function audienceScope(audience: 'admin' | 'reseller', role: string | undefined) {
  const isAdmin = audience === 'admin' && role === 'admin'
  const isReseller = audience === 'reseller' && role === 'reseller'
  return { isAdmin, isReseller, endpoint: isAdmin ? '/nameservers' : '/reseller/nameservers' }
}

// SourceNotice says where the pair in the fields came from: nothing configured
// yet, or the panel pair a reseller has not overridden.
function SourceNotice({ settings, isAdmin, isReseller }: {
  settings: NameserverSettings | null
  isAdmin: boolean
  isReseller: boolean
}) {
  const { t } = useTranslation('NameserverSetting')
  if (settings?.source === 'none') {
    return (
      <div className="text-sm px-3 py-2 rounded-lg border bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-300 mb-3">
        {isAdmin ? t('warnings.unconfiguredAdmin') : t('warnings.unconfiguredReseller')}
        {settings.suggested_ns1 && <span className="block mt-1">{t('warnings.suggestion')}</span>}
      </div>
    )
  }
  if (settings?.source === 'panel' && isReseller) {
    return (
      <div className="text-sm px-3 py-2 rounded-lg border bg-sky-50 dark:bg-sky-900/20 border-sky-200 dark:border-sky-800 text-sky-800 dark:text-sky-300 mb-3">
        {t('warnings.usingPanelPair')}
      </div>
    )
  }
  return null
}

// MigrateButton rewrites every existing zone to the saved pair. It is admin
// only, and disabled while nothing is configured: the migration writes the
// RESOLVED pair, which with no setting is the vanity fallback, so running it
// then would stamp ns1.<domain> into every zone.
function MigrateButton({ isAdmin, migrating, settings, onOpen }: {
  isAdmin: boolean
  migrating: boolean
  settings: NameserverSettings | null
  onOpen: () => void
}) {
  const { t } = useTranslation('NameserverSetting')
  if (!isAdmin) return null
  const unconfigured = settings?.source === 'none'
  return (
    <button type="button" onClick={onOpen}
      disabled={migrating || unconfigured}
      title={unconfigured ? t('migrateDisabledHint') : undefined}
      className="px-4 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50">
      {migrating ? t('migrating') : t('migrate')}
    </button>
  )
}

// The shared nameserver pair every customer zone publishes. An admin sets the
// panel-wide pair; a reseller sets its own white-label pair for the domains of
// the customers it manages. Customers only read the resolved pair, on the
// connection details page.
//
// The two audiences reach the panel through different menus, so the card is
// mounted twice with an explicit audience rather than once for both roles:
// admins find server settings under Tools & Settings, while a reseller never
// sees that admin page and manages its white-label pair from its profile.
export default function NameserverSetting({ audience }: { audience: 'admin' | 'reseller' }) {
  const { t } = useTranslation('NameserverSetting')
  const role = useAuth(state => state.username?.role)
  const { isAdmin, isReseller, endpoint } = audienceScope(audience, role)

  const [settings, setSettings] = useState<NameserverSettings | null>(null)
  const [ns1, setNS1] = useState('')
  const [ns2, setNS2] = useState('')
  const [saving, setSaving] = useState(false)
  const [migrating, setMigrating] = useState(false)
  const [migrateOpen, setMigrateOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(() => {
    if (!isAdmin && !isReseller) return
    api.get<NameserverSettings>(endpoint).then(response => {
      setSettings(response.data)
      // When nothing is configured the suggestion is written into the FIELD but
      // never saved: a wrong nameserver silently stops every customer domain
      // from resolving, so a human has to confirm the guess first.
      setNS1(response.data.ns1 || response.data.suggested_ns1 || '')
      setNS2(response.data.ns2 || response.data.suggested_ns2 || '')
    }).catch(() => { /* the card stays hidden when the role may not read it */ })
  }, [endpoint, isAdmin, isReseller])

  useEffect(() => { load() }, [load])

  async function save() {
    setSaving(true); setMessage(''); setError('')
    try {
      const response = await api.put<NameserverSettings>(endpoint, { ns1: ns1.trim(), ns2: ns2.trim() })
      setSettings(response.data)
      setMessage(isReseller ? t('messages.savedReseller') : t('messages.saved'))
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.save')))
    } finally {
      setSaving(false)
    }
  }

  async function migrate() {
    setMigrateOpen(false); setMigrating(true); setMessage(''); setError('')
    try {
      const response = await api.post<MigrationResult>('/nameservers/migrate', {})
      setMessage(t('messages.migrated', { updated: response.data.updated, total: response.data.total }))
      if (response.data.failed?.length) {
        setError(t('errors.migratePartial', { domains: response.data.failed.join(', ') }))
      }
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.migrate')))
    } finally {
      setMigrating(false)
    }
  }

  if (!isAdmin && !isReseller) return null

  const inputClasses = 'w-full px-3 py-2 font-mono text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="7" rx="2" /><rect x="2" y="13" width="20" height="7" rx="2" /><path d="M6 7.5h.01M6 16.5h.01" /></svg>
        </div>
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
            {isAdmin ? t('descriptionAdmin') : t('descriptionReseller')}
          </p>
        </div>
      </div>

      <SourceNotice settings={settings} isAdmin={isAdmin} isReseller={isReseller} />
      <FormAlerts error={error} message={message} />

      <div className="grid gap-4 sm:grid-cols-2 mb-4">
        <label className="block">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">NS1</span>
          <input type="text" value={ns1} onChange={event => setNS1(event.target.value)}
            placeholder="ns1.example.com" autoComplete="off" spellCheck={false} maxLength={253} className={inputClasses} />
        </label>
        <label className="block">
          <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">NS2</span>
          <input type="text" value={ns2} onChange={event => setNS2(event.target.value)}
            placeholder="ns2.example.com" autoComplete="off" spellCheck={false} maxLength={253} className={inputClasses} />
        </label>
      </div>

      <p className="text-xs text-slate-500 dark:text-slate-500 mb-4">{t('glueReminder')}</p>

      <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={save} disabled={saving || !ns1.trim() || !ns2.trim()}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50">
          {saving ? t('saving') : t('save')}
        </button>
        <MigrateButton isAdmin={isAdmin} migrating={migrating} settings={settings}
          onOpen={() => setMigrateOpen(true)} />
      </div>

      <ConfirmDialog
        open={migrateOpen}
        title={t('migrateConfirm.title')}
        message={t('migrateConfirm.message')}
        confirmText={t('migrateConfirm.action')}
        onConfirm={migrate}
        onCancel={() => setMigrateOpen(false)}
      />
    </section>
  )
}
