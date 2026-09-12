import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { FormAlerts } from './FormAlerts'

type HostnameStatus = {
  hostname: string
  protected: boolean
  note: string
}

// ProtectionBadge says whether the panel certificate already covers the
// hostname. It draws nothing until the status has been read.
function ProtectionBadge({ status }: { status: HostnameStatus | null }) {
  const { t } = useTranslation('HostnameSetting')
  if (!status) return null
  return (
    <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
      status.protected
        ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
        : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
    }`}>
      {status.protected ? t('protected') : t('awaitingProtection')}
    </span>
  )
}

export default function HostnameSetting() {
  const { t } = useTranslation('HostnameSetting')
  const [status, setStatus] = useState<HostnameStatus | null>(null)
  const [hostname, setHostname] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  // Promise callbacks rather than await/try: this is what the mount effect calls,
  // and writes sitting in an awaited body still count as the effect's own
  // continuation. t is a real dependency because the failure message uses it.
  const load = useCallback(() => {
    api.get<HostnameStatus>('/system/hostname')
      .then(response => {
        setStatus(response.data)
        setHostname(response.data.hostname)
      })
      .catch(caughtError => setError(apiError(caughtError, t('errors.load'))))
  }, [t])

  useEffect(() => { load() }, [load])

  async function save() {
    setError('')
    setMessage('')
    setSaving(true)
    try {
      const response = await api.put<HostnameStatus>('/system/hostname', { hostname: hostname.trim() })
      setStatus(response.data)
      setHostname(response.data.hostname)
      setMessage(t('messages.changed', { hostname: response.data.hostname }))
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.change')))
    } finally {
      setSaving(false)
    }
  }

  const unchanged = hostname.trim().toLowerCase() === (status?.hostname.toLowerCase() ?? '')

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5.25 14.25h13.5m-13.5 0a3 3 0 1 0 0 6h13.5a3 3 0 1 0 0-6m-13.5 0a3 3 0 1 1 0-6h13.5a3 3 0 1 1 0 6M18 11.25h.008v.008H18v-.008Zm0 6h.008v.008H18v-.008Z"/></svg>
        </div>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
            <ProtectionBadge status={status} />
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
            {t('descriptionPre')}<code className="text-[11px]">server1.example.com</code>
          </p>
        </div>
      </div>

      <FormAlerts error={error} message={message} />

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <input
          type="text"
          value={hostname}
          onChange={event => setHostname(event.target.value)}
          placeholder={t('placeholder')}
          autoComplete="off"
          spellCheck={false}
          maxLength={253}
          className="w-full max-w-md px-3 py-2 font-mono text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
        />
        <button
          type="button"
          onClick={save}
          disabled={saving || !hostname.trim() || unchanged}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? t('applying') : t('apply')}
        </button>
      </div>
    </section>
  )
}
