import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'

type PanelDomainStatus = {
  custom_domain: string
  ssl_status: 'none' | 'active' | 'failed'
  ssl_error?: string
  ssl_expires?: string
  server_ipv4: string
  // Empty means this server has no globally routable IPv6 address. That is the
  // ordinary state on an IPv4-only host, not a fault, so the screen says which
  // of the two it is rather than showing a blank.
  server_ipv6: string
  has_ipv6: boolean
}

export default function PanelDomain() {
  const { t } = useTranslation('PanelDomain')
  const [status, setStatus] = useState<PanelDomainStatus | null>(null)
  const [domain, setDomain] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  // Starts true because the mount effect below always fetches; the old code
  // reached the same state by flipping it on from inside that effect.
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [resetting, setResetting] = useState(false)

  // Writes only from the promise callbacks, so the mount effect can call it
  // without forcing a second render pass. Raising the spinner belongs to the
  // event path, which is what reload() adds for the save and reset handlers.
  const fetchStatus = useCallback(() => {
    return api.get<PanelDomainStatus>('/system/panel-domain')
      .then(response => {
        setStatus(response.data)
        setDomain(response.data.custom_domain || '')
      })
      .catch(caughtError => setError(apiError(caughtError, t('errors.load'))))
      .finally(() => setLoading(false))
  }, [t])

  function reload() {
    setLoading(true)
    setError('')
    return fetchStatus()
  }

  useEffect(() => { fetchStatus() }, [fetchStatus])

  async function save(event: React.FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    setSaving(true)
    try {
      const response = await api.post<{ custom_domain: string; ssl_status: string; warning?: string }>('/system/panel-domain', { domain: domain.trim() })
      setMessage(response.data.warning || t('messages.saved', { domain: domain.trim() }))
      await reload()
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.save')))
    } finally {
      setSaving(false)
    }
  }

  async function reset() {
    setMessage('')
    setError('')
    setResetting(true)
    try {
      await api.delete('/system/panel-domain')
      setMessage(t('messages.reset'))
      await reload()
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.reset')))
    } finally {
      setResetting(false)
    }
  }

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 0 20"/><path d="M12 2a15.3 15.3 0 0 0 0 20"/></svg>
        </div>
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{t('description')}</p>
        </div>
      </div>

      <form onSubmit={save} className="space-y-4">
        <div className="grid sm:grid-cols-2 gap-4">
          <label className="block">
            <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('customDomainLabel')}</span>
            <input value={domain} onChange={event => setDomain(event.target.value)} placeholder={t('customDomainPlaceholder')} disabled={loading || saving}
              className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-60" />
          </label>
          <div className="text-xs text-slate-500 dark:text-slate-400 rounded-xl border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900">
            <div>{t('serverIpv4')} <span className="font-mono text-slate-800 dark:text-slate-100">{status?.server_ipv4 || t('unknown')}</span></div>
            <div>{t('serverIpv6')} <span className="font-mono text-slate-800 dark:text-slate-100">{status?.server_ipv6 || (status?.has_ipv6 ? t('ipv6NoRoutable') : t('ipv6None'))}</span></div>
            <div>{t('sslStatus')} <span className="font-semibold text-slate-800 dark:text-slate-100">{status?.ssl_status || t('sslNone')}</span></div>
            {status?.ssl_status === 'active' && status.custom_domain && <div>{t('portlessUrl')} <span className="font-mono text-slate-800 dark:text-slate-100">https://{status.custom_domain}</span></div>}
            {status?.ssl_expires && <div>{t('expires')} <span className="font-mono text-slate-800 dark:text-slate-100">{status.ssl_expires}</span></div>}
          </div>
        </div>

        {status?.ssl_error && <div className="text-sm px-3 py-2 rounded-lg border bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300">{status.ssl_error}</div>}
        {message && <div className="text-sm px-3 py-2 rounded-lg border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300">{message}</div>}
        {error && <div className="text-sm px-3 py-2 rounded-lg border bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300">{error}</div>}

        <div className="flex items-center gap-3 flex-wrap">
          <button type="submit" disabled={saving || !domain.trim()} className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-50">
            {saving ? t('saving') : t('save')}
          </button>
          <button type="button" onClick={reset} disabled={resetting || !status?.custom_domain} className="px-4 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">
            {resetting ? t('resetting') : t('reset')}
          </button>
        </div>
      </form>
    </section>
  )
}
