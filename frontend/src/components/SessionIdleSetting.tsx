import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'

type SessionIdle = {
  minutes: number
  max: number
}

/**
 * Server-wide idle timeout.
 *
 * This is not the JWT lifetime: the lifetime ends a session a fixed time after
 * it was issued, this one ends it a fixed time after the last request. Both
 * apply at once, so the copy says which one this is.
 */
export default function SessionIdleSetting() {
  const { t } = useTranslation('SessionIdleSetting')
  const role = useAuth(state => state.username?.role)
  const [status, setStatus] = useState<SessionIdle | null>(null)
  const [minutes, setMinutes] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const isAdmin = role === 'admin'

  // Writes only from the promise callbacks, so the mount effect never sets
  // state synchronously. t is a real dependency because the failure uses it.
  const load = useCallback(() => {
    if (!isAdmin) return
    api.get<SessionIdle>('/system/session-idle')
      .then(response => {
        setStatus(response.data)
        setMinutes(String(response.data.minutes))
      })
      .catch(cause => setError(apiError(cause, t('errors.load'))))
  }, [isAdmin, t])

  useEffect(() => { load() }, [load])

  async function save() {
    setError('')
    setMessage('')
    setSaving(true)
    try {
      const response = await api.put<SessionIdle>('/system/session-idle', { minutes: Number(minutes) })
      setStatus(response.data)
      setMinutes(String(response.data.minutes))
      setMessage(response.data.minutes === 0 ? t('messages.disabled') : t('messages.saved', { minutes: response.data.minutes }))
    } catch (cause) {
      setError(apiError(cause, '') === 'session_idle_out_of_range'
        ? t('errors.outOfRange', { max: status?.max ?? 1440 })
        : apiError(cause, t('errors.save')))
    } finally {
      setSaving(false)
    }
  }

  // The endpoints are admin only, so a reseller or customer would collect a 403
  // and be shown an error for a control they are not offered.
  if (!isAdmin) return null

  const parsed = Number(minutes)
  const unchanged = Number.isInteger(parsed) && parsed === status?.minutes
  const malformed = minutes.trim() === '' || !Number.isInteger(parsed) || parsed < 0

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        </div>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
            {status && (
              <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                status.minutes > 0
                  ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                  : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'
              }`}>
                {status.minutes > 0 ? t('on') : t('off')}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{t('description')}</p>
        </div>
      </div>

      {error && <div className="text-sm px-3 py-2 rounded-lg border bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 mb-3">{error}</div>}
      {message && <div className="text-sm px-3 py-2 rounded-lg border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 mb-3">{message}</div>}

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <label className="text-sm text-slate-700 dark:text-slate-300" htmlFor="session-idle-minutes">
          {t('label')}
        </label>
        <input
          id="session-idle-minutes"
          type="number"
          min={0}
          max={status?.max ?? 1440}
          step={1}
          value={minutes}
          onChange={event => setMinutes(event.target.value)}
          className="w-32 px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
        />
        <button
          type="button"
          onClick={save}
          disabled={saving || malformed || unchanged}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? t('applying') : t('apply')}
        </button>
      </div>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">{t('hint', { max: status?.max ?? 1440 })}</p>
    </section>
  )
}
