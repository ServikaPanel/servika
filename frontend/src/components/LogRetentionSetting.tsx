import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'
import { FormAlerts } from './FormAlerts'

type LogRetention = {
  days: number
  min: number
  max: number
}

// What the field accepts until the server answers. The server owns the real
// bounds and sends them in `min` and `max`.
const DEFAULT_MIN = 1
const DEFAULT_MAX = 365

function bounds(status: LogRetention | null) {
  return { min: status?.min ?? DEFAULT_MIN, max: status?.max ?? DEFAULT_MAX }
}

// fieldState reports what the Apply button needs to know about the field:
// whether it still holds the saved value, and whether it holds something the
// server would refuse.
function fieldState(days: string, status: LogRetention | null) {
  const parsed = Number(days)
  return {
    unchanged: Number.isInteger(parsed) && parsed === status?.days,
    malformed: days.trim() === '' || !Number.isInteger(parsed) || parsed < 1,
  }
}

/**
 * How long the panel keeps its own request and application log rows.
 *
 * Nothing else deletes those rows, so this number decides how large the two
 * tables get. It does not touch the audit log, which records who changed what
 * and is kept whatever this says.
 */
export default function LogRetentionSetting() {
  const { t } = useTranslation('LogRetentionSetting')
  const role = useAuth(state => state.username?.role)
  const [status, setStatus] = useState<LogRetention | null>(null)
  const [days, setDays] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const isAdmin = role === 'admin'

  const load = useCallback(() => {
    if (!isAdmin) return
    api.get<LogRetention>('/system/log-retention')
      .then(response => {
        setStatus(response.data)
        setDays(String(response.data.days))
      })
      .catch(cause => setError(apiError(cause, t('errors.load'))))
  }, [isAdmin, t])

  useEffect(() => { load() }, [load])

  async function save() {
    setError('')
    setMessage('')
    setSaving(true)
    try {
      const response = await api.put<LogRetention>('/system/log-retention', { days: Number(days) })
      setStatus(response.data)
      setDays(String(response.data.days))
      setMessage(t('messages.saved', { days: response.data.days }))
    } catch (cause) {
      setError(apiError(cause, '') === 'log_retention_out_of_range'
        ? t('errors.outOfRange', bounds(status))
        : apiError(cause, t('errors.save')))
    } finally {
      setSaving(false)
    }
  }

  // The endpoints are admin only, so a reseller or customer would collect a 403
  // and be shown an error for a control they are not offered.
  if (!isAdmin) return null

  const limits = bounds(status)
  const { unchanged, malformed } = fieldState(days, status)

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>
        </div>
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{t('description')}</p>
        </div>
      </div>

      <FormAlerts error={error} message={message} />

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <label className="text-sm text-slate-700 dark:text-slate-300" htmlFor="log-retention-days">
          {t('label')}
        </label>
        <input
          id="log-retention-days"
          type="number"
          min={limits.min}
          max={limits.max}
          step={1}
          value={days}
          onChange={event => setDays(event.target.value)}
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
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">{t('hint', { min: limits.min, max: limits.max })}</p>
    </section>
  )
}
