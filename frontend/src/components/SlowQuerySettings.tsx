// The switch and the threshold behind the server-wide slow query view.
//
// Admin-only, mounted beside the table it controls rather than on the settings
// page, so the operator changing the threshold can see what it produces.
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'

type Status = {
  enabled: boolean
  seconds: number
  log_path: string
  log_size_kb: number
  log_present: boolean
  collected_at?: string
  last_error?: string
  min_seconds: number
  max_seconds: number
  retention_days: number
}

// The thresholds worth offering. A free-form number invites 0.01, which turns
// the slow log into the general log and the server into its own bottleneck.
const CHOICES = [0.5, 1, 2, 5, 10] as const

export default function SlowQuerySettings({ onChange }: { onChange?: () => void }) {
  const { t } = useTranslation('SlowQueryTable')
  const { notify } = useDialog()
  const report = useReportError()
  const [status, setStatus] = useState<Status | null>(null)
  const [saving, setSaving] = useState(false)
  const [loaded, setLoaded] = useState(false)

  const load = useCallback(() => {
    api.get<Status>('/admin/slow-queries/status')
      .then(r => setStatus(r.data))
      .catch(report('slowQueries'))
      .finally(() => setLoaded(true))
  }, [report])

  useEffect(() => { load() }, [load])

  async function save(next: Partial<Pick<Status, 'enabled' | 'seconds'>>) {
    setSaving(true)
    try {
      const { data } = await api.put<Status>('/admin/slow-queries/settings', next)
      setStatus(data)
      onChange?.()
    } catch (caught) {
      const reason = apiReason(caught)
      await notify({
        message: reason ? t([`reasons.${reason}`, 'saveFailed']) : apiError(caught, t('saveFailed')),
        tone: 'error',
      })
    } finally {
      setSaving(false)
    }
  }

  if (!loaded) return <div className="py-4 text-sm text-slate-400">{t('loading')}</div>
  if (!status) return null

  return (
    <div className="mb-4 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            checked={status.enabled}
            disabled={saving}
            onChange={e => save({ enabled: e.target.checked })}
            className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
          />
          <span className="text-sm font-medium text-slate-900 dark:text-slate-100">{t('settings.enabled')}</span>
        </label>

        <div className="flex items-center gap-2">
          <span className="text-sm text-slate-500 dark:text-slate-400">{t('settings.threshold')}</span>
          <div className="inline-flex rounded-lg bg-slate-100 p-0.5 dark:bg-slate-900">
            {CHOICES.map(value => (
              <button
                key={value}
                type="button"
                disabled={saving || !status.enabled}
                onClick={() => save({ seconds: value })}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-50 ${
                  Math.abs(status.seconds - value) < 0.001
                    ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                    : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                {t('settings.seconds', { count: value })}
              </button>
            ))}
          </div>
        </div>

        <div className="ml-auto text-xs text-slate-400 dark:text-slate-500">
          {status.log_present
            ? t('settings.logSize', { size: formatKB(status.log_size_kb) })
            : t('settings.logMissing')}
          {status.collected_at && <> · {t('settings.collectedAt', { time: status.collected_at })}</>}
          <> · {t('settings.retention', { count: status.retention_days })}</>
        </div>
      </div>

      {status.last_error && (
        <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-900/20 dark:text-red-300">
          {t('settings.lastError', { message: status.last_error })}
        </p>
      )}
      {!status.enabled && (
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">{t('settings.offHint')}</p>
      )}
    </div>
  )
}

function formatKB(kb: number): string {
  if (kb < 1024) return `${kb} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb.toFixed(1)} MB`
  return `${(mb / 1024).toFixed(2)} GB`
}
