// The server-wide switch behind per-account remote database access.
//
// Admin only, and mounted above the list it controls so the operator turning it
// on can see what it produces. Turning it on restarts MariaDB, which drops every
// site's open connections, so the button says that before it is pressed rather
// than after.
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import type { RemoteStatus } from './DBRemoteAccess'

export default function DBRemoteServerSwitch({ onChange }: { onChange?: () => void }) {
  const { t } = useTranslation('DBRemoteAccess')
  const { notify, confirm } = useDialog()
  const report = useReportError()
  const [status, setStatus] = useState<RemoteStatus | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    api.get<RemoteStatus>('/admin/db-remote')
      .then(r => setStatus(r.data))
      .catch(report('dbRemote'))
      .finally(() => setLoaded(true))
  }, [report])

  useEffect(() => { load() }, [load])

  async function toggle(next: boolean) {
    const ok = await confirm({
      title: next ? t('switch.confirmOnTitle') : t('switch.confirmOffTitle'),
      message: next ? t('switch.confirmOn') : t('switch.confirmOff'),
      confirmLabel: t('switch.confirmAction'),
      dangerous: true,
    })
    if (!ok) return
    setSaving(true)
    try {
      const { data } = await api.put<RemoteStatus>('/admin/db-remote', { enabled: next })
      setStatus(data)
      onChange?.()
    } catch (caught) {
      const reason = apiReason(caught)
      await notify({
        message: reason ? t([`reasons.${reason}`, 'switch.failed']) : apiError(caught, t('switch.failed')),
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
            onChange={e => toggle(e.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
          />
          <span className="text-sm font-medium text-slate-900 dark:text-slate-100">{t('switch.label')}</span>
        </label>

        <span className="text-xs text-slate-400 dark:text-slate-500">
          {status.enabled
            ? t('switch.onHint', { port: status.port })
            : t('switch.offHint')}
        </span>

        {status.applied_at && (
          <span className="ml-auto text-xs text-slate-400 dark:text-slate-500">
            {t('switch.appliedAt', { time: status.applied_at })}
          </span>
        )}
      </div>

      {status.port_rule_conflict && (
        <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-900/20 dark:text-amber-300">
          {t('switch.portRuleConflict', { port: status.port })}
        </p>
      )}
      {status.last_error && (
        <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-900/20 dark:text-red-300">
          {t('switch.lastError', { message: status.last_error })}
        </p>
      )}
    </div>
  )
}
