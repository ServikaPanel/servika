// Which addresses may reach a database account from outside the server.
//
// One component for both audiences: a site owner manages one account through the
// modal on their databases page, and an admin sees every allowed address on the
// server. The labels are written once, and neither screen can drift into
// describing the rule differently from the other.
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import {
  responsiveTableBodyClass, responsiveTableCellClass, responsiveTableClass,
  responsiveTableContainerClass, responsiveTableHeadClass, responsiveTableRowClass,
} from '@/lib/table'

export type RemoteHost = {
  id: number
  domain_id: number
  domain_name?: string
  db_user: string
  host: string
  label: string
  created_at: string
}

export type RemoteStatus = {
  enabled: boolean
  port: number
  port_rule_conflict?: boolean
  last_error?: string
  applied_at?: string
  hosts: RemoteHost[]
}

export default function DBRemoteAccess({
  domainId, dbUser, showDomain = false, onChange,
}: {
  /** Omitted on the admin view, which reads the server-wide list. */
  domainId?: number
  /** Set on the customer view: the account being opened. */
  dbUser?: string
  /** The server-wide view names the tenant; a site owner's does not need to. */
  showDomain?: boolean
  onChange?: () => void
}) {
  const { t } = useTranslation('DBRemoteAccess')
  const { notify } = useDialog()
  const report = useReportError()
  const [status, setStatus] = useState<RemoteStatus | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [host, setHost] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)

  const endpoint = domainId ? `/domains/${domainId}/db-remote` : '/admin/db-remote'

  const load = useCallback(() => {
    api.get<RemoteStatus>(endpoint)
      .then(r => setStatus(r.data))
      .catch(report('dbRemote'))
      .finally(() => setLoaded(true))
  }, [endpoint, report])

  useEffect(() => { load() }, [load])

  async function add() {
    if (!domainId || !dbUser) return
    setBusy(true)
    try {
      const { data } = await api.post<RemoteStatus>(endpoint, { db_user: dbUser, host, label })
      setStatus(data)
      setHost('')
      setLabel('')
      onChange?.()
    } catch (caught) {
      const reason = apiReason(caught)
      await notify({
        message: reason ? t([`reasons.${reason}`, 'addFailed']) : apiError(caught, t('addFailed')),
        tone: 'error',
      })
    } finally {
      setBusy(false)
    }
  }

  async function remove(entry: RemoteHost) {
    setBusy(true)
    try {
      const { data } = await api.delete<RemoteStatus>(
        `/domains/${entry.domain_id}/db-remote/${entry.id}`)
      setStatus(data)
      onChange?.()
    } catch (caught) {
      const reason = apiReason(caught)
      await notify({
        message: reason ? t([`reasons.${reason}`, 'removeFailed']) : apiError(caught, t('removeFailed')),
        tone: 'error',
      })
    } finally {
      setBusy(false)
    }
  }

  if (!loaded) return <div className="py-4 text-sm text-slate-400">{t('loading')}</div>
  if (!status) return null

  // Only the rows for the account being managed; the admin view passes no user
  // and sees everything.
  const rows = dbUser ? status.hosts.filter(entry => entry.db_user === dbUser) : status.hosts

  return (
    <div>
      {!status.enabled && (
        <p className="mb-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-900/20 dark:text-amber-300">
          {t('serverOff')}
        </p>
      )}

      {domainId && dbUser && (
        <div className="mb-4 space-y-2">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex-1 min-w-[12rem]">
              <span className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-300">{t('field.host')}</span>
              <input
                value={host}
                onChange={e => setHost(e.target.value)}
                placeholder={t('field.hostPlaceholder')}
                disabled={!status.enabled || busy}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 disabled:opacity-50"
              />
            </label>
            <label className="flex-1 min-w-[10rem]">
              <span className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-300">{t('field.label')}</span>
              <input
                value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder={t('field.labelPlaceholder')}
                disabled={!status.enabled || busy}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 disabled:opacity-50"
              />
            </label>
            <button
              type="button"
              onClick={add}
              disabled={!status.enabled || busy || host.trim() === ''}
              className="rounded-lg bg-brand-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-brand-700 disabled:opacity-50"
            >
              {t('add')}
            </button>
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500">{t('field.hint')}</p>
        </div>
      )}

      {rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('empty')}</p>
      ) : (
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                {showDomain && <th className="px-4 py-2.5 font-semibold">{t('column.domain')}</th>}
                {showDomain && <th className="px-4 py-2.5 font-semibold">{t('column.user')}</th>}
                <th className="px-4 py-2.5 font-semibold">{t('column.host')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.label')}</th>
                <th className="px-4 py-2.5 font-semibold">{t('column.added')}</th>
                <th className="px-4 py-2.5 text-right font-semibold">{t('column.actions')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {rows.map(entry => (
                <tr key={entry.id} className={responsiveTableRowClass}>
                  {showDomain && (
                    <td className={responsiveTableCellClass} data-label={t('column.domain')}>{entry.domain_name}</td>
                  )}
                  {showDomain && (
                    <td className={responsiveTableCellClass} data-label={t('column.user')}>
                      <span className="font-mono text-xs">{entry.db_user}</span>
                    </td>
                  )}
                  <td className={responsiveTableCellClass} data-label={t('column.host')}>
                    <span className="font-mono text-xs">{entry.host}</span>
                  </td>
                  <td className={responsiveTableCellClass} data-label={t('column.label')}>
                    {entry.label || <span className="text-slate-400">—</span>}
                  </td>
                  <td className={responsiveTableCellClass} data-label={t('column.added')}>{entry.created_at}</td>
                  <td className={`${responsiveTableCellClass} text-right`}>
                    <button
                      type="button"
                      onClick={() => remove(entry)}
                      disabled={busy}
                      className="rounded px-2 py-1 text-sm text-red-600 transition hover:bg-red-50 disabled:opacity-50 dark:text-red-400 dark:hover:bg-red-900/30"
                    >
                      {t('remove')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-xs text-slate-400 dark:text-slate-500">{t('security')}</p>
    </div>
  )
}
