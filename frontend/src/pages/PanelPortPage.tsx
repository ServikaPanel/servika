import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

type Outcome = {
  kind: string
  old_port: number
  new_port: number
  state: 'running' | 'succeeded' | 'rolled_back' | 'rollback_failed'
  error?: string
}

type Status = {
  backend: number
  external: number
  host: string
  last_change?: Outcome
}

type Change = {
  id: number
  kind: string
  old_port: number
  new_port: number
  succeeded: boolean
  rolled_back: boolean
  last_error?: string
  created_at: string
}

/*
 * The panel's own ports.
 *
 * The one screen where a mistake removes the screen. Two things follow from
 * that and are visible here. The external port changes in place and the answer
 * comes back with the request; the backend port restarts the panel, so the
 * request is answered 202 and the verdict arrives afterwards through a status
 * this polls. And the confirmation says what will actually happen, including
 * that the panel goes away for a moment, because an operator who is not
 * expecting that will reach for the power button.
 */
export default function PanelPortPage() {
  const { t } = useTranslation('PanelPort')
  const dialog = useDialog()

  const reasonText = useCallback((err: unknown, fallbackKey: string) => {
    const reason = apiReason(err)
    if (reason) {
      const translated = t(`reason.${reason}`, { defaultValue: '' })
      if (translated) return translated
    }
    return apiError(err, t(fallbackKey))
  }, [t])

  const [status, setStatus] = useState<Status | null>(null)
  const [changes, setChanges] = useState<Change[]>([])
  const [loadError, setLoadError] = useState('')
  const [busy, setBusy] = useState(false)
  const [backendPort, setBackendPort] = useState('')
  const [externalPort, setExternalPort] = useState('')

  const load = useCallback(() => {
    return Promise.all([
      api.get<Status>('/system/panel-port'),
      api.get<{ changes: Change[] }>('/system/panel-port/history'),
    ])
      .then(([current, history]) => {
        setLoadError('')
        setStatus(current.data)
        setChanges(history.data.changes ?? [])
      })
      .catch((err) => setLoadError(reasonText(err, 'error.load')))
  }, [reasonText])

  useEffect(() => {
    void load()
  }, [load])

  // A backend change restarts the panel, so the browser loses the connection
  // and then gets it back. Polling is how the verdict arrives; it stops as soon
  // as the change is no longer running.
  const running = status?.last_change?.state === 'running'
  useEffect(() => {
    if (!running) return undefined
    const timer = setInterval(() => { void load() }, 5000)
    return () => clearInterval(timer)
  }, [running, load])

  const change = async (kind: 'backend' | 'external', value: string) => {
    const port = Number(value)
    if (!Number.isInteger(port) || port <= 0) return

    const confirmed = await dialog.confirm({
      title: t('change.confirmTitle'),
      message: kind === 'backend'
        ? t('change.confirmBackend', { port })
        : t('change.confirmExternal', { port }),
      confirmLabel: t('change.confirmAction'),
      dangerous: true,
    })
    if (!confirmed) return

    setBusy(true)
    try {
      await api.post('/system/panel-port', { kind, port })
      await load()
      if (kind === 'backend') {
        await dialog.notify({ title: t('change.startedTitle'), message: t('change.startedBody') })
      }
    } catch (err) {
      await dialog.notify({
        title: t('change.failedTitle'),
        message: reasonText(err, 'error.change'),
        tone: 'error',
      })
      await load()
    } finally {
      setBusy(false)
    }
  }

  const outcome = status?.last_change

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.toolsAndSettings'), href: '/tools-settings' },
        { label: t('breadcrumb.panelPort') },
      ]} />

      <div className="mb-5 max-w-3xl">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="mt-1 text-sm leading-relaxed text-slate-500 dark:text-slate-400">{t('description')}</p>
      </div>

      {loadError && (
        <p className="mb-4 max-w-3xl rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
          {loadError}
        </p>
      )}

      {/* An in-flight or just-finished change is reported at the top, because
          for a backend change this is the only place the result can appear. */}
      {outcome && (
        <div className={`mb-5 max-w-3xl rounded-lg px-3 py-2 text-sm ${
          outcome.state === 'succeeded'
            ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200'
            : outcome.state === 'running'
              ? 'bg-sky-50 text-sky-800 dark:bg-sky-950 dark:text-sky-200'
              : 'bg-rose-50 text-rose-800 dark:bg-rose-950 dark:text-rose-200'
        }`}>
          <p className="font-medium">{t(`outcome.${outcome.state}`)}</p>
          <p className="mt-1">
            {t('outcome.detail', { kind: t(`kind.${outcome.kind}`), from: outcome.old_port, to: outcome.new_port })}
          </p>
          {outcome.error && <p className="mt-1">{outcome.error}</p>}
        </div>
      )}

      <section className="mb-6 max-w-3xl rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('external.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('external.description')}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
          {t('current')}: <span className="font-mono">{status?.external ?? '…'}</span>
        </p>
        <div className="mt-3 flex gap-2">
          <input
            value={externalPort}
            onChange={(event) => setExternalPort(event.target.value)}
            inputMode="numeric"
            placeholder={String(status?.external ?? '')}
            className="w-32 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm dark:border-slate-600 dark:bg-slate-900"
          />
          <button
            type="button"
            onClick={() => void change('external', externalPort)}
            disabled={busy || running || externalPort.trim() === ''}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {t('change.button')}
          </button>
        </div>
      </section>

      <section className="mb-6 max-w-3xl rounded-xl border border-amber-300 bg-white p-5 dark:border-amber-800 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('backend.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('backend.description')}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
          {t('current')}: <span className="font-mono">{status?.host}:{status?.backend ?? '…'}</span>
        </p>
        <div className="mt-3 flex gap-2">
          <input
            value={backendPort}
            onChange={(event) => setBackendPort(event.target.value)}
            inputMode="numeric"
            placeholder={String(status?.backend ?? '')}
            className="w-32 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm dark:border-slate-600 dark:bg-slate-900"
          />
          <button
            type="button"
            onClick={() => void change('backend', backendPort)}
            disabled={busy || running || backendPort.trim() === ''}
            className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {t('change.button')}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('backend.restartNote')}</p>
      </section>

      <section className="max-w-3xl rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('history.title')}</h2>
        {changes.length === 0 ? (
          <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{t('history.none')}</p>
        ) : (
          <table className="mt-3 min-w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
              <tr>
                <th className="py-2 pr-4">{t('history.what')}</th>
                <th className="py-2 pr-4">{t('history.from')}</th>
                <th className="py-2 pr-4">{t('history.to')}</th>
                <th className="py-2 pr-4">{t('history.result')}</th>
                <th className="py-2">{t('history.when')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
              {changes.map((item) => (
                <tr key={item.id}>
                  <td className="py-2 pr-4 align-top text-xs">{t(`kind.${item.kind}`)}</td>
                  <td className="py-2 pr-4 align-top font-mono text-xs">{item.old_port}</td>
                  <td className="py-2 pr-4 align-top font-mono text-xs">{item.new_port}</td>
                  <td className="py-2 pr-4 align-top text-xs">
                    {item.succeeded
                      ? t('history.succeeded')
                      : item.rolled_back
                        ? t('history.rolledBack')
                        : t('history.failed')}
                    {item.last_error && (
                      <span className="block text-slate-500 dark:text-slate-400">{item.last_error}</span>
                    )}
                  </td>
                  <td className="py-2 align-top text-xs text-slate-500 dark:text-slate-400">
                    {new Date(item.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
