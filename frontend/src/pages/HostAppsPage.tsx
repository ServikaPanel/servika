import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

type Status = {
  active_state: string
  sub_state: string
  restarts: string
  installed: boolean
}

type Offered = {
  code: string
  name: string
  version: string
  takes_port: boolean
  port_env_name: string
  available: boolean
  unavailable_reason?: string
}

type Installed = {
  id: number
  code: string
  name: string
  version: string
  system_user: string
  state: 'installing' | 'installed' | 'failed' | 'removing'
  last_error?: string
  port: number
  firewall_open: boolean
  status: Status
}

type Overview = {
  enabled: boolean
  catalog: Offered[]
  installed: Installed[]
  architecture: string
  port_min: number
  port_max: number
}

/*
 * Server-level applications.
 *
 * Two things this screen says out loud, because both are invisible otherwise.
 * A port is CLOSED at the firewall until the operator opens it, so an
 * application that is running and unreachable is the normal state rather than a
 * fault. And an application the catalog cannot install here (no build for this
 * architecture) is shown with the reason rather than hidden, because a row that
 * simply vanished would read as a panel that forgot it.
 */
export default function HostAppsPage() {
  const { t } = useTranslation('HostApps')
  const dialog = useDialog()

  const reasonText = useCallback((err: unknown, fallbackKey: string) => {
    const reason = apiReason(err)
    if (reason) {
      const translated = t(`reason.${reason}`, { defaultValue: '' })
      if (translated) return translated
    }
    return apiError(err, t(fallbackKey))
  }, [t])

  const [data, setData] = useState<Overview | null>(null)
  const [loadError, setLoadError] = useState('')
  const [busy, setBusy] = useState('')

  const load = useCallback(() => {
    return api.get<Overview>('/system/host-apps')
      .then((response) => {
        setLoadError('')
        setData(response.data)
      })
      .catch((err) => setLoadError(reasonText(err, 'error.load')))
  }, [reasonText])

  useEffect(() => {
    void load()
  }, [load])

  // An install downloads and unpacks, so its result arrives after the request
  // that started it. Polling stops as soon as nothing is in flight.
  const working = data?.installed.some((app) => app.state === 'installing' || app.state === 'removing') ?? false
  useEffect(() => {
    if (!working) return undefined
    const timer = setInterval(() => { void load() }, 5000)
    return () => clearInterval(timer)
  }, [working, load])

  const install = async (item: Offered) => {
    const confirmed = await dialog.confirm({
      title: t('install.confirmTitle', { name: item.name }),
      message: t('install.confirmBody', { name: item.name, version: item.version }),
      confirmLabel: t('install.action'),
    })
    if (!confirmed) return

    setBusy(item.code)
    try {
      await api.post('/system/host-apps', { code: item.code })
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('install.failedTitle'),
        message: reasonText(err, 'error.install'),
        tone: 'error',
      })
    } finally {
      setBusy('')
    }
  }

  const remove = async (app: Installed) => {
    const confirmed = await dialog.confirm({
      title: t('remove.confirmTitle', { name: app.name }),
      message: t('remove.confirmBody', { name: app.name }),
      confirmLabel: t('remove.action'),
      dangerous: true,
    })
    if (!confirmed) return

    setBusy(app.code)
    try {
      await api.delete(`/system/host-apps/${app.id}`)
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('remove.failedTitle'),
        message: reasonText(err, 'error.remove'),
        tone: 'error',
      })
    } finally {
      setBusy('')
    }
  }

  const act = async (app: Installed, action: 'start' | 'stop' | 'restart') => {
    setBusy(app.code)
    try {
      await api.post(`/system/host-apps/${app.id}/action`, { action })
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('action.failedTitle'),
        message: reasonText(err, 'error.action'),
        tone: 'error',
      })
    } finally {
      setBusy('')
    }
  }

  const toggleFirewall = async (app: Installed) => {
    const opening = !app.firewall_open
    if (opening) {
      const confirmed = await dialog.confirm({
        title: t('firewall.confirmTitle'),
        message: t('firewall.confirmBody', { port: app.port, name: app.name }),
        confirmLabel: t('firewall.open'),
        dangerous: true,
      })
      if (!confirmed) return
    }
    setBusy(app.code)
    try {
      await api.put(`/system/host-apps/${app.id}/firewall`, { open: opening })
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('firewall.failedTitle'),
        message: reasonText(err, 'error.firewall'),
        tone: 'error',
      })
    } finally {
      setBusy('')
    }
  }

  const setEnabled = async (enabled: boolean) => {
    if (!enabled) {
      const confirmed = await dialog.confirm({
        title: t('feature.confirmOffTitle'),
        message: t('feature.confirmOffBody'),
        confirmLabel: t('feature.turnOff'),
      })
      if (!confirmed) return
    }
    setBusy('feature')
    try {
      await api.put('/system/host-apps/enabled', { enabled })
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('feature.failedTitle'),
        message: reasonText(err, 'error.feature'),
        tone: 'error',
      })
    } finally {
      setBusy('')
    }
  }

  const enabled = data?.enabled ?? false
  const installedCodes = new Set((data?.installed ?? []).map((app) => app.code))

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.toolsAndSettings'), href: '/tools-settings' },
        { label: t('breadcrumb.hostApps') },
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

      <section className="mb-6 max-w-3xl rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('feature.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {enabled ? t('feature.isOn') : t('feature.isOff')}
        </p>
        <button
          type="button"
          onClick={() => void setEnabled(!enabled)}
          disabled={busy === 'feature' || data === null}
          className={`mt-3 rounded-lg px-4 py-2 text-sm font-medium text-white disabled:opacity-50 ${
            enabled ? 'bg-slate-600' : 'bg-sky-600'
          }`}
        >
          {enabled ? t('feature.turnOff') : t('feature.turnOn')}
        </button>
        {enabled === false && (
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('feature.offNote')}</p>
        )}
      </section>

      <section className="mb-6 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('installed.title')}</h2>
        {(data?.installed.length ?? 0) === 0 ? (
          <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{t('installed.none')}</p>
        ) : (
          <table className="mt-3 min-w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
              <tr>
                <th className="py-2 pr-4">{t('installed.application')}</th>
                <th className="py-2 pr-4">{t('installed.state')}</th>
                <th className="py-2 pr-4">{t('installed.port')}</th>
                <th className="py-2 pr-4">{t('installed.reachable')}</th>
                <th className="py-2">{t('installed.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
              {data?.installed.map((app) => (
                <tr key={app.id}>
                  <td className="py-2 pr-4 align-top">
                    <span className="font-medium text-slate-900 dark:text-slate-100">{app.name}</span>
                    <span className="ml-2 font-mono text-xs text-slate-500 dark:text-slate-400">{app.version}</span>
                    <span className="block font-mono text-xs text-slate-500 dark:text-slate-400">{app.system_user}</span>
                  </td>
                  <td className="py-2 pr-4 align-top text-xs">
                    {t(`state.${app.state}`)}
                    {app.status.active_state && (
                      <span className="block text-slate-500 dark:text-slate-400">
                        {app.status.active_state}/{app.status.sub_state}
                      </span>
                    )}
                    {app.last_error && (
                      <span className="block text-rose-600 dark:text-rose-400">{app.last_error}</span>
                    )}
                  </td>
                  <td className="py-2 pr-4 align-top font-mono text-xs">{app.port || '—'}</td>
                  <td className="py-2 pr-4 align-top text-xs">
                    <button
                      type="button"
                      onClick={() => void toggleFirewall(app)}
                      disabled={!enabled || busy === app.code || app.port === 0}
                      className={`rounded-lg px-2 py-1 text-xs font-medium disabled:opacity-50 ${
                        app.firewall_open
                          ? 'bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100'
                          : 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-200'
                      }`}
                    >
                      {app.firewall_open ? t('firewall.isOpen') : t('firewall.isClosed')}
                    </button>
                  </td>
                  <td className="py-2 align-top text-xs">
                    <div className="flex flex-wrap gap-1">
                      <button type="button" onClick={() => void act(app, 'start')} disabled={!enabled || busy === app.code}
                        className="rounded-lg bg-emerald-600 px-2 py-1 text-white disabled:opacity-50">{t('action.start')}</button>
                      <button type="button" onClick={() => void act(app, 'restart')} disabled={!enabled || busy === app.code}
                        className="rounded-lg bg-sky-600 px-2 py-1 text-white disabled:opacity-50">{t('action.restart')}</button>
                      <button type="button" onClick={() => void act(app, 'stop')} disabled={!enabled || busy === app.code}
                        className="rounded-lg bg-slate-600 px-2 py-1 text-white disabled:opacity-50">{t('action.stop')}</button>
                      <button type="button" onClick={() => void remove(app)} disabled={!enabled || busy === app.code}
                        className="rounded-lg bg-rose-600 px-2 py-1 text-white disabled:opacity-50">{t('remove.action')}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
          {t('installed.firewallNote', { min: data?.port_min ?? 31000, max: data?.port_max ?? 31999 })}
        </p>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('catalog.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {t('catalog.description', { architecture: data?.architecture ?? '' })}
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {data?.catalog.map((item) => (
            <div key={item.code} className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
              <p className="font-medium text-slate-900 dark:text-slate-100">{item.name}</p>
              <p className="font-mono text-xs text-slate-500 dark:text-slate-400">{item.version}</p>
              {!item.takes_port && (
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('catalog.manualPort')}</p>
              )}
              {item.available ? (
                <button
                  type="button"
                  onClick={() => void install(item)}
                  disabled={!enabled || busy === item.code || installedCodes.has(item.code)}
                  className="mt-2 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
                >
                  {installedCodes.has(item.code) ? t('catalog.alreadyInstalled') : t('install.action')}
                </button>
              ) : (
                <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
                  {t(`reason.${item.unavailable_reason}`, { defaultValue: t('catalog.unavailable') })}
                </p>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
