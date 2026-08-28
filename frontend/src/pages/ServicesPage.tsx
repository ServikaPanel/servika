import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Service = {
  unit: string
  label: string
  group: string
  reloadable: boolean
  status: string
}

const STATUS_STYLES: Record<string, string> = {
  active: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300',
  inactive: 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
  failed: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
  absent: 'bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500',
}

const GROUP_ICONS: Record<string, string> = {
  'Web Server': ICON.globe,
  'Database & Cache': ICON.database,
  DNS: ICON.antenna,
  'PHP-FPM': ICON.code,
  Other: ICON.settings,
}

export default function ServicesPage() {
  const { t } = useTranslation('ServicesPage')
  const [services, setServices] = useState<Service[]>([])
  const [loading, setLoading] = useState(true)
  const [processingUnit, setProcessingUnit] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Promise callbacks rather than await/try: this is what the mount effect calls,
  // and writes in an awaited body still count as the effect's own continuation.
  const load = useCallback(() =>
    api.get<Service[]>('/system/services')
      .then(response => setServices(response.data))
      .catch(caughtError => setError(apiError(caughtError, t('errors.loadFailed'))))
      .finally(() => setLoading(false)),
  [t])

  useEffect(() => { load() }, [load])

  async function applyAction(service: Service, action: 'restart' | 'reload') {
    setProcessingUnit(service.unit)
    setError(null)
    setSuccess(null)
    try {
      await api.post('/system/service-action', { unit: service.unit, action })
      setSuccess(t(action === 'reload' ? 'success.reloaded' : 'success.restarted', { label: service.label }))
      await load()
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.actionFailed', { label: service.label })))
    } finally {
      setProcessingUnit(null)
    }
  }

  const groups: { name: string; services: Service[] }[] = []
  for (const service of services) {
    let group = groups.find(item => item.name === service.group)
    if (!group) {
      group = { name: service.group, services: [] }
      groups.push(group)
    }
    group.services.push(service)
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumbTools'), href: '/tools-settings' },
        { label: t('breadcrumbServices') },
      ]} />
      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('subtitle')}
        </p>
      </div>

      {error && <div className="mb-4 px-4 py-2.5 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-4 px-4 py-2.5 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? (
        <div className="p-8 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : (
        <div className="space-y-5">
          {groups.map(group => (
            <section key={group.name}>
              <div className="flex items-center gap-2 mb-2 px-1">
                <span className="text-slate-500 dark:text-slate-400"><Icon d={GROUP_ICONS[group.name] || ICON.settings} className="h-5 w-5" /></span>
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{group.name}</h2>
              </div>
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {group.services.map(service => {
                    const absent = service.status === 'absent'
                    const busy = processingUnit === service.unit
                    return (
                      <li key={service.unit} className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 px-5 py-4">
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-slate-900 dark:text-slate-100">{service.label}</div>
                          <div className="text-xs font-mono text-slate-400 dark:text-slate-500">{service.unit}</div>
                        </div>
                        <span className={`self-start sm:self-auto sm:w-28 sm:text-center text-xs px-2.5 py-1 rounded-full font-medium ${STATUS_STYLES[service.status] || STATUS_STYLES.inactive}`}>
                          {t(`statuses.${service.status}`, { defaultValue: service.status })}
                        </span>
                        <div className="flex items-center gap-2 shrink-0">
                          {service.reloadable ? (
                            <button disabled={absent || busy} onClick={() => applyAction(service, 'reload')}
                              className="w-20 px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 transition">
                              {t('reload')}
                            </button>
                          ) : (
                            <span className="hidden sm:block w-20" />
                          )}
                          <button disabled={absent || busy} onClick={() => applyAction(service, 'restart')}
                            className="w-20 px-3.5 py-1.5 text-sm rounded-lg bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:bg-slate-800 dark:hover:bg-slate-100 disabled:opacity-40 transition">
                            {busy ? t('working') : t('restart')}
                          </button>
                        </div>
                      </li>
                    )
                  })}
                </ul>
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  )
}
