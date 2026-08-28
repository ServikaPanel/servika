import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Domain = { id: number; domain_name: string }
type InstallationResult = { site_url: string; admin_url: string; admin_user: string; admin_password: string; version: string }
type Installation = {
  domain_id: number; domain_name: string; dir: string; version: string
  last_version: string; status: 'current' | 'outdated' | 'unknown'; install_date: string
  site_url: string; admin_url: string
}

const ROOT_DIRECTORY = '/ (root)'

/** Returns whether the directory value represents the domain root. */
function isRootDirectory(directory: string): boolean {
  return directory === ROOT_DIRECTORY
}

/** Returns the directory value for display. */
function displayDirectory(directory: string): string {
  return directory
}

export default function WordPressPage() {
  const { t } = useTranslation('WordPressPage')
  const { confirm, notify } = useDialog()
  const [domains, setDomains] = useState<Domain[]>([])
  const [domainId, setDomainId] = useState<number | null>(null)
  const [installations, setInstallations] = useState<Installation[]>([])
  const [loadingInstallations, setLoadingInstallations] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [installing, setInstalling] = useState(false)
  const [result, setResult] = useState<InstallationResult | null>(null)
  const [busyKey, setBusyKey] = useState<string | null>(null)

  const [subdirectory, setSubdirectory] = useState('')
  const [siteTitle, setSiteTitle] = useState('')
  const [adminUser, setAdminUser] = useState('admin')
  const [adminEmail, setAdminEmail] = useState('')

  useEffect(() => {
    api.get<Domain[]>('/domains').then(response => {
      setDomains(response.data || [])
      if (response.data?.length) setDomainId(response.data[0].id)
    }).catch(cause => setError(apiError(cause)))
    listAll()
  }, [])

  function listAll() {
    setLoadingInstallations(true)
    api.get<Installation[]>('/wordpress/all')
      .then(response => setInstallations(response.data || []))
      .catch(cause => setError(apiError(cause)))
      .finally(() => setLoadingInstallations(false))
  }

  async function install(event: React.FormEvent) {
    event.preventDefault()
    if (!domainId) return
    setError(null); setResult(null); setInstalling(true)
    try {
      const { data } = await api.post<InstallationResult>(`/domains/${domainId}/wordpress`, {
        sub_dir: subdirectory.trim(), site_title: siteTitle.trim(), admin_user: adminUser.trim(), admin_email: adminEmail.trim(),
      })
      setResult(data); setSiteTitle(''); setSubdirectory('')
      listAll()
    } catch (cause) { setError(apiError(cause, t('errors.installFailed'))) }
    finally { setInstalling(false) }
  }

  async function update(installation: Installation) {
    const key = installation.domain_id + installation.dir
    setBusyKey(key); setError(null)
    try { await api.post(`/domains/${installation.domain_id}/wordpress/update`, { dir: installation.dir }); listAll() }
    catch (cause) { setError(apiError(cause, t('errors.updateFailed'))) }
    finally { setBusyKey(null) }
  }

  async function remove(installation: Installation) {
    if (isRootDirectory(installation.dir)) { await notify({ message: t('errors.rootDelete'), tone: 'error' }); return }
    if (!(await confirm({ message: t('confirmDelete', { domain: installation.domain_name, dir: installation.dir }), dangerous: true }))) return
    const key = installation.domain_id + installation.dir
    setBusyKey(key); setError(null)
    try {
      await api.delete(`/domains/${installation.domain_id}/wordpress`, { data: { dir: installation.dir, delete_db: true } })
      listAll()
    } catch (cause) { setError(apiError(cause, t('errors.deleteFailed'))) }
    finally { setBusyKey(null) }
  }

  const selectedDomain = domains.find(domain => domain.id === domainId)
  const outdatedInstallations = useMemo(() => installations.filter(installation => installation.status === 'outdated'), [installations])

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('breadcrumbTitle') }]} />
      <div className="flex items-center gap-3 mb-1">
        <span><Icon d={ICON.pencil} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      {/* Security warning banner */}
      {!loadingInstallations && outdatedInstallations.length > 0 && (
        <div className="mb-4 px-4 py-3 rounded-2xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 flex items-start gap-3">
          <span className="leading-none"><Icon d={ICON.warning} className="h-5 w-5" /></span>
          <div className="text-sm text-amber-800 dark:text-amber-200">
            <strong>{t('outdated.banner', { count: outdatedInstallations.length })}</strong> {t('outdated.warning')}
            <div className="mt-1 text-xs text-amber-700 dark:text-amber-300 font-mono">
              {outdatedInstallations.map(installation => `${installation.domain_name}${isRootDirectory(installation.dir) ? '' : installation.dir}`).join(', ')}
            </div>
          </div>
        </div>
      )}

      {/* Installation result with one-time credentials */}
      {result && (
        <div className="mb-4 rounded-2xl border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/15 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-700 dark:text-emerald-300 mb-2">
            <Icon d={ICON.check} className="inline h-4 w-4 mr-1" />{t('result.installed', { version: result.version })}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
            <Info label={t('result.site')} value={result.site_url} link />
            <Info label={t('result.admin')} value={result.admin_url} link />
            <Info label={t('result.user')} value={result.admin_user} mono />
            <Info label={t('result.password')} value={result.admin_password} mono />
          </div>
          <p className="text-[11px] text-amber-700 dark:text-amber-400 mt-2">{t('result.savePassword')}</p>
        </div>
      )}

      {/* Full-width table of all installations */}
      <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl overflow-hidden mb-6">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('installedSites')} {!loadingInstallations && <span className="text-slate-400 font-normal">({installations.length})</span>}</h3>
          <button onClick={listAll} disabled={loadingInstallations} className="text-xs px-2.5 py-1 border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">{t('refresh')}</button>
        </div>
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="text-left font-medium px-4 py-2.5">{t('table.domain')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('table.directory')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('table.version')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('table.status')}</th>
                <th className="text-left font-medium px-4 py-2.5 whitespace-nowrap">{t('table.installed')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('table.actions')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {loadingInstallations ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-400">{t('scanning')}</td></tr>
              ) : installations.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center">
                  <div className="mb-1"><Icon d={ICON.pencil} className="h-6 w-6" /></div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{t('emptyTitle')}</p>
                  <p className="text-xs text-slate-400 mt-1">{t('emptyHint')}</p>
                </td></tr>
              ) : (
                installations.map(installation => {
                  const key = installation.domain_id + installation.dir
                  const isOutdated = installation.status === 'outdated'
                  return (
                    <tr key={key} className={`${responsiveTableRowClass} ${isOutdated ? 'bg-amber-50/50 dark:bg-amber-900/10' : ''}`}>
                      <td data-label={t('table.domain')} className={responsiveTableCellClass}>
                        <a href={installation.site_url} target="_blank" rel="noreferrer" className="font-medium text-slate-800 dark:text-slate-100 hover:text-brand-600 dark:hover:text-brand-400">{installation.domain_name}</a>
                      </td>
                      <td data-label={t('table.directory')} className={responsiveTableCodeCellClass}>{displayDirectory(installation.dir)}</td>
                      <td data-label={t('table.version')} className={responsiveTableCellClass}>
                        <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 font-mono font-semibold">{installation.version ? `v${installation.version}` : '-'}</span>
                      </td>
                      <td data-label={t('table.status')} className={responsiveTableCellClass}><StatusBadge installation={installation} /></td>
                      <td data-label={t('table.installed')} className={responsiveTableCodeCellClass}>{installation.install_date || '-'}</td>
                      <td className={responsiveTableActionCellClass}>
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <a href={installation.admin_url} target="_blank" rel="noreferrer" className="text-xs px-2.5 py-1 border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">{t('adminButton')}</a>
                          <button disabled={!!busyKey} onClick={() => update(installation)}
                            className={`text-xs px-2.5 py-1 rounded-md disabled:opacity-50 ${isOutdated ? 'bg-amber-500 hover:bg-amber-600 text-white' : 'border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'}`}>
                            {busyKey === key ? '...' : isOutdated ? t('updateToVersion', { version: installation.last_version }) : t('update')}
                          </button>
                          {!isRootDirectory(installation.dir) && (
                            <button disabled={!!busyKey} onClick={() => remove(installation)} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">{t('delete')}</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* New installation */}
      <form onSubmit={install} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 max-w-2xl">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('form.heading')}</h3>
        <div className="mb-3">
          <label className="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1.5">{t('form.domain')}</label>
          <select value={domainId ?? ''} onChange={event => setDomainId(Number(event.target.value))}
            className="w-full sm:w-80 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
            {domains.map(domain => <option key={domain.id} value={domain.id}>{domain.domain_name}</option>)}
          </select>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label={t('form.siteTitle')} value={siteTitle} setValue={setSiteTitle} required placeholder={t('form.siteTitlePlaceholder')} />
          <Field label={t('form.subdirectory')} value={subdirectory} setValue={setSubdirectory} placeholder={t('form.subdirectoryPlaceholder')} mono />
          <Field label={t('form.adminUser')} value={adminUser} setValue={setAdminUser} required mono />
          <Field label={t('form.adminEmail')} value={adminEmail} setValue={setAdminEmail} required type="email" placeholder={t('form.adminEmailPlaceholder')} />
        </div>
        <button disabled={installing || !domainId} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
          {installing ? t('installing') : (selectedDomain ? t('installButtonDomain', { domain: selectedDomain.domain_name }) : t('installButton'))}
        </button>
      </form>
    </div>
  )
}

function StatusBadge({ installation }: { installation: Installation }) {
  const { t } = useTranslation('WordPressPage')
  if (installation.status === 'outdated') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200 font-medium">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
        {installation.last_version ? t('status.updateAvailableTo', { version: installation.last_version }) : t('status.updateAvailable')}
      </span>
    )
  }
  if (installation.status === 'current') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 font-medium">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
        {t('status.upToDate')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 font-medium">
      {t('status.unknown')}
    </span>
  )
}

function Field({ label, value, setValue, required, placeholder, mono, type }: { label: string; value: string; setValue: (value: string) => void; required?: boolean; placeholder?: string; mono?: boolean; type?: string }) {
  return (
    <label className="block">
      <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{label}</span>
      <input value={value} onChange={event => setValue(event.target.value)} required={required} placeholder={placeholder} type={type || 'text'}
        className={`mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none ${mono ? 'font-mono' : ''}`} />
    </label>
  )
}
function Info({ label, value, mono, link }: { label: string; value: string; mono?: boolean; link?: boolean }) {
  return (
    <div className="flex items-baseline gap-1.5 min-w-0">
      <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold shrink-0">{label}</span>
      {link ? <a href={value} target="_blank" rel="noreferrer" className="text-xs text-brand-600 dark:text-brand-400 hover:underline truncate font-mono">{value}</a>
        : <span className={`text-xs text-slate-800 dark:text-slate-100 truncate ${mono ? 'font-mono' : ''}`}>{value}</span>}
    </div>
  )
}
