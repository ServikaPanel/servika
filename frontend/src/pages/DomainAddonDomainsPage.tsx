import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDomainRefusal } from '@/lib/domainRefusal'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type AddonDomain = {
  id: number
  domain_name: string
  parked: boolean
  docroot: string
  php_version: string
  ssl: boolean
  created_at: string
}

type RedirectStatus = {
  active: boolean
  target_url?: string
  status_code?: number
}

type WWWRedirect = {
  mode: 'off' | 'to_www' | 'to_apex'
  modes: string[]
  // The backend refuses to_www when www does not point here, so the reason is
  // shown before the attempt rather than as a rejection afterwards.
  www_resolves_to_apex: boolean
  // The stored mode is not the mode in force. It is vetted against the
  // certificate only when it is stored, and SSL installation is asynchronous, so
  // a redirect set during domain creation was checked before any certificate
  // existed. Every later render drops it again when the certificate that arrived
  // does not name the target, which the screen used to report as active.
  applied: boolean
  reason: string
}

export default function DomainAddonDomainsPage() {
  const { t } = useTranslation('DomainAddonDomainsPage')
  const domainRefusal = useDomainRefusal()
  const { confirm } = useDialog()
  const { id } = useParams()
  const [addons, setAddons] = useState<AddonDomain[]>([])
  const [redirect, setRedirect] = useState<RedirectStatus>({ active: false })
  const [www, setWww] = useState<WWWRedirect | null>(null)
  const [wwwSaving, setWwwSaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [redirectSaving, setRedirectSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [domainName, setDomainName] = useState('')
  const [parked, setParked] = useState(false)
  const [targetURL, setTargetURL] = useState('')
  const [statusCode, setStatusCode] = useState(301)

  // Split so the mount effect never writes state synchronously: fetchAddons
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchAddons = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<AddonDomain[]>(`/domains/${id}/addon-domains`),
      api.get<RedirectStatus>(`/domains/${id}/redirect`),
      api.get<WWWRedirect>(`/domains/${id}/www-redirect`),
    ]).then(([addonsResponse, redirectResponse, wwwResponse]) => {
      setAddons(addonsResponse.data || [])
      setRedirect(redirectResponse.data || { active: false })
      setTargetURL(redirectResponse.data?.target_url || '')
      setStatusCode(redirectResponse.data?.status_code || 301)
      setWww(wwwResponse.data || null)
    }).catch(error => setError(apiError(error))).finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    fetchAddons()
  }, [fetchAddons])

  useEffect(() => { fetchAddons() }, [fetchAddons])

  async function create(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setSaving(true)
    try {
      const { data } = await api.post<AddonDomain>(`/domains/${id}/addon-domains`, { domain_name: domainName.trim(), parked })
      setSuccess(t('toast.created', { domain: data.domain_name }))
      setDomainName('')
      setParked(false)
      load()
    } catch (error) { setError(domainRefusal(error, t('toast.createFailed'))) }
    finally { setSaving(false) }
  }

  async function remove(addon: AddonDomain) {
    const mode = addon.parked ? t('mode.parked') : t('mode.addon')
    if (!(await confirm({ message: t('confirmDelete', { domain: addon.domain_name, mode }), dangerous: true }))) return
    setError(null); setSuccess(null)
    try {
      await api.delete(`/domains/${id}/addon-domains/${addon.id}`)
      setSuccess(t('toast.deleted', { domain: addon.domain_name }))
      load()
    } catch (error) { setError(apiError(error, t('toast.deleteFailed'))) }
  }

  async function saveRedirect(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setRedirectSaving(true)
    try {
      await api.put(`/domains/${id}/redirect`, { target_url: targetURL.trim(), status_code: statusCode })
      setSuccess(t('toast.redirectSaved'))
      load()
    } catch (error) { setError(apiError(error, t('toast.redirectSaveFailed'))) }
    finally { setRedirectSaving(false) }
  }

  async function saveWWWRedirect(mode: WWWRedirect['mode']) {
    setError(null); setSuccess(null); setWwwSaving(true)
    try {
      await api.put(`/domains/${id}/www-redirect`, { mode })
      setSuccess(t('toast.wwwSaved'))
      load()
    } catch (error) { setError(apiError(error, t('toast.wwwSaveFailed'))) }
    finally { setWwwSaving(false) }
  }

  async function deleteRedirect() {
    if (!(await confirm({ message: t('confirmRemoveRedirect'), dangerous: true }))) return
    setError(null); setSuccess(null); setRedirectSaving(true)
    try {
      await api.delete(`/domains/${id}/redirect`)
      setSuccess(t('toast.redirectRemoved'))
      setTargetURL('')
      setStatusCode(301)
      load()
    } catch (error) { setError(apiError(error, t('toast.redirectRemoveFailed'))) }
    finally { setRedirectSaving(false) }
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.addonDomains') },
      ]} />
      <div className="flex items-center gap-3 mb-1">
        <span className="text-brand-600 dark:text-brand-400"><Icon d={ICON.globe} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      <form onSubmit={create} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('form.title')}</h3>
        <div className="flex flex-wrap items-end gap-2">
          <label className="block">
            <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('form.domainLabel')}</span>
            <input value={domainName} onChange={event => setDomainName(event.target.value.toLowerCase())} required placeholder="example.com"
              className="mt-1 w-64 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
          </label>
          <label className="flex items-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-600 dark:text-slate-300">
            <input type="checkbox" checked={parked} onChange={event => setParked(event.target.checked)} />
            {t('form.parkedLabel')}
          </label>
          <button disabled={saving || !domainName.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {saving ? t('form.creating') : t('form.add')}
          </button>
        </div>
        <p className="text-[11px] text-slate-400 mt-2">{t('form.hint')}</p>
      </form>

      <form onSubmit={saveRedirect} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
        <div className="flex items-center justify-between gap-3 mb-3">
          <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('redirect.title')}</h3>
          {redirect.active && <span className="text-xs px-2 py-1 rounded-full bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300">{t('redirect.active')}</span>}
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <label className="block flex-1 min-w-[260px]">
            <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('redirect.targetLabel')}</span>
            <input value={targetURL} onChange={event => setTargetURL(event.target.value)} required placeholder="https://example.com"
              className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
          </label>
          <label className="block">
            <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('redirect.statusLabel')}</span>
            <select value={statusCode} onChange={event => setStatusCode(Number(event.target.value))}
              className="mt-1 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
              <option value={301}>{t('redirect.status301')}</option>
              <option value={302}>{t('redirect.status302')}</option>
            </select>
          </label>
          <button disabled={redirectSaving || !targetURL.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {redirectSaving ? t('redirect.saving') : t('redirect.save')}
          </button>
          {redirect.active && <button type="button" onClick={deleteRedirect} disabled={redirectSaving} className="px-4 py-2 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 text-sm font-medium rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">{t('redirect.remove')}</button>}
        </div>
      </form>

      {www && (
        <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
          <div className="flex items-center justify-between gap-3 mb-1">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('www.title')}</h3>
            {redirect.active && <span className="text-xs px-2 py-1 rounded-full bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300">{t('www.overridden')}</span>}
          </div>
          <p className="text-[11px] text-slate-400 mb-3">{t('www.hint')}</p>
          <div className="flex flex-wrap items-center gap-2">
            {(['off', 'to_www', 'to_apex'] as const).map(mode => (
              <button key={mode} type="button" disabled={wwwSaving || www.mode === mode || (mode === 'to_www' && !www.www_resolves_to_apex)}
                onClick={() => saveWWWRedirect(mode)}
                className={`px-3 py-2 text-sm font-medium rounded-lg border disabled:opacity-50 ${www.mode === mode
                  ? 'border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-300'
                  : 'border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                {t(`www.mode.${mode}`)}
              </button>
            ))}
          </div>
          {!www.www_resolves_to_apex && <p className="text-[11px] text-amber-600 dark:text-amber-400 mt-2">{t('www.wwwUnresolved')}</p>}
          {www.reason === 'redirect_cert_missing_target' && <p className="text-[11px] text-amber-600 dark:text-amber-400 mt-2">{t('www.certMissingTarget')}</p>}
        </div>
      )}

      <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('list.title')}</h3>
        {loading ? <div className="text-sm text-slate-400 py-2">{t('list.loading')}</div>
          : addons.length === 0 ? (
            <div className="text-center py-6">
              <div className="mb-1 flex justify-center text-slate-400"><Icon d={ICON.globe} className="h-6 w-6" /></div>
              <p className="text-sm text-slate-500 dark:text-slate-400">{t('list.empty')}</p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
              {addons.map(addon => (
                <li key={addon.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <a href={`http://${addon.domain_name}`} target="_blank" rel="noreferrer" className="font-mono text-sm text-brand-600 dark:text-brand-400 hover:underline">{addon.domain_name}</a>
                    <div className="text-[11px] text-slate-400 font-mono truncate">{addon.parked ? t('list.parked') : addon.docroot} · {t('list.phpPrefix')} {addon.php_version}</div>
                  </div>
                  <button onClick={() => remove(addon)} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20">{t('list.delete')}</button>
                </li>
              ))}
            </ul>
          )}
      </div>

      <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link></div>
    </div>
  )
}
