import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDomainRefusal } from '@/lib/domainRefusal'
import { useDialog } from '@/lib/dialog'
import { sslState } from '@/lib/ssl'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Sub = {
  id: number; subdomain: string; fqdn: string; php_version: string
  docroot: string; created_at: string
  ssl?: boolean; ssl_source?: string
}

export default function DomainSubdomainsPage() {
  const { t } = useTranslation('DomainSubdomainsPage')
  const domainRefusal = useDomainRefusal()
  const { confirm } = useDialog()
  const { id } = useParams()
  const [subdomains, setSubdomains] = useState<Sub[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [subdomainName, setSubdomainName] = useState('')
  const [saving, setSaving] = useState(false)
  const [sslBusy, setSSLBusy] = useState<number | null>(null)

  // Split so the mount effect never writes state synchronously: fetchSubdomains
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchSubdomains = useCallback(() => {
    if (!id) return
    api.get<Sub[]>(`/domains/${id}/subdomain`).then(response => setSubdomains(response.data || [])).catch(error => setError(apiError(error))).finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    fetchSubdomains()
  }, [fetchSubdomains])

  useEffect(() => { fetchSubdomains() }, [fetchSubdomains])

  async function create(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setSaving(true)
    try {
      const { data } = await api.post(`/domains/${id}/subdomain`, { subdomain: subdomainName.trim() })
      setSuccess(t('toast.created', { fqdn: data.fqdn }))
      setSubdomainName('')
      load()
    } catch (error) { setError(domainRefusal(error, t('toast.createFailed'))) }
    finally { setSaving(false) }
  }

  async function remove(subdomain: Sub) {
    if (!(await confirm({ message: t('confirmDelete', { fqdn: subdomain.fqdn }), dangerous: true }))) return
    setError(null); setSuccess(null)
    try { await api.delete(`/domains/${id}/subdomain/${subdomain.id}`); load() }
    catch (error) { setError(apiError(error, t('toast.deleteFailed'))) }
  }

  async function issueSSL(subdomain: Sub, type: 'letsencrypt' | 'self-signed') {
    setError(null); setSuccess(null); setSSLBusy(subdomain.id)
    try {
      await api.post(`/domains/${id}/subdomain/${subdomain.id}/ssl`, { type })
      setSuccess(t('toast.sslInstalled', { fqdn: subdomain.fqdn, method: type === 'letsencrypt' ? t('sslMethod.letsencrypt') : t('sslMethod.selfSigned') }))
    } catch (error) { setError(apiError(error, t('toast.sslInstallFailed'))) }
    finally { setSSLBusy(null) }
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.subdomains') },
      ]} />
      <div className="flex items-center gap-3 mb-1">
        <span className="text-brand-600 dark:text-brand-400"><Icon d={ICON.globe} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">{t('subtitlePre')} <span className="font-mono">blog.domain.com</span>{t('subtitlePost')}</p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      <form onSubmit={create} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('form.title')}</h3>
        <div className="flex flex-wrap items-end gap-2">
          <label className="block">
            <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('form.label')}</span>
            <input value={subdomainName} onChange={event => setSubdomainName(event.target.value.toLowerCase())} required placeholder="blog"
              className="mt-1 w-48 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
          </label>
          <button disabled={saving || !subdomainName.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {saving ? t('form.creating') : t('form.add')}
          </button>
        </div>
        <p className="text-[11px] text-slate-400 mt-2">{t('form.hintPre')} <span className="font-mono">blog</span>, <span className="font-mono">shop</span>, <span className="font-mono">api</span>.</p>
      </form>

      <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('list.title')}</h3>
        {loading ? <div className="text-sm text-slate-400 py-2">{t('list.loading')}</div>
          : subdomains.length === 0 ? (
            <div className="text-center py-6">
              <div className="mb-1 flex justify-center text-slate-400"><Icon d={ICON.globe} className="h-6 w-6" /></div>
              <p className="text-sm text-slate-500 dark:text-slate-400">{t('list.empty')}</p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
              {subdomains.map(subdomain => (
                <li key={subdomain.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <a href={`${subdomain.ssl ? 'https' : 'http'}://${subdomain.fqdn}`} target="_blank" rel="noreferrer" className="font-mono text-sm text-brand-600 dark:text-brand-400 hover:underline">{subdomain.fqdn}</a>
                    {/* This screen offers to install a certificate and never
                        said whether one was already there, so the two buttons
                        below read as available work on a site that is already
                        served over HTTPS. Amber for the self-signed fail-safe:
                        it encrypts and still leaves the visitor on a full-page
                        browser warning. */}
                    {sslState(subdomain.ssl, subdomain.ssl_source) === 'trusted' && (
                      <span title={t('list.sslActive')} className="ml-1.5 text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 rounded">SSL</span>
                    )}
                    {sslState(subdomain.ssl, subdomain.ssl_source) === 'selfSigned' && (
                      <span title={t('list.sslSelfSigned')} className="ml-1.5 text-[10px] font-semibold bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 rounded">SSL</span>
                    )}
                    <div className="text-[11px] text-slate-400 font-mono truncate">{subdomain.docroot} · {t('list.phpPrefix')} {subdomain.php_version}</div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <Link to={`/domains/${id}/subdomain/${subdomain.id}`} title={t('list.manageTitle')}
                      className="text-xs px-2.5 py-1 border border-brand-300 dark:border-brand-800 text-brand-600 dark:text-brand-400 rounded-md hover:bg-brand-50 dark:hover:bg-brand-900/20">
                      {t('list.manage')}
                    </Link>
                    <button onClick={() => issueSSL(subdomain, 'letsencrypt')} disabled={sslBusy === subdomain.id} title={t('list.letsencryptTitle')}
                      className="text-xs px-2.5 py-1 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 rounded-md hover:bg-emerald-50 dark:hover:bg-emerald-900/20 disabled:opacity-50">
                      {sslBusy === subdomain.id ? '…' : t('list.letsencrypt')}
                    </button>
                    <button onClick={() => issueSSL(subdomain, 'self-signed')} disabled={sslBusy === subdomain.id} title={t('list.selfSignedTitle')}
                      className="text-xs px-2 py-1 border border-slate-300 dark:border-slate-700 text-slate-500 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50">
                      {t('list.selfSigned')}
                    </button>
                    <button onClick={() => remove(subdomain)} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20">{t('list.delete')}</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        <p className="text-[11px] text-slate-400 mt-3 pt-3 border-t border-slate-100 dark:border-slate-700/60">
          {t('list.dnsNote')}
        </p>
      </div>

      <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link></div>
    </div>
  )
}
