import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import ToolCard from '@/components/ToolCard'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Detail = {
  id: number; subdomain: string; fqdn: string; php_version: string; docroot: string
  created_at: string; parent_id: number; parent_name: string; disk_kb: number; ipv4: string
  // True when the account runs its own PHP-FPM service. One master serves every
  // domain it holds, so the version follows the parent domain and this screen
  // must not offer a choice the server would refuse.
  php_locked?: boolean
}

type Version = { version: string; description: string }

// The subdomain-scoped tools exposed by the API under /domains/:id/subdomain/:sid.
// Labels and descriptions are resolved from the DomainSubdomainPage namespace via each tool slug.
const TOOLS = [
  { slug: 'wordpress', icon: 'M12 3v18m9-9H3', color: 'sky' as const },
  { slug: 'logs', icon: 'M4 6h16M4 12h16M4 18h10', color: 'slate' as const },
  { slug: 'composer', icon: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4', color: 'amber' as const },
  { slug: 'protection', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', color: 'rose' as const },
  { slug: 'statistics', icon: 'M4 20h16M7 16V9m5 7V5m5 11v-4', color: 'violet' as const },
  { slug: 'php', icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4', color: 'indigo' as const },
  { slug: 'web-server', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01', color: 'emerald' as const },
]

function formatDisk(diskKB: number): string {
  if (diskKB >= 1024 * 1024) return `${(diskKB / 1024 / 1024).toFixed(2)} GB`
  if (diskKB >= 1024) return `${(diskKB / 1024).toFixed(1)} MB`
  return `${diskKB} KB`
}

export default function DomainSubdomainPage() {
  const { t } = useTranslation('DomainSubdomainPage')
  const { id, sid } = useParams()
  const [detail, setDetail] = useState<Detail | null>(null)
  const [versions, setVersions] = useState<Version[]>([])
  const [selectedVersion, setSelectedVersion] = useState('')
  const [sslActive, setSSLActive] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Split so the mount effect never writes state synchronously: fetchDetail
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a write.
  const fetchDetail = useCallback(() => {
    if (!id || !sid) return
    api.get<Detail>(`/domains/${id}/subdomain/${sid}`)
      .then(response => { setDetail(response.data); setSelectedVersion(response.data.php_version) })
      .catch(error => setError(apiError(error)))
      .finally(() => setLoading(false))
    // The installed PHP versions come from the parent domain's settings endpoint,
    // so the selector never offers a version the server cannot serve.
    api.get<{ versions: Version[] }>(`/domains/${id}/php-settings`)
      .then(response => setVersions(response.data.versions || []))
      .catch(() => setVersions([]))
    api.get<{ active: boolean }>(`/domains/${id}/subdomain/${sid}/ssl`)
      .then(response => setSSLActive(response.data.active))
      .catch(() => setSSLActive(null))
  }, [id, sid])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchDetail()
  }, [fetchDetail])

  useEffect(() => { fetchDetail() }, [fetchDetail])

  async function savePHP() {
    setError(null); setSuccess(null); setSaving(true)
    try {
      const { data } = await api.put(`/domains/${id}/subdomain/${sid}/php`, { php_version: selectedVersion })
      setSuccess(t('toast.phpSaved', { version: data.php_version }))
      load()
    } catch (error) {
      // Reachable with the picker enabled only when the account moved to its own
      // PHP-FPM service while this page was open. The server answers with a code
      // because it cannot word it in the twelve languages the interface ships.
      setError(apiError(error, '') === 'php_version_locked_to_parent'
        ? t('php.locked')
        : apiError(error, t('toast.phpChangeFailed')))
    }
    finally { setSaving(false) }
  }

  const toolBase = `/domains/${id}/subdomain/${sid}`

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: detail?.parent_name || t('breadcrumb.domain'), href: `/subscriptions/${id}` },
        { label: t('breadcrumb.subdomains'), href: `/subscriptions/${id}/subdomains` },
        { label: detail?.fqdn || t('breadcrumb.subdomain') },
      ]} />

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? <div className="text-sm text-slate-400 py-4">{t('loading')}</div>
        : !detail ? <div className="text-sm text-slate-500 dark:text-slate-400 py-4">{t('notFound')}</div>
          : (
            <>
              <div className="flex items-center gap-3 mb-1">
                <span className="text-brand-600 dark:text-brand-400"><Icon d={ICON.globe} className="h-6 w-6" /></span>
                <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100 font-mono">{detail.fqdn}</h1>
                {sslActive !== null && (
                  <span className={`text-[11px] px-2 py-0.5 rounded-md font-medium ${sslActive
                    ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400'}`}>
                    {sslActive ? t('ssl.active') : t('ssl.none')}
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">
                {t('intro.pre')} <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400">{detail.parent_name}</Link>{t('intro.post')}
              </p>

              <div className="grid gap-4 md:grid-cols-2 mb-5">
                <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
                  <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('details.title')}</h3>
                  <dl className="space-y-2 text-sm">
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.address')}</dt>
                      <dd><a href={`${sslActive ? 'https' : 'http'}://${detail.fqdn}`} target="_blank" rel="noreferrer" className="font-mono text-brand-600 dark:text-brand-400 hover:underline">{detail.fqdn}</a></dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.documentRoot')}</dt>
                      <dd className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate">{detail.docroot}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.diskUsage')}</dt>
                      <dd className="text-slate-700 dark:text-slate-300">{formatDisk(detail.disk_kb)}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.phpVersion')}</dt>
                      <dd className="text-slate-700 dark:text-slate-300">{detail.php_version}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.created')}</dt>
                      <dd className="text-slate-700 dark:text-slate-300">{detail.created_at}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt className="text-slate-500 dark:text-slate-400">{t('details.serverIp')}</dt>
                      <dd className="font-mono text-xs text-slate-700 dark:text-slate-300">{detail.ipv4}</dd>
                    </div>
                  </dl>
                </div>

                <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
                  <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('php.title')}</h3>
                  {/* The standing note is only true of an account on the shared
                      master. On its own service the subdomain shares the parent's
                      interpreter, so the note is REPLACED rather than added to. */}
                  {detail.php_locked
                    ? <p className="text-xs text-amber-600 dark:text-amber-400 mb-3">{t('php.locked')}</p>
                    : <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('php.note')}</p>}
                  <div className="flex flex-wrap items-end gap-2">
                    <label className="block">
                      <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('php.versionLabel')}</span>
                      <select value={selectedVersion} onChange={event => setSelectedVersion(event.target.value)}
                        disabled={detail.php_locked}
                        className="mt-1 w-56 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-60">
                        {versions.length === 0 && <option value={detail.php_version}>{detail.php_version}</option>}
                        {versions.map(version => (
                          <option key={version.version} value={version.version}>{version.version}{version.description ? ` — ${version.description}` : ''}</option>
                        ))}
                      </select>
                    </label>
                    <button onClick={savePHP} disabled={saving || detail.php_locked || !selectedVersion || selectedVersion === detail.php_version}
                      className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                      {saving ? t('php.applying') : t('php.apply')}
                    </button>
                  </div>
                  {!detail.php_locked && <p className="text-[11px] text-slate-400 mt-2">{t('php.validationNote')}</p>}
                </div>
              </div>

              <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
                <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('toolsSection.title')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('toolsSection.note')}</p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {TOOLS.map(tool => (
                    <ToolCard key={tool.slug} label={t(`tools.${tool.slug}.label`)} description={t(`tools.${tool.slug}.description`)} icon={tool.icon} color={tool.color} to={`${toolBase}/${tool.slug}`} />
                  ))}
                </div>
              </div>

              <div className="mt-4">
                <Link to={`/subscriptions/${id}/subdomains`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubdomains')}</Link>
              </div>
            </>
          )}
    </div>
  )
}
