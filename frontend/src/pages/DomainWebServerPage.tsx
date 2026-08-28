import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useAuth } from '@/store/auth'
import { useResourceScope } from '@/lib/scope'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import CodeMirror from '@uiw/react-codemirror'
import { oneDark } from '@codemirror/theme-one-dark'

type Settings = {
  hdr_x_content_type: boolean
  hdr_x_xss: boolean
  hdr_referrer: boolean
  hdr_permissions: boolean
  hdr_csp_upgrade: boolean
  hdr_hsts: boolean
  hsts_max_age: number
  hsts_subdomains: boolean
  hsts_preload: boolean
  fastcgi_cache: boolean
  fastcgi_cache_minutes: number
  browser_cache: boolean
  browser_cache_days: number
  extra_directives: string
}

type Response = { domain_name: string; settings: Settings }
type WebRootResponse = { web_root: string; subdirectory: string; candidates: string[] }
type CustomVhostResponse = { enabled: boolean; content: string; domain_name: string }

const BACKEND_INFO: Record<string, { name: string; icon: string; description: string; color: string }> = {
  'php-fpm': {
    name: 'nginx + PHP-FPM',
    icon: ICON.bolt,
    description: 'Default. nginx calls PHP-FPM directly through FastCGI. Ideal for WordPress, Laravel, and dynamic PHP sites with the lowest latency.',
    color: 'emerald',
  },
  'apache': {
    name: 'nginx + Apache',
    icon: ICON.feather,
    description: 'nginx terminates TLS at the edge, while Apache (10080) serves the vhost behind it. Full .htaccess support for Joomla, older WordPress sites, and legacy CMSs.',
    color: 'indigo',
  },
  'static': {
    name: 'Static (no PHP)',
    icon: ICON.file,
    description: 'Serves files only. Intended for React, Vue, or Angular SPAs, static site generators such as Hugo and Jekyll, and CDN content. PHP requests return 404.',
    color: 'slate',
  },
}

const HEADERS = [
  { key: 'hdr_x_content_type', label: 'X-Content-Type-Options', value: 'nosniff',
    description: 'Prevents MIME sniffing as an XSS defense' },
  { key: 'hdr_x_xss', label: 'X-XSS-Protection', value: '1; mode=block',
    description: 'Legacy browser XSS protection' },
  { key: 'hdr_referrer', label: 'Referrer-Policy', value: 'strict-origin-when-cross-origin',
    description: 'Restricts cross-site Referer information' },
  { key: 'hdr_permissions', label: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=(), interest-cohort=()',
    description: 'Disables camera, microphone, and location APIs by default' },
  { key: 'hdr_csp_upgrade', label: 'Upgrade Insecure Requests', value: 'CSP: upgrade-insecure-requests',
    description: 'Automatically upgrades HTTP links to HTTPS' },
] as const

export default function DomainWebServerPage() {
  const { t } = useTranslation('DomainWebServerPage')
  const { confirm } = useDialog()
  const { id, base, isSubdomain, backHref } = useResourceScope()
  const user = useAuth(state => state.username)
  const isAdmin = user?.role === 'admin'
  const [response, setResponse] = useState<Response | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [processing, setProcessing] = useState(false)

  // Raw vhost file — admin only. CloudPanel-like: the file nginx actually serves
  // is always shown in an inline editor, no separate "open" click.
  const [customVhost, setCustomVhost] = useState<CustomVhostResponse | null>(null)
  const [customVhostContent, setCustomVhostContent] = useState('')
  const [customVhostChanging, setCustomVhostChanging] = useState(false)
  const [customVhostSaving, setCustomVhostSaving] = useState(false)
  const customVhostDirty = customVhost !== null && customVhostContent !== customVhost.content

  const [backend, setBackend] = useState<string>('php-fpm')
  const [backendChanging, setBackendChanging] = useState(false)
  const [webRootPath, setWebRootPath] = useState('')
  const [webRootSubdirectory, setWebRootSubdirectory] = useState('')
  const [webRootCandidates, setWebRootCandidates] = useState<string[]>([])
  const [webRootChanging, setWebRootChanging] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchSettings
  // settles only through promise callbacks, and load() adds the spinner for the
  // reload button and the refreshes that follow a write.
  const fetchSettings = useCallback(() => {
    if (!id) return
    // A subdomain has a fixed document root and no vhost file of its own, so the
    // web-root and custom-vhost requests are skipped rather than 404ing.
    Promise.all([
      api.get<Response>(`${base}/nginx-settings`),
      api.get<{backend: string}>(`${base}/web-backend`),
      isSubdomain ? Promise.resolve(null) : api.get<WebRootResponse>(`/domains/${id}/web-root`),
      isAdmin && !isSubdomain ? api.get<CustomVhostResponse>(`/domains/${id}/custom-vhost`) : Promise.resolve(null),
    ]).then(([settingsResponse, backendResponse, webRootResponse, customVhostResponse]) => {
      setResponse(settingsResponse.data); setSettings(settingsResponse.data.settings)
      setBackend(backendResponse.data.backend)
      if (webRootResponse) {
        setWebRootPath(webRootResponse.data.web_root)
        setWebRootSubdirectory(webRootResponse.data.subdirectory)
        setWebRootCandidates(webRootResponse.data.candidates || [])
      }
      if (customVhostResponse) {
        setCustomVhost(customVhostResponse.data)
        setCustomVhostContent(customVhostResponse.data.content)
      }
    }).catch(error => setError(apiError(error)))
      .finally(() => setLoading(false))
  }, [base, id, isAdmin, isSubdomain])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchSettings()
  }, [fetchSettings])

  useEffect(() => { fetchSettings() }, [fetchSettings])

  async function saveBackend(newBackend: string) {
    if (newBackend === backend || backendChanging) return
    setBackendChanging(true); setError(null); setSuccess(null)
    try {
      await api.put(`${base}/web-backend`, { backend: newBackend })
      setBackend(newBackend)
      setSuccess(t('success.backendChanged', { name: t(`backend.${newBackend}.name`, { defaultValue: BACKEND_INFO[newBackend]?.name || newBackend }) }))
      setTimeout(() => setSuccess(null), 4000)
    } catch (error) {
      setError(apiError(error, t('errors.changeBackendFailed')))
    } finally {
      setBackendChanging(false)
    }
  }

  async function saveWebRoot() {
    setWebRootChanging(true); setError(null); setSuccess(null)
    try {
      const response = await api.put<WebRootResponse>(`/domains/${id}/web-root`, { subdirectory: webRootSubdirectory })
      setWebRootPath(response.data.web_root)
      setWebRootSubdirectory(response.data.subdirectory)
      setWebRootCandidates(response.data.candidates || [])
      setSuccess(t('success.docRootUpdated'))
      setTimeout(() => setSuccess(null), 4000)
    } catch (error) {
      setError(apiError(error, t('errors.updateDocRootFailed')))
    } finally {
      setWebRootChanging(false)
    }
  }

  async function save() {
    if (!settings) return
    setProcessing(true); setError(null); setSuccess(null)
    try {
      await api.put(`${base}/nginx-settings`, { settings })
      setSuccess(t('success.settingsApplied'))
      load()
    } catch (error) {
      setError(apiError(error, t('errors.saveSettingsFailed')))
    } finally {
      setProcessing(false)
    }
  }

  // Saving the raw file always switches the domain to custom-vhost mode: the
  // edited content becomes the file nginx serves.
  async function saveCustomVhost() {
    if (!isAdmin) return
    setCustomVhostSaving(true); setError(null); setSuccess(null)
    try {
      const response = await api.put<CustomVhostResponse>(`/domains/${id}/custom-vhost`, {
        enabled: true,
        content: customVhostContent,
      })
      setCustomVhost(response.data)
      setCustomVhostContent(response.data.content)
      setSuccess(t('success.customVhostSaved'))
      setTimeout(() => setSuccess(null), 4000)
    } catch (error) {
      setError(apiError(error, t('errors.saveCustomVhostFailed')))
    } finally {
      setCustomVhostSaving(false)
    }
  }

  // Return to panel-managed vhost: the edited content is preserved server-side,
  // and the managed vhost is re-rendered from the settings above.
  async function returnToManagedVhost() {
    if (!isAdmin || !customVhost) return
    if (!(await confirm({ message: t('vhost.confirmReturn'), dangerous: true }))) return
    setCustomVhostChanging(true); setError(null); setSuccess(null)
    try {
      await api.put<CustomVhostResponse>(`/domains/${id}/custom-vhost`, {
        enabled: false,
        content: customVhost.content,
      })
      setSuccess(t('success.returnedToPanel'))
      setTimeout(() => setSuccess(null), 4000)
      load()
    } catch (error) {
      setError(apiError(error, t('errors.returnManagedFailed')))
    } finally {
      setCustomVhostChanging(false)
    }
  }

  function updateSetting<K extends keyof Settings>(key: K, value: Settings[K]) {
    if (!settings) return
    setSettings({ ...settings, [key]: value })
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: response?.domain_name || '...', href: backHref },
        { label: t('breadcrumb.settings') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {response && <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        <Link to={backHref} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{response.domain_name}</Link>
        {' · '}{t('subtitle')}
      </p>}

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {/* Web server stack selector */}
      <div className="mb-6 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('stack.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
              {t('stack.description')}
            </p>
          </div>
          {backendChanging && <span className="text-xs text-slate-400 dark:text-slate-500">{t('applying')}</span>}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(isSubdomain ? (['php-fpm','static'] as const) : (['php-fpm','apache','static'] as const)).map(k => {
            const b = BACKEND_INFO[k]
            const enabled = backend === k
            const colorClasses: Record<string, string> = {
              emerald: enabled ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 ring-2 ring-emerald-500/20' : 'border-slate-200 dark:border-slate-700 hover:border-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 dark:bg-emerald-900/20',
              indigo:  enabled ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 ring-2 ring-indigo-500/20'    : 'border-slate-200 dark:border-slate-700 hover:border-indigo-300 hover:bg-indigo-50 dark:bg-indigo-900/20',
              slate:   enabled ? 'border-slate-500 bg-slate-100 dark:bg-slate-800 ring-2 ring-slate-400/20'      : 'border-slate-200 dark:border-slate-700 hover:border-slate-400 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800',
            }
            return (
              <button key={k} type="button"
                onClick={() => saveBackend(k)}
                disabled={backendChanging || enabled}
                className={`text-left p-4 border rounded-lg transition disabled:cursor-default ${colorClasses[b.color]}`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-slate-600 dark:text-slate-300"><Icon d={b.icon} className="h-5 w-5" /></span>
                  {enabled && <span className="text-[10px] uppercase tracking-wider font-semibold text-emerald-700 dark:text-emerald-300">{t('stack.active')}</span>}
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t(`backend.${k}.name`, { defaultValue: b.name })}</div>
                <div className="text-[11px] text-slate-600 dark:text-slate-400 dark:text-slate-500 mt-1.5 leading-snug">{t(`backend.${k}.description`, { defaultValue: b.description })}</div>
              </button>
            )
          })}
        </div>
      </div>

      {!isSubdomain && <div className="mb-6 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('docRoot.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
              {t('docRoot.description')}
            </p>
          </div>
          {webRootChanging && <span className="text-xs text-slate-400 dark:text-slate-500">{t('applying')}</span>}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-3 items-end">
          <label className="block text-sm">
            <span className="block mb-1 text-slate-600 dark:text-slate-400">{t('docRoot.subdirLabel')}</span>
            <input
              list="web-root-candidates"
              value={webRootSubdirectory}
              onChange={event => setWebRootSubdirectory(event.target.value)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm text-slate-900 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
              placeholder={t('docRoot.placeholder')}
            />
            <datalist id="web-root-candidates">
              {webRootCandidates.map(candidate => <option key={candidate || 'public_html'} value={candidate} />)}
            </datalist>
          </label>
          <button onClick={saveWebRoot} disabled={webRootChanging}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-slate-900 text-white dark:bg-white dark:text-slate-900 disabled:opacity-50">
            {t('docRoot.save')}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">
          {t('docRoot.currentLabel')} <code className="font-mono text-slate-700 dark:text-slate-300 break-all">{webRootPath || 'public_html'}</code>
        </p>
      </div>}

      <div className="mb-5 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
        <strong>HSTS</strong>{t('hstsNote.pre')}<code className="font-mono">nginx -t</code>{t('hstsNote.mid')}<code className="font-mono">reload</code>{t('hstsNote.post')}
      </div>

      {loading || !settings ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> : (
        <>
          {!isSubdomain && customVhost?.enabled && (
            <div className="mb-5 flex items-start gap-1.5 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
              <Icon d={ICON.warning} className="mt-0.5 h-3.5 w-3.5 shrink-0" /><span><strong>{t('customVhostActive.boldPre')}</strong>{t('customVhostActive.post')}<strong>{t('customVhostActive.boldNot')}</strong>{t('customVhostActive.tail')}</span>
            </div>
          )}

          {/* General security headers */}
          <Card title={t('cards.securityHeaders')}>
            <div className="space-y-3">
              {HEADERS.map(h => (
                <RowToggle
                  key={h.key}
                  label={h.label}
                  value={h.value}
                  description={t(`headers.${h.key}`, { defaultValue: h.description })}
                  enabled={settings[h.key] as boolean}
                  onToggle={() => updateSetting(h.key as keyof Settings, !settings[h.key] as never)}
                />
              ))}
            </div>
          </Card>

          {/* HSTS-specific settings */}
          <Card title={t('cards.hsts')}>
            <RowToggle
              label="Strict-Transport-Security"
              value={`max-age=${settings.hsts_max_age}${settings.hsts_subdomains ? '; includeSubDomains' : ''}${settings.hsts_preload ? '; preload' : ''}`}
              description={t('hsts.description')}
              enabled={settings.hdr_hsts}
              onToggle={() => updateSetting('hdr_hsts', !settings.hdr_hsts)}
            />
            {settings.hdr_hsts && (
              <div className="mt-3 pl-4 border-l-2 border-slate-200 dark:border-slate-700 space-y-2">
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('hsts.maxAgeLabel')}</label>
                  <select value={settings.hsts_max_age} onChange={event => updateSetting('hsts_max_age', parseInt(event.target.value))}
                    className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono">
                    <option value={300}>{t('hsts.maxAge300')}</option>
                    <option value={86400}>{t('hsts.maxAge86400')}</option>
                    <option value={604800}>{t('hsts.maxAge604800')}</option>
                    <option value={2592000}>{t('hsts.maxAge2592000')}</option>
                    <option value={15768000}>{t('hsts.maxAge15768000')}</option>
                    <option value={31536000}>{t('hsts.maxAge31536000')}</option>
                    <option value={63072000}>{t('hsts.maxAge63072000')}</option>
                  </select>
                </div>
                <CheckboxRow
                  label="includeSubDomains"
                  description={t('hsts.includeSubDomainsDesc')}
                  checked={settings.hsts_subdomains}
                  onChange={v => updateSetting('hsts_subdomains', v)}
                />
                <CheckboxRow
                  label="preload"
                  description={t('hsts.preloadDesc')}
                  checked={settings.hsts_preload}
                  onChange={v => updateSetting('hsts_preload', v)}
                />
              </div>
            )}
          </Card>

          {/* Performance cache */}
          <Card title={t('cards.performanceCache')}>
            <RowToggle
              label="nginx FastCGI Cache"
              value={t('cache.fastcgiValue', { minutes: settings.fastcgi_cache_minutes })}
              description={t('cache.fastcgiDesc')}
              enabled={settings.fastcgi_cache}
              onToggle={() => updateSetting('fastcgi_cache', !settings.fastcgi_cache)}
            />
            {settings.fastcgi_cache && (
              <div className="mt-3 pl-4 border-l-2 border-slate-200 dark:border-slate-700">
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('cache.durationMinutes')}</label>
                <select value={settings.fastcgi_cache_minutes} onChange={event => updateSetting('fastcgi_cache_minutes', parseInt(event.target.value))}
                  className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono">
                  <option value={5}>{t('cache.min5')}</option>
                  <option value={15}>{t('cache.min15')}</option>
                  <option value={60}>{t('cache.min60')}</option>
                  <option value={360}>{t('cache.min360')}</option>
                  <option value={1440}>{t('cache.min1440')}</option>
                </select>
              </div>
            )}

            <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800">
              <RowToggle
                label={t('cache.browserLabel')}
                value={t('cache.browserValue', { days: settings.browser_cache_days })}
                description={t('cache.browserDesc')}
                enabled={settings.browser_cache}
                onToggle={() => updateSetting('browser_cache', !settings.browser_cache)}
              />
              {settings.browser_cache && (
                <div className="mt-3 pl-4 border-l-2 border-slate-200 dark:border-slate-700">
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('cache.durationDays')}</label>
                  <select value={settings.browser_cache_days} onChange={event => updateSetting('browser_cache_days', parseInt(event.target.value))}
                    className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono">
                    <option value={1}>{t('cache.day1')}</option>
                    <option value={7}>{t('cache.day7')}</option>
                    <option value={30}>{t('cache.day30')}</option>
                    <option value={90}>{t('cache.day90')}</option>
                    <option value={365}>{t('cache.day365')}</option>
                  </select>
                </div>
              )}
            </div>
          </Card>

          {isAdmin && !isSubdomain && customVhost && (
            <Card title={t('cards.vhostFile')}>
              <div className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
                {t('vhost.warningPre')}<strong>{t('vhost.warningBoldActually')}</strong>{t('vhost.warningMid')}<strong>{t('vhost.warningBoldEntire')}</strong>{t('vhost.warningPost')}
                <code className="font-mono">/.well-known/acme-challenge/</code>{t('vhost.warningTail')}
              </div>

              <div className="flex items-center justify-between gap-3 mb-3">
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {customVhost.enabled ? t('vhost.activeState') : t('vhost.managedState')}
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {customVhostDirty && <span className="text-[10px] uppercase tracking-wider text-amber-600 dark:text-amber-400 bg-amber-500/15 px-1.5 py-0.5 rounded">{t('vhost.unsaved')}</span>}
                  {customVhost.enabled && (
                    <button onClick={returnToManagedVhost} disabled={customVhostChanging}
                      className="px-3 py-1.5 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 text-xs rounded-md">
                      {customVhostChanging ? t('vhost.working') : t('vhost.returnToPanel')}
                    </button>
                  )}
                  <button onClick={saveCustomVhost} disabled={customVhostSaving || !customVhostDirty}
                    className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-40 text-white text-xs font-medium rounded-md">
                    {customVhostSaving ? t('vhost.saving') : t('saveApply')}
                  </button>
                </div>
              </div>

              <div className="rounded-lg overflow-hidden border border-slate-700">
                <CodeMirror
                  value={customVhostContent}
                  height="480px"
                  theme={oneDark}
                  onChange={setCustomVhostContent}
                  basicSetup={{
                    lineNumbers: true,
                    foldGutter: true,
                    highlightActiveLine: true,
                    highlightActiveLineGutter: true,
                    bracketMatching: true,
                    tabSize: 2,
                  }}
                  style={{ fontSize: '13px' }}
                />
              </div>
            </Card>
          )}

          {/* Additional directives */}
          <Card title={t('cards.additionalDirectives')}>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-2">
              {t('directives.pre')}<code className="font-mono">server</code>{t('directives.mid')}<code className="font-mono">client_max_body_size 200m;</code>
            </p>
            <textarea value={settings.extra_directives} onChange={event => updateSetting('extra_directives', event.target.value)}
              rows={6}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-xs font-mono"
              placeholder={t('directives.placeholder')} />
          </Card>

          <div className="flex gap-3 mt-6">
            <button onClick={save} disabled={processing}
              className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
              {processing ? t('applying') : t('saveApply')}
            </button>
            <button onClick={load} disabled={processing}
              className="px-4 py-2.5 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm rounded-md">
              {t('reload')}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4">
      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3 pb-2 border-b border-slate-100 dark:border-slate-800">{title}</h3>
      {children}
    </div>
  )
}

function RowToggle({ label, value, description, enabled, onToggle }:
  { label: string; value: string; description: string; enabled: boolean; onToggle: () => void }) {
  return (
    <div className="flex items-start gap-3 py-2 border-b border-slate-50 last:border-0">
      <button onClick={onToggle}
        className={`flex-shrink-0 mt-0.5 relative inline-flex h-6 w-11 items-center rounded-full transition ${
          enabled ? 'bg-emerald-500' : 'bg-slate-300'
        }`}>
        <span className={`inline-block h-4 w-4 transform rounded-full bg-white dark:bg-slate-800 shadow transition ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
      </button>
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline justify-between gap-2">
          <div className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">{label}</div>
          <code className="text-xs font-mono text-slate-500 dark:text-slate-500 truncate">{value}</code>
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{description}</div>
      </div>
    </div>
  )
}

function CheckboxRow({ label, description, checked, onChange }:
  { label: string; description: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-2 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)}
        className="mt-1 cursor-pointer" />
      <div>
        <div className="font-mono text-xs font-medium text-slate-900 dark:text-slate-100">{label}</div>
        <div className="text-xs text-slate-500 dark:text-slate-500">{description}</div>
      </div>
    </label>
  )
}