import type { ReactNode } from 'react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import { useResourceScope } from '@/lib/scope'

type Version = { version: string; pool_dir: string; sock_dir: string; service: string; description: string }

type Settings = {
  memory_limit: string; max_execution_time: number; max_input_time: number
  post_max_size: string; upload_max_filesize: string; opcache_enable: boolean
  disable_functions: string
  display_errors: boolean; log_errors: boolean; allow_url_fopen: boolean
  file_uploads: boolean; short_open_tag: boolean
  error_reporting: string; include_path: string; open_basedir: string
  session_save_path: string; mail_force_extra_parameters: string
  pm_strategy: string; pm_max_children: number; pm_max_requests: number
  pm_start_servers: number; pm_min_spare_servers: number; pm_max_spare_servers: number
  extra_directives: string
  debug_mode: boolean
}

type Response = {
  domain_name: string; system_user: string; php_version: string
  settings: Settings; versions: Version[]
  modules?: string[]
}

const PROCESS_MANAGER_OPTIONS = [
  { value: 'ondemand', label: 'ondemand (recommended, zero processes when idle)' },
  { value: 'dynamic', label: 'dynamic (scales with load)' },
  { value: 'static', label: 'static (fixed pool)' },
]

export default function DomainPHPPage() {
  const { t } = useTranslation('DomainPHPPage')
  const { id, base, isSubdomain, backHref } = useResourceScope()
  const [response, setResponse] = useState<Response | null>(null)
  const [selectedVersion, setSelectedVersion] = useState<string>('')
  const [settings, setSettings] = useState<Settings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [debugLog, setDebugLog] = useState<string[]>([])
  const [debugLogLoading, setDebugLogLoading] = useState(false)

  // Declared before the loader that calls it: a function hoisted past its own
  // use site cannot pick up a later definition, so the earlier call would keep
  // an older closure over id.
  const loadDebugLog = useCallback(async () => {
    if (!id) return
    setDebugLogLoading(true)
    try {
      const { data } = await api.get<{ lines: string[] }>(`/domains/${id}/php/debug-log`)
      setDebugLog(data.lines || [])
    } catch {
      setDebugLog([])
    } finally {
      setDebugLogLoading(false)
    }
  }, [id])

  // Split so the mount effect never writes state synchronously: fetchSettings
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a write.
  const fetchSettings = useCallback(() => {
    if (!id) return
    api.get<Response>(`${base}/php-settings`)
      .then(r => { setResponse(r.data); setSelectedVersion(r.data.php_version); setSettings(r.data.settings); loadDebugLog() })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [base, id, loadDebugLog])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchSettings()
  }, [fetchSettings])

  useEffect(() => { fetchSettings() }, [fetchSettings])

  async function save() {
    if (!settings) return
    setIsProcessing(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.put(`${base}/php-settings`, { php_version: selectedVersion, settings })
      setSuccess(t('saved', { version: data.php_version, socket: data.socket }))
      load()
    } catch (e) {
      setError(refusalMessage(e, t('saveFailed')))
    } finally {
      setIsProcessing(false)
    }
  }

  // The size boxes are free text now, so the server can refuse what was typed.
  // It answers a stable CODE rather than a sentence, because this screen renders
  // twelve languages. Anything that is not one of these codes passes through as
  // the server wrote it, so a new refusal is never swallowed.
  function refusalMessage(cause: unknown, fallback: string): string {
    switch (apiError(cause, '')) {
      case 'php_size_value_invalid':
        return t('refusal.sizeInvalid')
      case 'php_setting_contains_control_character':
        return t('refusal.controlCharacter')
      default:
        return apiError(cause, fallback)
    }
  }

  async function clearDebugLog() {
    if (!id) return
    setDebugLogLoading(true); setError(null)
    try {
      await api.delete(`/domains/${id}/php/debug-log`)
      setDebugLog([])
    } catch (e) {
      setError(apiError(e, t('clearLogFailed')))
    } finally {
      setDebugLogLoading(false)
    }
  }

  function updateSetting<K extends keyof Settings>(key: K, value: Settings[K]) {
    if (!settings) return; setSettings({ ...settings, [key]: value })
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: response?.domain_name || '...', href: backHref },
        { label: t('breadcrumb.phpSettings') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {response && <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">
        <Link to={backHref} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 font-medium">{response.domain_name}</Link>
        {' · '}{t('systemUser')}<code className="font-mono">{response.system_user}</code>
      </p>}

      <div className="mb-5 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
        {t('poolNotice.pre')}<code className="font-mono">php_admin_value/flag</code>{t('poolNotice.mid1')}<code className="font-mono">.htaccess</code>{t('poolNotice.mid2')}<code className="font-mono">.user.ini</code>{t('poolNotice.post')}
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading || !settings || !response ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-400">{t('loading')}</div> : (
        <>
          {/* PHP version displayed as compact segmented controls */}
          <Card title={t('version.title')}>
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 p-1">
                {response.versions.map(version => {
                  const isSelected = selectedVersion === version.version
                  const isActive = response.php_version === version.version
                  return (
                    <button key={version.version} onClick={() => setSelectedVersion(version.version)}
                      className={`relative inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-mono transition ${
                        isSelected
                          ? 'bg-white dark:bg-slate-800 shadow-sm text-slate-900 ring-1 ring-brand-300'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-white dark:bg-slate-800/60'
                      }`}>
                      <span className="font-semibold">PHP {version.version}</span>
                      {isActive && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title={t('version.active')} />}
                    </button>
                  )
                })}
              </div>
              {(() => {
                const version = response.versions.find(candidate => candidate.version === selectedVersion)
                if (!version) return null
                const isActive = response.php_version === selectedVersion
                return (
                  <span className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                    <span>{version.description}</span>
                    {isActive ? (
                      <span className="text-[10px] uppercase tracking-wider bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 rounded font-semibold">{t('version.active')}</span>
                    ) : (
                      <span className="text-[10px] uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 rounded font-semibold">{t('version.saveToApply')}</span>
                    )}
                  </span>
                )
              })()}
            </div>
          </Card>

          {/* Performance and security */}
          <Card title={t('cards.performance')}>
            <Grid>
              <Section label="memory_limit" help={t('help.memoryLimit')}>
                <Txt value={settings.memory_limit} onChange={v => updateSetting('memory_limit', v)} mono placeholder={t('size.placeholder')} />
              </Section>
              <NumberField label="max_execution_time" suffix="sec" help={t('help.maxExecutionTime')} value={settings.max_execution_time} onChange={v => updateSetting('max_execution_time', v)} />
              <NumberField label="max_input_time" suffix="sec" help={t('help.maxInputTime')} value={settings.max_input_time} onChange={v => updateSetting('max_input_time', v)} />
              <Section label="post_max_size" help={t('help.postMaxSize')}>
                <Txt value={settings.post_max_size} onChange={v => updateSetting('post_max_size', v)} mono placeholder={t('size.placeholder')} />
              </Section>
              <Section label="upload_max_filesize" help={t('help.uploadMaxFilesize')}>
                <Txt value={settings.upload_max_filesize} onChange={v => updateSetting('upload_max_filesize', v)} mono placeholder={t('size.placeholder')} />
              </Section>
              <Flag label="opcache.enable" help={t('help.opcacheEnable')} value={settings.opcache_enable} onChange={v => updateSetting('opcache_enable', v)} t={t} />
            </Grid>
            <div className="mt-4">
              <Label>disable_functions <Hint text={t('help.disableFunctions')} /></Label>
              <Txt value={settings.disable_functions} onChange={v => updateSetting('disable_functions', v)} mono />
            </div>
          </Card>

          {/* Common settings */}
          <Card title={t('cards.general')}>
            <Grid>
              <Flag label="display_errors" help={t('help.displayErrors')} value={settings.display_errors} onChange={v => updateSetting('display_errors', v)} t={t} />
              <Flag label="log_errors" help={t('help.logErrors')} value={settings.log_errors} onChange={v => updateSetting('log_errors', v)} t={t} />
              <Flag label="allow_url_fopen" help={t('help.allowUrlFopen')} value={settings.allow_url_fopen} onChange={v => updateSetting('allow_url_fopen', v)} t={t} />
              <Flag label="file_uploads" help={t('help.fileUploads')} value={settings.file_uploads} onChange={v => updateSetting('file_uploads', v)} t={t} />
              <Flag label="short_open_tag" help={t('help.shortOpenTag')} value={settings.short_open_tag} onChange={v => updateSetting('short_open_tag', v)} t={t} />
            </Grid>
            <Field label="error_reporting" help={t('help.errorReporting')}>
              <Txt value={settings.error_reporting} onChange={v => updateSetting('error_reporting', v)} mono />
            </Field>
            <Field label="include_path" help={t('help.includePath')}>
              <Txt value={settings.include_path} onChange={v => updateSetting('include_path', v)} mono />
            </Field>
            <Field label="open_basedir" help={t('help.openBasedir')}>
              <Txt value={settings.open_basedir} onChange={v => updateSetting('open_basedir', v)} mono placeholder={t('openBasedirPlaceholder')} />
            </Field>
            <Field label="session.save_path" help={t('help.sessionSavePath')}>
              <Txt value={settings.session_save_path} onChange={v => updateSetting('session_save_path', v)} mono />
            </Field>
            <Field label="mail.force_extra_parameters" help={t('help.mailForceExtraParameters')}>
              <Txt value={settings.mail_force_extra_parameters} onChange={v => updateSetting('mail_force_extra_parameters', v)} mono />
            </Field>
          </Card>
          {/* PHP Debug Mode. The auto_prepend shim and its log are written once per
              tenant home, so they belong to the domain scope; a subdomain would show
              the parent's log rather than its own. */}
          {!isSubdomain && <Card title={t('cards.debugMode')}>
            <div className="flex items-start gap-4">
              <button onClick={() => updateSetting('debug_mode', !settings.debug_mode)}
                className={`flex-shrink-0 mt-0.5 relative inline-flex h-6 w-11 items-center rounded-full transition ${settings.debug_mode ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-600'}`}
                title={settings.debug_mode ? t('debug.disableTitle') : t('debug.enableTitle')}>
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition ${settings.debug_mode ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('debug.label')}</span>
                  <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-semibold ${settings.debug_mode ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'}`}>
                    {settings.debug_mode ? t('debug.on') : t('debug.off')}
                  </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                  {t('debug.descPre')}<code className="font-mono">register_shutdown_function</code>{t('debug.descMid')}
                  <code className="font-mono"> .servika/php_debug.log</code>{t('debug.descPost')}<code className="font-mono">error_reporting(0)</code>{t('debug.descEnd')}
                </p>
              </div>
            </div>
            {settings.debug_mode && (
              <div className="mt-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
                <strong>{t('debug.warningLabel')}</strong>{t('debug.warningPre')}<strong>{t('debug.warningBold1')}</strong>{t('debug.warningMid')}
                <strong> {t('debug.warningBold2')}</strong>{t('debug.warningPost')}<strong>{t('debug.warningBold3')}</strong>{t('debug.warningEnd')}<strong>{t('debug.warningSave')}</strong>{t('debug.warningDot')}
              </div>
            )}
          </Card>}

          {/* Last Errors -- debug log panel */}
          {!isSubdomain && <Card title={t('cards.lastErrors')}>
            <div className="flex items-center justify-between gap-3 mb-3">
              <p className="text-xs text-slate-500 dark:text-slate-400 min-w-0 break-all">
                {t('debugLog.sourcePre')}<code className="font-mono">/home/{response.system_user}/.servika/php_debug.log</code>{t('debugLog.sourcePost')}
              </p>
              <div className="flex gap-2 flex-shrink-0">
                <button onClick={loadDebugLog} disabled={debugLogLoading}
                  className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400 text-xs font-medium rounded-md transition">
                  {debugLogLoading ? t('debugLog.loading') : t('debugLog.refresh')}
                </button>
                <button onClick={clearDebugLog} disabled={debugLogLoading}
                  className="px-3 py-1.5 border border-red-300 dark:border-red-700 hover:bg-red-50 dark:bg-red-900/20 dark:hover:bg-red-900/30 text-red-600 dark:text-red-400 text-xs font-medium rounded-md transition">
                  {t('debugLog.clear')}
                </button>
              </div>
            </div>
            {debugLog.length === 0 ? (
              <div className="text-xs text-slate-400 dark:text-slate-400 italic py-4 text-center">
                {!settings.debug_mode ? t('debugLog.emptyOff') : t('debugLog.emptyOn')}
              </div>
            ) : (
              <div className="max-h-80 overflow-auto rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-950">
                <ul className="divide-y divide-slate-800">
                  {[...debugLog].reverse().map((line, i) => (
                    <li key={i} className="px-3 py-1.5 text-[11px] font-mono text-red-300 whitespace-pre-wrap break-all leading-relaxed">
                      {line}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>}

          {/* PHP-FPM pool */}
          <Card title={t('cards.fpmPool')}>
            <Grid>
              <Section label="pm" help={t('help.pm')}>
                <select value={settings.pm_strategy} onChange={e => updateSetting('pm_strategy', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono">
                  {PROCESS_MANAGER_OPTIONS.map(p => <option key={p.value} value={p.value}>{t(`processManager.${p.value}`, { defaultValue: p.label })}</option>)}
                </select>
              </Section>
              <NumberField label="pm.max_children" help={t('help.pmMaxChildren')} value={settings.pm_max_children} onChange={v => updateSetting('pm_max_children', v)} />
              <NumberField label="pm.max_requests" help={t('help.pmMaxRequests')} value={settings.pm_max_requests} onChange={v => updateSetting('pm_max_requests', v)} />
              <NumberField label="pm.start_servers" help={t('help.pmStartServers')} value={settings.pm_start_servers} onChange={v => updateSetting('pm_start_servers', v)} />
              <NumberField label="pm.min_spare_servers" help={t('help.pmMinSpareServers')} value={settings.pm_min_spare_servers} onChange={v => updateSetting('pm_min_spare_servers', v)} />
              <NumberField label="pm.max_spare_servers" help={t('help.pmMaxSpareServers')} value={settings.pm_max_spare_servers} onChange={v => updateSetting('pm_max_spare_servers', v)} />
            </Grid>
          </Card>

          {/* Read-only, server-level PHP modules */}
          <Card title={t('cards.installedModules')}>
            <div className="flex items-baseline justify-between mb-2">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {t('modules.countPre')}<strong>{response.modules?.length || 0}</strong>{t('modules.countPost', { count: response.modules?.length || 0, version: response.php_version })}
              </p>
              <Link to="/system/php-modules" className="text-xs text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 font-medium whitespace-nowrap">
                {t('modules.manageServer')}
              </Link>
            </div>
            <div className="flex flex-wrap gap-1">
              {(response.modules || []).map(m => (
                <span key={m} className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                  {m}
                </span>
              ))}
            </div>
          </Card>

          {/* Per-domain disable_functions controls for dangerous functions */}
          <Card title={t('cards.disableDangerous')}>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
              {t('dangerous.descPre')}<code className="font-mono">disable_functions</code>{t('dangerous.descMid')}<strong>{t('dangerous.descBoldOn')}</strong>{t('dangerous.descAnd')}<strong>{t('dangerous.descBoldOff')}</strong>{t('dangerous.descPost')}
            </p>
            {(() => {
              const groups = [
                { name: t('dangerous.groups.shellExecution'), color: 'red',
                  functions: ['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen', 'pcntl_exec'] },
                { name: t('dangerous.groups.fileExecution'), color: 'orange',
                  functions: ['assert', 'create_function'] },
                { name: t('dangerous.groups.networkAccess'), color: 'amber',
                  functions: ['fsockopen', 'pfsockopen', 'stream_socket_client', 'curl_multi_exec'] },
                { name: t('dangerous.groups.systemDiscovery'), color: 'sky',
                  functions: ['phpinfo', 'posix_kill', 'posix_setuid', 'posix_setgid', 'posix_setpgid'] },
                { name: t('dangerous.groups.moduleLoading'), color: 'violet',
                  functions: ['dl', 'putenv', 'pcntl_signal', 'pcntl_fork'] },
              ]
              const disabledFunctions = (settings.disable_functions || '').split(',').map(name => name.trim()).filter(Boolean)
              const disabledSet = new Set(disabledFunctions)

              function getGroupStatus(group: typeof groups[0]) {
                // All disabled means blocked, none disabled means enabled, otherwise the group is mixed.
                const allDisabled = group.functions.every(name => disabledSet.has(name))
                const noneDisabled = group.functions.every(name => !disabledSet.has(name))
                if (allDisabled) return 'blocked'
                if (noneDisabled) return 'active'
                return 'mixed'
              }
              function toggleGroup(group: typeof groups[0]) {
                const nextDisabled = new Set(disabledSet)
                const allDisabled = group.functions.every(name => nextDisabled.has(name))
                if (allDisabled) {
                  // Remove every function to enable the group.
                  group.functions.forEach(name => nextDisabled.delete(name))
                } else {
                  // Add every function to block the group.
                  group.functions.forEach(name => nextDisabled.add(name))
                }
                updateSetting('disable_functions', Array.from(nextDisabled).join(','))
              }
              const colorClasses: Record<string, string> = {
                red: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20',
                orange: 'border-orange-200 bg-orange-50/40',
                amber: 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20',
                sky: 'border-sky-200 bg-sky-50 dark:bg-sky-900/20',
                violet: 'border-violet-200 dark:border-violet-800 bg-violet-50 dark:bg-violet-900/20',
              }

              return (
                <div className="space-y-2">
                  {groups.map(group => {
                    const groupStatus = getGroupStatus(group)
                    const isBlocked = groupStatus === 'blocked'
                    const isMixed = groupStatus === 'mixed'
                    return (
                      <div key={group.name} className={`border rounded-lg p-3 ${colorClasses[group.color]}`}>
                        <div className="flex items-start gap-3">
                          <button onClick={() => toggleGroup(group)}
                            className={`flex-shrink-0 mt-0.5 relative inline-flex h-5 w-9 items-center rounded-full transition ${
                              isBlocked ? 'bg-red-500' : (isMixed ? 'bg-amber-400' : 'bg-emerald-500')
                            }`}
                            title={isBlocked ? t('dangerous.enableAll') : t('dangerous.blockAll')}>
                            <span className={`inline-block h-3 w-3 transform rounded-full bg-white dark:bg-slate-800 shadow transition ${
                              isBlocked ? 'translate-x-1' : 'translate-x-5'
                            }`} />
                          </button>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-baseline gap-2">
                              <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{group.name}</span>
                              <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-medium ${
                                isBlocked ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' : (isMixed ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300' : 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300')
                              }`}>
                                {isBlocked ? t('dangerous.blocked') : (isMixed ? t('dangerous.mixed') : t('dangerous.active'))}
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-600 dark:text-slate-400 font-mono mt-0.5 break-all">
                              {group.functions.join(', ')}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )
            })()}

            <details className="mt-4">
              <summary className="text-xs text-slate-600 cursor-pointer hover:text-slate-900 dark:hover:text-slate-100">{t('dangerous.editManually')}</summary>
              <input value={settings.disable_functions} onChange={e => updateSetting('disable_functions', e.target.value)}
                className="w-full mt-2 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-xs font-mono" />
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{t('dangerous.commaSeparated')}</p>
            </details>
          </Card>

          {/* Additional directives */}
          <Card title={t('cards.additionalDirectives')}>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
              {t('additional.descPre')}<code className="font-mono">extension=imagick.so</code>
            </p>
            <textarea value={settings.extra_directives} onChange={e => updateSetting('extra_directives', e.target.value)}
              rows={5}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-xs font-mono"
              placeholder=";extension=imagick.so&#10;date.timezone = Europe/Istanbul" />
          </Card>

          {/* Save controls */}
          <div className="flex gap-3 mt-6">
            <button onClick={save} disabled={isProcessing}
              className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
              {isProcessing ? t('save.saving') : t('save.saveAndApply')}
            </button>
            <button onClick={load} disabled={isProcessing}
              className="px-4 py-2.5 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm rounded-md">
              {t('save.cancelReload')}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ----- Helper components -----
function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5">
      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-4 pb-2 border-b border-slate-100 dark:border-slate-800">{title}</h3>
      {children}
    </div>
  )
}
function Grid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-2 gap-x-6 gap-y-3">{children}</div>
}
function Label({ children }: { children: ReactNode }) {
  return <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{children}</label>
}
function Hint({ text }: { text: string }) {
  return <span title={text} className="inline-block ml-1 text-slate-400 dark:text-slate-400 cursor-help">ⓘ</span>
}
function Field({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <div className="mt-3">
      <Label>{label} <Hint text={help} /></Label>
      {children}
    </div>
  )
}
function Section({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <div>
      <Label>{label} <Hint text={help} /></Label>
      {children}
    </div>
  )
}
function NumberField({ label, help, suffix, value, onChange }: { label: string; help: string; suffix?: string; value: number; onChange: (v: number) => void }) {
  return (
    <Section label={label} help={help}>
      <div className="flex">
        <input type="number" value={value} onChange={e => onChange(parseInt(e.target.value || '0'))}
          className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono" />
        {suffix && <span className="ml-2 text-xs text-slate-500 dark:text-slate-400 self-center">{suffix}</span>}
      </div>
    </Section>
  )
}
function Txt({ value, onChange, mono, placeholder }: { value: string; onChange: (v: string) => void; mono?: boolean; placeholder?: string }) {
  return (
    <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      className={`w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm ${mono ? 'font-mono' : ''}`} />
  )
}
function Flag({ label, help, value, onChange, t }: { label: string; help: string; value: boolean; onChange: (v: boolean) => void; t: TFunction }) {
  return (
    <Section label={label} help={help}>
      <button onClick={() => onChange(!value)}
        className={`px-3 py-2 rounded-md text-sm font-mono w-full text-left transition border ${value ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-300 text-emerald-700 dark:text-emerald-300' : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'}`}>
        {value ? t('flag.on') : t('flag.off')}
      </button>
    </Section>
  )
}
