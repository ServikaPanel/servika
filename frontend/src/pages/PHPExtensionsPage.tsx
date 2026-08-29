import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { getCookie, setCookie } from '@/lib/cookies'
import Breadcrumb from '@/components/Breadcrumb'

type Version = { version: string; ini_dir: string; service: string }
type Extension = { name: string; active: boolean; ini_file: string }

const REQUIRED_EXTENSIONS = new Set([
  'core', 'date', 'standard', 'pdo', 'mysqlnd', 'phar', 'spl', 'reflection',
  'session', 'pcre', 'tokenizer', 'json', 'hash', 'random', 'libxml',
])

// The selected PHP version is remembered in a cookie (never localStorage), so a
// return to this page reopens the version last worked on. It is a page-scoped
// preference, so the Max-Age matches servika.migration.source's 30 days rather
// than the year the theme and language get.
const PHP_VERSION_COOKIE = 'servika.php.version'
const PHP_VERSION_MAX_AGE = 60 * 60 * 24 * 30
const DEFAULT_PHP_VERSION = '8.3'

export default function PHPExtensionsPage() {
  const { t } = useTranslation('PHPExtensionsPage')
  const { confirm, notify } = useDialog()
  const [versions, setVersions] = useState<Version[]>([])
  // Read the remembered version in a lazy initializer, not a mount effect
  // (react-hooks/set-state-in-effect), and accept it only when it is well
  // formed; the fetch below drops it to the default when it is not installed.
  const [activeVersion, setActiveVersionState] = useState(() => {
    const saved = getCookie(PHP_VERSION_COOKIE)
    return saved && /^\d+\.\d+$/.test(saved) ? saved : DEFAULT_PHP_VERSION
  })
  const setActiveVersion = useCallback((version: string) => {
    setActiveVersionState(version)
    setCookie(PHP_VERSION_COOKIE, version, PHP_VERSION_MAX_AGE)
  }, [])
  const [extensions, setExtensions] = useState<Extension[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [peclModalOpen, setPeclModalOpen] = useState(false)
  const [peclProgress, setPeclProgress] = useState<{ step: string; percent: number } | null>(null)

  // Split so the version effect never writes state synchronously: fetchExtensions
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchExtensions = useCallback(() => {
    api.get(`/php-extensions?version=${activeVersion}`)
      .then(response => {
        setExtensions(response.data.content || [])
        const list: Version[] = response.data.versions || []
        setVersions(list)
        // A remembered version that is no longer installed drops to the first
        // one, so an uninstall does not leave the page on a version that is gone.
        if (list.length > 0 && !list.some(v => v.version === activeVersion)) {
          setActiveVersion(list[0].version)
        }
      })
      .catch(error => {
        // The backend refuses a version it does not have, so a stale cookie
        // would otherwise strand the page on an error; drop to the default and
        // let the effect refetch. Only a 400 triggers this, so a network blip
        // does not silently change the selected version.
        if (activeVersion !== DEFAULT_PHP_VERSION && error?.response?.status === 400) {
          setActiveVersion(DEFAULT_PHP_VERSION)
          return
        }
        setError(apiError(error))
      })
      .finally(() => setLoading(false))
  }, [activeVersion, setActiveVersion])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchExtensions()
  }, [fetchExtensions])

  useEffect(() => { fetchExtensions() }, [fetchExtensions])

  async function toggle(extension: Extension) {
    if (REQUIRED_EXTENSIONS.has(extension.name.toLowerCase())) {
      await notify({ message: t('alerts.coreCannotDisable') })
      return
    }
    const active = !extension.active
    try {
      await api.put('/php-extensions/toggle', {
        version: activeVersion,
        ini_file: extension.ini_file,
        active,
      })
      setSuccess(active
        ? t('success.toggleEnabled', { name: extension.name })
        : t('success.toggleDisabled', { name: extension.name }))
      setTimeout(() => setSuccess(null), 3000)
      load()
    } catch (error) {
      setError(apiError(error, t('errors.toggleFailed')))
    }
  }

  async function installIonCube() {
    if (!(await confirm({ message: t('confirm.ionCubeInstall', { version: activeVersion }) }))) return
    setLoading(true); setError(null)
    try {
      const response = await api.post('/php-extensions/ioncube-install', { version: activeVersion })
      const data = response.data
      setSuccess(data.loaded ? t('success.ionCubeLoaded') : t('success.ionCubeNotLoaded'))
      setTimeout(() => setSuccess(null), 5000)
      load()
    } catch (error) {
      setError(apiError(error, t('errors.ionCubeInstallFailed')))
      setLoading(false)
    }
  }

  async function removeIonCube() {
    if (!(await confirm({ message: t('confirm.ionCubeRemove', { version: activeVersion }), dangerous: true }))) return
    setLoading(true); setError(null)
    try {
      await api.post('/php-extensions/ioncube-remove', { version: activeVersion })
      setSuccess(t('success.ionCubeRemoved'))
      setTimeout(() => setSuccess(null), 3000)
      load()
    } catch (error) {
      setError(apiError(error, t('errors.ionCubeRemoveFailed')))
      setLoading(false)
    }
  }

  async function installPecl(packageName: string) {
    if (!packageName.match(/^[a-zA-Z0-9_-]+$/)) {
      await notify({ message: t('alerts.invalidPackage'), tone: 'error' }); return
    }
    if (!(await confirm({ message: t('confirm.peclInstall', { package: packageName, version: activeVersion }) }))) return
    setPeclModalOpen(false)
    setError(null)
    setPeclProgress({ step: 'starting', percent: 2 })
    try {
      const { data } = await api.post('/php-extensions/pecl-install', { version: activeVersion, package: packageName })
      pollPecl(data.job_id, packageName)
    } catch (error) {
      setPeclProgress(null)
      setError(apiError(error, t('errors.peclInstallFailed')))
    }
  }

  // pollPecl follows the async install job and settles only through promise
  // callbacks (never a mount effect), so it does not trip set-state-in-effect. The
  // step and error come back as CODES the frontend localizes; the raw build log is
  // shown separately.
  function pollPecl(jobId: string, packageName: string) {
    const tick = () => {
      api.get('/php-extensions/pecl-status', { params: { id: jobId } })
        .then(({ data }) => {
          if (data.state === 'done') {
            setPeclProgress(null)
            setSuccess(t('success.peclInstalled', { package: packageName }))
            setTimeout(() => setSuccess(null), 5000)
            load()
            return
          }
          if (data.state === 'failed') {
            setPeclProgress(null)
            setError(t(`pecl.error.${data.error}`, { defaultValue: t('errors.peclInstallFailed') }))
            return
          }
          setPeclProgress({ step: data.step, percent: data.percent })
          setTimeout(tick, 1500)
        })
        .catch(() => {
          setPeclProgress(null)
          setError(t('errors.peclInstallFailed'))
        })
    }
    tick()
  }

  const filtered = filter ? extensions.filter(extension => extension.name.toLowerCase().includes(filter.toLowerCase())) : extensions
  const activeCount = extensions.filter(extension => extension.active).length
  const inactiveCount = extensions.length - activeCount

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.system') },
        { label: t('breadcrumb.current') },
      ]} />

      <div className="flex items-center justify-between mb-1">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <div className="flex gap-2">
          <button onClick={() => {
              const ionCubeInstalled = extensions.some(extension => extension.name.toLowerCase().includes('ioncube'))
              if (ionCubeInstalled) removeIonCube(); else installIonCube()
            }}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-sm rounded-md">
            {extensions.some(extension => extension.name.toLowerCase().includes('ioncube')) ? t('removeIonCube') : t('installIonCube')}
          </button>
          <button onClick={() => setPeclModalOpen(true)}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-800 text-white text-sm rounded-md">
            {t('installFromPecl')}
          </button>
        </div>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        {t('subtitle.pre')}<strong>{t('subtitle.bold')}</strong>{t('subtitle.post')}
      </p>

      {/* Version tabs */}
      <div className="flex gap-2 mb-4 border-b border-slate-200 dark:border-slate-700">
        {versions.map(version => (
          <button key={version.version} onClick={() => setActiveVersion(version.version)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition ${
              activeVersion === version.version
                ? 'border-brand-500 text-brand-700 dark:text-brand-300'
                : 'border-transparent text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 dark:text-slate-300'
            }`}>
            {t('versionTab', { version: version.version })}
          </button>
        ))}
      </div>

      {/* Toolbar with counters and search */}
      <div className="flex items-center justify-between mb-4 gap-3">
        <div className="flex items-center gap-3 text-sm">
          <span className="px-2.5 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 font-medium text-xs">
            {t('counters.enabled', { count: activeCount })}
          </span>
          <span className="px-2.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 dark:text-slate-500 font-medium text-xs">
            {t('counters.inactive', { count: inactiveCount })}
          </span>
          <span className="text-slate-400 dark:text-slate-500 text-xs">{t('counters.total', { count: extensions.length })}</span>
        </div>
        <input
          type="text"
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder={t('searchPlaceholder')}
          className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm w-64 focus:border-brand-500 outline-none"
        />
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {peclProgress && (
        <div className="mb-3 px-3 py-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md">
          <div className="flex items-center justify-between text-sm text-blue-700 dark:text-blue-300 mb-2">
            <span>{t(`pecl.step.${peclProgress.step}`, { defaultValue: peclProgress.step })}</span>
            <span className="font-mono">{peclProgress.percent}%</span>
          </div>
          <div className="h-2 w-full rounded-full bg-blue-100 dark:bg-blue-900/40 overflow-hidden">
            <div className="h-full rounded-full bg-blue-500 transition-all duration-500" style={{ width: `${peclProgress.percent}%` }} />
          </div>
        </div>
      )}

      {loading ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
          {filtered.map(extension => {
            const required = REQUIRED_EXTENSIONS.has(extension.name.toLowerCase())
            return (
              <div key={extension.ini_file}
                className={`flex items-center justify-between gap-2 px-3 py-2 rounded-md border ${
                  extension.active
                    ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800'
                    : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-700'
                }`}>
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">{extension.name}</div>
                  {required && <div className="text-[10px] text-slate-500 dark:text-slate-500">{t('coreExtension')}</div>}
                </div>
                <button
                  onClick={() => toggle(extension)}
                  disabled={required}
                  className={`flex-shrink-0 relative inline-flex h-5 w-9 items-center rounded-full transition ${
                    extension.active ? 'bg-emerald-500' : 'bg-slate-300'
                  } ${required ? 'opacity-40 cursor-not-allowed' : ''}`}
                  title={required ? t('toggleTitle.core') : (extension.active ? t('toggleTitle.disable') : t('toggleTitle.enable'))}
                >
                  <span className={`inline-block h-3 w-3 transform rounded-full bg-white dark:bg-slate-800 shadow transition ${extension.active ? 'translate-x-5' : 'translate-x-1'}`} />
                </button>
              </div>
            )
          })}
        </div>
      )}

      {peclModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setPeclModalOpen(false)}>
          <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={event => event.stopPropagation()}>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('peclModal.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-3">{t('peclModal.descPre')}<code className="font-mono">gmp, imap, bcmath</code>{t('peclModal.descMid')}<code className="font-mono">redis, mongodb, imagick</code>{t('peclModal.descPost')}</p>
            <p className="text-xs text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded p-2 mb-3">
              {t('peclModal.warnPre', { version: activeVersion })}<code className="font-mono">/etc/php.d/</code>{t('peclModal.warnMid')}
            </p>
            <input id="peclPackageName" type="text" autoFocus placeholder={t('peclModal.inputPlaceholder')}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm mb-3"
              onKeyDown={event => {
                if (event.key === 'Enter') {
                  const value = (event.target as HTMLInputElement).value.trim()
                  if (value) installPecl(value)
                }
              }} />
            <div className="flex justify-end gap-2">
              <button onClick={() => setPeclModalOpen(false)}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('peclModal.cancel')}</button>
              <button onClick={() => {
                const value = (document.getElementById('peclPackageName') as HTMLInputElement)?.value?.trim()
                if (value) installPecl(value)
              }} className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded">{t('peclModal.install')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}