import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
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

// CATALOG is the curated select-and-install list that replaced the free-text
// PECL box. Each item's `key` is the name sent to install; the backend probes
// its own candidate packages (bundled dnf, pecl dnf, then a source build). The
// category label and the per-item description are i18n keys, so only the
// extension name and key stay in the code. Adding an extension here is one line.
type CatalogItem = { name: string; key: string }
const CATALOG: { category: string; items: CatalogItem[] }[] = [
  { category: 'database', items: [
    { name: 'PostgreSQL', key: 'pgsql' },
    { name: 'Redis', key: 'redis' },
    { name: 'MongoDB', key: 'mongodb' },
    { name: 'SQLite3', key: 'sqlite3' },
    { name: 'OCI8 (Oracle)', key: 'oci8' },
    { name: 'ODBC', key: 'odbc' },
    { name: 'DBA', key: 'dba' },
  ] },
  { category: 'cache', items: [
    { name: 'APCu', key: 'apcu' },
    { name: 'Memcached', key: 'memcached' },
    { name: 'OPcache', key: 'opcache' },
    { name: 'igbinary', key: 'igbinary' },
  ] },
  { category: 'image', items: [
    { name: 'ImageMagick', key: 'imagick' },
    { name: 'GD', key: 'gd' },
    { name: 'EXIF', key: 'exif' },
  ] },
  { category: 'i18n', items: [
    { name: 'intl', key: 'intl' },
    { name: 'gettext', key: 'gettext' },
    { name: 'mbstring', key: 'mbstring' },
  ] },
  { category: 'development', items: [
    { name: 'Xdebug', key: 'xdebug' },
    { name: 'SPX', key: 'spx' },
    { name: 'AST', key: 'ast' },
  ] },
  { category: 'network', items: [
    { name: 'SOAP', key: 'soap' },
    { name: 'IMAP', key: 'imap' },
    { name: 'SSH2', key: 'ssh2' },
    { name: 'Sockets', key: 'sockets' },
    { name: 'AMQP', key: 'amqp' },
    { name: 'gRPC', key: 'grpc' },
  ] },
  { category: 'compression', items: [
    { name: 'Zip', key: 'zip' },
    { name: 'BZ2', key: 'bz2' },
    { name: 'Brotli', key: 'brotli' },
    { name: 'LZ4', key: 'lz4' },
  ] },
  { category: 'math', items: [
    { name: 'GMP', key: 'gmp' },
    { name: 'BCMath', key: 'bcmath' },
    { name: 'msgpack', key: 'msgpack' },
    { name: 'YAML', key: 'yaml' },
  ] },
  { category: 'other', items: [
    { name: 'LDAP', key: 'ldap' },
    { name: 'UUID', key: 'uuid' },
    { name: 'Swoole', key: 'swoole' },
    { name: 'Data Structures', key: 'ds' },
  ] },
]

const CATALOG_KEYS = new Set(CATALOG.flatMap(group => group.items.map(item => item.key)))

// matchesKey decides whether an installed extension name is the catalog key,
// loosely: a trailing version digit (redis6 → redis), a pdo_ prefix, or the key
// as a substring. It is used both to render a catalog item's toggle and to keep
// a matched extension out of the "outside the catalog" section.
function matchesKey(extensionName: string, key: string): boolean {
  const name = extensionName.toLowerCase()
  return name === key || name.replace(/[0-9]+$/, '') === key || name === 'pdo_' + key || name.includes(key)
}

// The selected PHP version is remembered in a cookie (never localStorage), so a
// return to this page reopens the version last worked on. It is a page-scoped
// preference, so the Max-Age matches servika.migration.source's 30 days rather
// than the year the theme and language get.
const PHP_VERSION_COOKIE = 'servika.php.version'
const PHP_VERSION_MAX_AGE = 60 * 60 * 24 * 30
const DEFAULT_PHP_VERSION = '8.3'

// embedded drops the breadcrumb, heading and page padding so the wizard can
// render this page as one of its steps without a page-within-a-page chrome.
export default function PHPExtensionsPage({ embedded }: { embedded?: boolean } = {}) {
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

  // install runs the same async job the free-text box used to, but the package
  // name comes from a catalog item so it is always well formed; the name shown
  // in every message is the catalog's display name.
  async function install(item: CatalogItem) {
    if (peclProgress) return
    if (!(await confirm({ message: t('confirm.catalogInstall', { name: item.name, key: item.key, version: activeVersion }), confirmLabel: t('catalog.install') }))) return
    setError(null); setSuccess(null)
    setPeclProgress({ step: 'starting', percent: 2 })
    try {
      const { data } = await api.post('/php-extensions/pecl-install', { version: activeVersion, package: item.key })
      pollPecl(data.job_id, item.name)
    } catch (error) {
      setPeclProgress(null)
      setError(apiError(error, t('errors.peclInstallFailed')))
    }
  }

  // pollPecl follows the async install job and settles only through promise
  // callbacks (never a mount effect), so it does not trip set-state-in-effect. The
  // step and error come back as CODES the frontend localizes; the raw build log is
  // shown separately.
  function pollPecl(jobId: string, displayName: string) {
    const tick = () => {
      api.get('/php-extensions/pecl-status', { params: { id: jobId } })
        .then(({ data }) => {
          if (data.state === 'done') {
            setPeclProgress(null)
            setSuccess(t('success.peclInstalled', { package: displayName }))
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

  const ionCubeInstalled = extensions.some(extension => extension.name.toLowerCase().includes('ioncube'))
  const findInstalled = useCallback(
    (key: string) => extensions.find(extension => matchesKey(extension.name, key)),
    [extensions])
  const f = filter.toLowerCase().trim()
  const groups = CATALOG
    .map(group => ({
      category: group.category,
      items: f
        ? group.items.filter(item => item.name.toLowerCase().includes(f) || item.key.includes(f) || t(`catalog.desc.${item.key}`).toLowerCase().includes(f))
        : group.items,
    }))
    .filter(group => group.items.length > 0)
  // Installed extensions the catalog does not name (the operator added them by
  // hand), so nothing installed is hidden from this screen.
  const extraInstalled = extensions.filter(extension => {
    const name = extension.name.toLowerCase()
    if (REQUIRED_EXTENSIONS.has(name) || name.includes('ioncube')) return false
    if ([...CATALOG_KEYS].some(key => matchesKey(name, key))) return false
    return f ? name.includes(f) : true
  })

  return (
    <div className={embedded ? '' : 'px-6 py-5'}>
      {!embedded && (
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.system') },
          { label: t('breadcrumb.current') },
        ]} />
      )}

      <div className="flex items-center justify-between mb-1">
        {!embedded && <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>}
        <button onClick={() => ionCubeInstalled ? removeIonCube() : installIonCube()}
          className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-sm rounded-md self-start">
          {ionCubeInstalled ? t('removeIonCube') : t('installIonCube')}
        </button>
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
                : 'border-transparent text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}>
            {t('versionTab', { version: version.version })}
          </button>
        ))}
      </div>

      <div className="flex items-center justify-end mb-4">
        <input
          type="text"
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder={t('searchPlaceholder')}
          className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded text-sm w-64 focus:border-brand-500 outline-none"
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
        <div className="space-y-6">
          {groups.map(group => (
            <section key={group.category}>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-2">{t(`catalog.category.${group.category}`)}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {group.items.map(item => {
                  const installed = findInstalled(item.key)
                  return (
                    <div key={item.key}
                      className={`flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg border ${
                        installed?.active ? 'bg-emerald-50 dark:bg-emerald-900/15 border-emerald-200 dark:border-emerald-800'
                        : installed ? 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-700'
                        : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700'
                      }`}>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{item.name} <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500">{item.key}</span></div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-500 truncate">{t(`catalog.desc.${item.key}`)}</div>
                      </div>
                      {installed ? (
                        <button onClick={() => toggle(installed)} title={installed.active ? t('toggleTitle.disable') : t('toggleTitle.enable')}
                          className={`flex-shrink-0 relative inline-flex h-5 w-9 items-center rounded-full transition ${installed.active ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`}>
                          <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow transition ${installed.active ? 'translate-x-5' : 'translate-x-1'}`} />
                        </button>
                      ) : (
                        <button onClick={() => install(item)} disabled={!!peclProgress}
                          className="flex-shrink-0 px-2.5 py-1 text-xs font-medium rounded-md bg-brand-600 hover:bg-brand-700 text-white disabled:opacity-50">{t('catalog.install')}</button>
                      )}
                    </div>
                  )
                })}
              </div>
            </section>
          ))}

          {extraInstalled.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-2">{t('catalog.extraInstalled')}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {extraInstalled.map(extension => (
                  <div key={extension.ini_file} className={`flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg border ${extension.active ? 'bg-emerald-50 dark:bg-emerald-900/15 border-emerald-200 dark:border-emerald-800' : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-700'}`}>
                    <div className="font-mono text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{extension.name}</div>
                    <button onClick={() => toggle(extension)} title={extension.active ? t('toggleTitle.disable') : t('toggleTitle.enable')}
                      className={`flex-shrink-0 relative inline-flex h-5 w-9 items-center rounded-full transition ${extension.active ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`}>
                      <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow transition ${extension.active ? 'translate-x-5' : 'translate-x-1'}`} />
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {!embedded && (
        <p className="mt-6 text-xs text-slate-400 dark:text-slate-500">
          {t('catalog.footerPre')}<Link to="/tools-settings" className="text-brand-600 dark:text-brand-400 underline">{t('catalog.footerLink')}</Link>{t('catalog.footerPost')}
        </p>
      )}
    </div>
  )
}
