import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'

type Version = {
  version: string; code: string; resource: 'remi' | 'appstream'
  loaded: boolean; installable?: boolean
  pool_dir?: string; sock_dir?: string; service?: string; php_bin?: string
  real_version?: string; module_count?: number; description?: string
}

// Detached job runs in a background systemd transient unit under PID 1.
// It survives tab close. Status and log polling show live progress.
type ActiveOp = { version: string; resource: string; action: 'install' | 'remove' }
type OpStatus = { running: boolean; version?: string; resource?: string; action?: 'install' | 'remove'; status?: string }
type LogResponse = { log: string; running: boolean; version?: string; resource?: string; action?: 'install' | 'remove' }

type Filter = 'all' | 'installed' | 'available'

// embedded drops the breadcrumb, heading and page padding so the wizard can
// render this page as one of its steps without a page-within-a-page chrome.
export default function PHPVersionsPage({ embedded }: { embedded?: boolean } = {}) {
  const { t } = useTranslation('PHPVersionsPage')
  const { confirm, notify } = useDialog()
  const [versions, setVersions] = useState<Version[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [activeOp, setActiveOp] = useState<ActiveOp | null>(null)
  const [opLog, setOpLog] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const logRef = useRef<HTMLPreElement>(null)

  // Split so the mount effect never writes state synchronously: fetchVersions
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a completed install or removal.
  const fetchVersions = useCallback(() => {
    api.get<{ versions: Version[] }>('/php-versions')
      .then(r => setVersions(r.data.versions || []))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    fetchVersions()
  }, [fetchVersions])

  // Initial load: version list + catch any running job (resume-on-reopen).
  useEffect(() => {
    fetchVersions()
    api.get<OpStatus>('/php-versions/status')
      .then(r => {
        if (r.data.running && r.data.version) {
          setActiveOp({
            version: r.data.version,
            resource: r.data.resource || 'remi',
            action: r.data.action || 'install',
          })
        }
      })
      .catch(() => { // Ignore transient failures while resuming jobs.
      })
  }, [fetchVersions])

  // Poll active job every two seconds. Refresh the version list when the job completes.
  useEffect(() => {
    if (!activeOp) return
    let done = false
    const tick = async () => {
      try {
        const r = await api.get<LogResponse>('/php-versions/log')
        if (done) return
        setOpLog(r.data.log || '')
        if (!r.data.running) {
          setSuccess(activeOp.action === 'remove'
            ? t('success.removed', { version: activeOp.version })
            : t('success.installed', { version: activeOp.version }))
          setTimeout(() => setSuccess(null), 6000)
          setActiveOp(null)
          load()
        }
      } catch {
        // Keep polling through transient network failures.
      }
    }
    const id = window.setInterval(tick, 2000)
    tick()
    return () => { done = true; window.clearInterval(id) }
  }, [activeOp, load, t])

  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }) }, [opLog])

  async function install(v: Version) {
    if (activeOp) { await notify({ message: t('alerts.opInProgress') }); return }
    if (!(await confirm({ message: t('confirm.install', { version: v.version, resource: v.resource }) }))) return
    setError(null); setSuccess(null); setOpLog('')
    try {
      await api.post('/php-versions/install', { version: v.version, resource: v.resource })
      setOpLog(t('log.installStarted', { version: v.version }))
      setActiveOp({ version: v.version, resource: v.resource, action: 'install' })
    } catch (e) { setError(apiError(e, t('errors.startInstallFailed'))) }
  }

  async function remove(v: Version) {
    if (v.resource === 'appstream') {
      await notify({ message: t('alerts.appstreamCannotRemove') })
      return
    }
    if (activeOp) { await notify({ message: t('alerts.opInProgress') }); return }
    if (!(await confirm({ message: t('confirm.remove', { version: v.version }), dangerous: true }))) return
    setError(null); setSuccess(null); setOpLog('')
    try {
      await api.post('/php-versions/remove', { version: v.version, resource: v.resource })
      setOpLog(t('log.removeStarted', { version: v.version }))

      setActiveOp({ version: v.version, resource: v.resource, action: 'remove' })
    } catch (e) { setError(apiError(e, t('errors.startRemoveFailed'))) }
  }

  const filtered = versions.filter(v => {
    if (filter === 'installed') return v.loaded
    if (filter === 'available') return !v.loaded
    return true
  })
  const installedCount = versions.filter(v => v.loaded).length

  return (
    <div className={embedded ? '' : 'px-6 py-5'}>
      {!embedded && (
        <>
          <Breadcrumb items={[
            { label: t('breadcrumb.home'), href: '/' },
            { label: t('breadcrumb.tools'), href: '/tools-settings' },
            { label: t('breadcrumb.current') },
          ]} />

          <div className="mb-5">
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {t('subtitle')}
            </p>
          </div>
        </>
      )}

      {error && <div className="mb-3 flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-900/15 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-xs text-emerald-700 dark:border-emerald-800/50 dark:bg-emerald-900/15 dark:text-emerald-300">{success}</div>}

      {/* Active operation, inline live log */}
      {activeOp && (
        <div className="mb-4 rounded-2xl border border-brand-200 bg-brand-50 p-4 dark:border-brand-900/50 dark:bg-brand-900/15">
          <div className="mb-2 flex items-center gap-2">
            <span className="h-3 w-3 animate-spin rounded-full border-2 border-brand-400 border-t-transparent" />
            <span className="text-sm font-semibold text-brand-700 dark:text-brand-300">
              {activeOp.action === 'remove'
                ? t('log.removeInProgress', { version: activeOp.version })
                : t('log.installInProgress', { version: activeOp.version })}
            </span>
          </div>
          <pre ref={logRef} className="max-h-48 overflow-auto rounded-xl bg-slate-900 p-3 font-mono text-xs text-slate-100">{opLog || t('log.waiting')}</pre>
        </div>
      )}

      {/* Filter tabs */}
      <div className="mb-4 flex items-center gap-0.5 rounded-xl border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-800 dark:bg-slate-800/60">
        {(['all', 'installed', 'available'] as const).map(opt => (
          <button key={opt} onClick={() => setFilter(opt)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${filter === opt ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
            {opt === 'all' ? t('filters.all', { count: versions.length }) : opt === 'installed' ? t('filters.installed', { count: installedCount }) : t('filters.available', { count: versions.length - installedCount })}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-12 text-sm text-slate-400">
          <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-300 border-t-transparent dark:border-slate-600 dark:border-t-transparent" />
          {t('loading')}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
          {filtered.map(v => {
            const key = v.version + ':' + v.resource
            // Toggle state: on = installed. An AppStream version is the system
            // default and cannot be removed, so its toggle stays locked on.
            const thisOp = activeOp?.version === v.version
            const fixed = v.resource === 'appstream' && v.loaded
            const locked = !!activeOp || fixed
            return (
              <div key={key}
                className={`rounded-2xl border p-4 transition ${
                  v.loaded ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-900/20'
                    : 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/60'}`}>
                <div className="mb-2 flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">PHP {v.version}</div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                        v.resource === 'appstream' ? 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300'
                          : 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300'
                      }`}>{v.resource}</span>
                      {v.loaded && <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">{t('badges.installed')}</span>}
                      {parseInt(v.version) < 8 && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">{t('badges.eol')}</span>}
                    </div>
                  </div>
                  <button
                    onClick={() => { if (locked) return; if (v.loaded) { remove(v) } else { install(v) } }}
                    disabled={locked}
                    title={fixed ? t('actions.fixed') : v.loaded ? t('actions.remove') : t('actions.install')}
                    className={`flex-shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition ${
                      v.loaded ? (thisOp ? 'bg-sky-400 animate-pulse' : 'bg-emerald-500') : (thisOp ? 'bg-sky-400 animate-pulse' : 'bg-slate-300 dark:bg-slate-600')
                    } ${locked ? 'opacity-60 cursor-not-allowed' : ''}`}>
                    <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition ${v.loaded ? 'translate-x-6' : 'translate-x-1'}`} />
                  </button>
                </div>

                {v.description && <div className="mb-2 text-xs text-slate-500 dark:text-slate-400">{v.description}</div>}

                {v.loaded && (
                  <div className="mb-3 space-y-0.5 rounded-lg border border-slate-200 bg-white p-2 font-mono text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
                    {v.real_version && <div>{t('card.version')} <span className="text-slate-900 dark:text-slate-100">{v.real_version}</span></div>}
                    {v.module_count !== undefined && <div>{t('card.extensions')} <span className="text-slate-900 dark:text-slate-100">{v.module_count}</span></div>}
                    {v.service && <div className="truncate">{t('card.service')} <span className="text-slate-700 dark:text-slate-300">{v.service}</span></div>}
                  </div>
                )}

                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {thisOp ? t('hint.processing')
                    : v.loaded ? (v.resource === 'appstream' ? t('hint.appstream') : t('hint.installed'))
                      : t('hint.install')}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
