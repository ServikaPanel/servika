// PHP & Server Setup Wizard — gathers the scattered PHP version / extension /
// loader / web-server screens into one step-by-step surface (EasyApache style).
// Each step renders an existing management screen embedded, so there is one code
// path and the same backend endpoints; only the chrome is the wizard's.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import PHPVersionsPage, { type VersionSelection } from './PHPVersionsPage'
import PHPExtensionsPage, { type Selection } from './PHPExtensionsPage'

const STEPS = ['versions', 'extensions', 'webserver', 'summary'] as const
type Step = (typeof STEPS)[number]

export default function PHPServerWizardPage() {
  const { t } = useTranslation('PHPServerWizardPage')
  const [active, setActive] = useState<Step>('versions')
  const activeIdx = STEPS.indexOf(active)
  // Versions and extensions picked across the wizard; the Summary step installs
  // them in bulk, versions first so an extension can target a version installed
  // in the same run.
  const [selectedVersions, setSelectedVersions] = useState<VersionSelection[]>([])
  const [selected, setSelected] = useState<Selection[]>([])

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.tools'), href: '/tools-settings' },
        { label: t('breadcrumb.current') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('subtitle')}</p>

      <div className="grid grid-cols-1 lg:grid-cols-[15rem_minmax(0,1fr)] gap-5 items-start">
        <nav className="lg:sticky lg:top-[4.5rem] flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible pb-1">
          {STEPS.map((key, i) => {
            const selected = key === active
            const done = i < activeIdx
            return (
              <button
                key={key}
                onClick={() => setActive(key)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition shrink-0 lg:shrink w-auto lg:w-full ${
                  selected
                    ? 'bg-brand-50 dark:bg-brand-900/25 border border-brand-300 dark:border-brand-700'
                    : 'border border-transparent hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                <span className={`flex items-center justify-center w-6 h-6 rounded-full text-xs font-semibold shrink-0 ${
                  selected ? 'bg-brand-600 text-white' : done ? 'bg-emerald-500 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
                }`}>
                  {done ? '✓' : i + 1}
                </span>
                <span className="min-w-0">
                  <span className={`block text-sm font-medium ${selected ? 'text-brand-800 dark:text-brand-200' : 'text-slate-700 dark:text-slate-200'}`}>{t(`steps.${key}.name`)}</span>
                  <span className="hidden lg:block text-[11px] text-slate-400 dark:text-slate-500 truncate">{t(`steps.${key}.desc`)}</span>
                </span>
              </button>
            )
          })}
        </nav>

        <section className="min-w-0">
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-4 sm:p-5">
            {active === 'versions' && <PHPVersionsPage embedded selectedVersions={selectedVersions} setSelectedVersions={setSelectedVersions} />}
            {active === 'extensions' && <PHPExtensionsPage embedded selected={selected} setSelected={setSelected} />}
            {active === 'webserver' && <WebServerStep />}
            {active === 'summary' && <SummaryStep selected={selected} selectedVersions={selectedVersions} onClear={() => { setSelected([]); setSelectedVersions([]) }} />}
          </div>

          <div className="flex items-center justify-between mt-4">
            <button
              onClick={() => activeIdx > 0 && setActive(STEPS[activeIdx - 1])}
              disabled={activeIdx === 0}
              className="px-4 py-2 text-sm rounded-md border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40"
            >← {t('nav.back')}</button>
            {activeIdx < STEPS.length - 1 ? (
              <button
                onClick={() => setActive(STEPS[activeIdx + 1])}
                className="px-4 py-2 text-sm rounded-md bg-slate-900 hover:bg-slate-800 dark:bg-slate-700 dark:hover:bg-slate-600 text-white dark:text-slate-100 font-medium"
              >{t('nav.next')} →</button>
            ) : (
              <Link to="/tools-settings" className="px-4 py-2 text-sm rounded-md bg-emerald-600 hover:bg-emerald-700 text-white font-medium">{t('nav.finish')}</Link>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

type Version = { version: string; loaded: boolean }

// WebServerStep states the platform's real architecture: nginx plus an isolated
// per-tenant PHP-FPM pool. cPanel/EasyApache's Apache-compile model does not
// apply here, and the step says so honestly rather than drawing controls for it.
function WebServerStep() {
  const { t } = useTranslation('PHPServerWizardPage')
  const [installed, setInstalled] = useState<number | null>(null)
  useEffect(() => {
    api.get<{ versions: Version[] }>('/php-versions')
      .then(r => setInstalled((r.data.versions || []).filter(v => v.loaded).length))
      .catch(() => setInstalled(null))
  }, [])
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('webserver.heading')}</h2>
      <div className="rounded-xl border border-sky-200 dark:border-sky-800/50 bg-sky-50 dark:bg-sky-900/15 p-4 text-sm text-sky-800 dark:text-sky-200">
        {t('webserver.intro')}
      </div>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <StatusCard label={t('webserver.card.server')} value="nginx" ok />
        <StatusCard label={t('webserver.card.mode')} value={t('webserver.card.modeValue')} ok />
        <StatusCard label={t('webserver.card.installed')} value={installed != null ? t('webserver.card.installedValue', { count: installed }) : '…'} ok={!!installed} />
        <StatusCard label={t('webserver.card.apache')} value={t('webserver.card.apacheValue')} ok />
      </dl>
      <p className="text-xs text-slate-500 dark:text-slate-500">{t('webserver.note')}</p>
    </div>
  )
}

function StatusCard({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-3">
      <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-1">{label}</div>
      <div className="flex items-center gap-1.5 text-sm font-medium text-slate-800 dark:text-slate-200">
        <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
        {value}
      </div>
    </div>
  )
}

type BulkState = 'pending' | 'installing' | 'done' | 'error'
type BulkKind = 'version' | 'extension'
type BulkRow = { kind: BulkKind; version: string; key: string; name: string; resource?: string; state: BulkState; message?: string }

// installExtensionJob runs the async PECL job for one extension and resolves when
// it is done. It rejects with { peclError } for a job failure (a localizable CODE)
// or the raw axios error for a transport failure, so the caller can word both.
function installExtensionJob(sel: Selection, onProgress: (step: string, percent: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    api.post('/php-extensions/pecl-install', { version: sel.version, package: sel.key })
      .then(({ data }) => {
        const jobId = data.job_id
        const tick = () => {
          api.get('/php-extensions/pecl-status', { params: { id: jobId } })
            .then(({ data }) => {
              if (data.state === 'done') { resolve(); return }
              if (data.state === 'failed') { reject({ peclError: data.error }); return }
              onProgress(data.step, data.percent)
              setTimeout(tick, 1500)
            })
            .catch(reject)
        }
        tick()
      })
      .catch(reject)
  })
}

// installVersionJob runs the detached PHP-version install (a systemd transient
// unit) and watches it through the server-wide single-slot status endpoint. The
// job carries no percent, so progress is coarse: running → 55, finishing → 95.
// It resolves when the slot is free again, matching the standalone page, which
// also reports completion on !running rather than reading a failure status.
function installVersionJob(sel: VersionSelection, onProgress: (step: string, percent: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    api.post('/php-versions/install', { version: sel.version, resource: sel.resource })
      .then(() => {
        const tick = () => {
          api.get<{ running: boolean; version?: string }>('/php-versions/status')
            .then(({ data }) => {
              if (!data.running) { resolve(); return }
              const here = data.version === sel.version
              onProgress(here ? 'installing' : 'finishing', here ? 55 : 95)
              setTimeout(tick, 2000)
            })
            .catch(reject)
        }
        setTimeout(tick, 2000)
      })
      .catch(reject)
  })
}

// SummaryStep lists the installed PHP versions and installs the components the
// operator picked in the earlier steps, one after another (versions first, then
// extensions) with a live progress bar and a per-row status badge.
function SummaryStep({ selected, selectedVersions, onClear }: { selected: Selection[]; selectedVersions: VersionSelection[]; onClear: () => void }) {
  const { t } = useTranslation(['PHPServerWizardPage', 'PHPExtensionsPage'])
  const [versions, setVersions] = useState<Version[]>([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [rows, setRows] = useState<BulkRow[]>([])
  const [current, setCurrent] = useState<{ name: string; kind: BulkKind; step: string; percent: number } | null>(null)
  const [done, setDone] = useState(false)

  useEffect(() => {
    api.get<{ versions: Version[] }>('/php-versions')
      .then(r => setVersions((r.data.versions || []).filter(v => v.loaded)))
      .catch(() => { /* leave the list empty; the message covers it */ })
      .finally(() => setLoading(false))
  }, [])

  const total = selectedVersions.length + selected.length

  // Versions first so an extension can target a version installed in the same run.
  const preview = (): BulkRow[] => [
    ...selectedVersions.map(v => ({ kind: 'version' as const, version: v.version, key: v.version, name: `PHP ${v.version}`, resource: v.resource, state: 'pending' as const })),
    ...selected.map(s => ({ kind: 'extension' as const, version: s.version, key: s.key, name: s.name, state: 'pending' as const })),
  ]

  // Triggered by the button, never a mount effect, so it does not trip
  // react-hooks/set-state-in-effect. Each item installs in turn; a failure is
  // recorded on its row and does not stop the rest.
  async function bulkInstall() {
    if (running || total === 0) return
    setRunning(true); setDone(false)
    const list = preview()
    setRows(list)
    for (let i = 0; i < list.length; i++) {
      const s = list[i]
      setRows(prev => prev.map((x, j) => j === i ? { ...x, state: 'installing' } : x))
      setCurrent({ name: s.name, kind: s.kind, step: 'starting', percent: 2 })
      try {
        if (s.kind === 'version') {
          await installVersionJob({ version: s.version, resource: s.resource || 'remi' }, (step, percent) => setCurrent({ name: s.name, kind: 'version', step, percent }))
        } else {
          await installExtensionJob({ version: s.version, key: s.key, name: s.name }, (step, percent) => setCurrent({ name: s.name, kind: 'extension', step, percent }))
        }
        setRows(prev => prev.map((x, j) => j === i ? { ...x, state: 'done' } : x))
      } catch (e) {
        const code = (e as { peclError?: string })?.peclError
        const message = code
          ? t(`pecl.error.${code}`, { ns: 'PHPExtensionsPage', defaultValue: t('PHPExtensionsPage:errors.peclInstallFailed') })
          : apiError(e, t('PHPExtensionsPage:errors.peclInstallFailed'))
        setRows(prev => prev.map((x, j) => j === i ? { ...x, state: 'error', message } : x))
      }
    }
    setCurrent(null); setRunning(false); setDone(true)
    onClear() // the installed components now show as active in their steps
  }

  // While running the rows carry live state; before running, preview the selection.
  const shown = rows.length > 0 ? rows : preview()

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('summary.heading')}</h2>
      <p className="text-sm text-slate-500 dark:text-slate-500">{t('summary.subtitle')}</p>

      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-2">{t('summary.installedLabel')}</div>
        {loading ? <div className="text-sm text-slate-400 dark:text-slate-500">{t('summary.loading')}</div> : versions.length === 0 ? (
          <div className="text-sm text-slate-500 dark:text-slate-500">{t('summary.empty')}</div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {versions.map(v => (
              <span key={v.version} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-700/60 text-sm font-mono text-slate-800 dark:text-slate-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />PHP {v.version}
              </span>
            ))}
          </div>
        )}
      </div>

      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-2">{t('summary.toInstallLabel', { count: total })}</div>
        {total === 0 && !done ? (
          <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 p-4 text-sm text-slate-500 dark:text-slate-400">
            {t('summary.emptyHint')}
          </div>
        ) : (
          <div className="space-y-2">
            {shown.map(s => (
              <div key={s.kind + s.version + s.key} className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
                <div className="min-w-0">
                  <span className="text-[9px] uppercase tracking-wide mr-1.5 px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">{t(`summary.kind.${s.kind}`)}</span>
                  <span className="text-sm font-medium text-slate-800 dark:text-slate-200">{s.name}</span>
                  {s.kind === 'extension' && <span className="ml-1.5 font-mono text-[11px] text-slate-400 dark:text-slate-500">PHP {s.version}</span>}
                  {s.message && <div className="text-[11px] text-red-600 dark:text-red-400 mt-0.5">{s.message}</div>}
                </div>
                <BulkBadge state={s.state} />
              </div>
            ))}
          </div>
        )}
      </div>

      {current && (
        <div className="rounded-lg border border-brand-200 dark:border-brand-800 bg-brand-50 dark:bg-brand-950/40 px-4 py-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-sm font-medium text-brand-800 dark:text-brand-200">
              <span className="inline-block w-3.5 h-3.5 mr-2 align-[-2px] rounded-full border-2 border-brand-400 border-t-transparent animate-spin" />
              {t('summary.installingName', { name: current.name })}
            </span>
            <span className="text-xs tabular-nums text-brand-700 dark:text-brand-300">%{current.percent}</span>
          </div>
          <div className="text-xs text-brand-700 dark:text-brand-300 mb-2">
            {current.kind === 'extension'
              ? t(`pecl.step.${current.step}`, { ns: 'PHPExtensionsPage', defaultValue: current.step })
              : t(`summary.versionStep.${current.step}`, { defaultValue: current.step })}
          </div>
          <div className="h-2 rounded-full bg-brand-100 dark:bg-brand-900 overflow-hidden">
            <div className="h-full rounded-full bg-brand-500 transition-all duration-500" style={{ width: `${Math.min(100, current.percent)}%` }} />
          </div>
        </div>
      )}

      {done && <div className="rounded-xl border border-emerald-200 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-900/15 p-4 text-sm text-emerald-800 dark:text-emerald-200">{t('summary.bulkDone')}</div>}

      {total === 0 && !done && (
        <div className="rounded-xl border border-emerald-200 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-900/15 p-4 text-sm text-emerald-800 dark:text-emerald-200">
          {t('summary.done')}
        </div>
      )}

      {total > 0 && (
        <button onClick={bulkInstall} disabled={running}
          className="w-full sm:w-auto px-5 py-2.5 rounded-md bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium disabled:opacity-60">
          {running ? t('summary.installing') : t('summary.installButton', { count: total })}
        </button>
      )}
    </div>
  )
}

function BulkBadge({ state }: { state: BulkState }) {
  const { t } = useTranslation('PHPServerWizardPage')
  const map: Record<BulkState, { key: string; c: string }> = {
    pending: { key: 'summary.badge.pending', c: 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400' },
    installing: { key: 'summary.badge.installing', c: 'bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300' },
    done: { key: 'summary.badge.done', c: 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300' },
    error: { key: 'summary.badge.error', c: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300' },
  }
  const m = map[state]
  return <span className={`shrink-0 text-[11px] px-2 py-0.5 rounded-full font-medium ${m.c}`}>{t(m.key)}</span>
}
