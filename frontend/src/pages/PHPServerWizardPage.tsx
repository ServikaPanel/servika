// PHP & Server Setup Wizard — gathers the scattered PHP version / extension /
// loader / web-server screens into one step-by-step surface (EasyApache style).
// Each step renders an existing management screen embedded, so there is one code
// path and the same backend endpoints; only the chrome is the wizard's.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import PHPVersionsPage from './PHPVersionsPage'
import PHPExtensionsPage from './PHPExtensionsPage'

const STEPS = ['versions', 'extensions', 'webserver', 'summary'] as const
type Step = (typeof STEPS)[number]

export default function PHPServerWizardPage() {
  const { t } = useTranslation('PHPServerWizardPage')
  const [active, setActive] = useState<Step>('versions')
  const activeIdx = STEPS.indexOf(active)

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
            {active === 'versions' && <PHPVersionsPage embedded />}
            {active === 'extensions' && <PHPExtensionsPage embedded />}
            {active === 'webserver' && <WebServerStep />}
            {active === 'summary' && <SummaryStep />}
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

// SummaryStep lists the installed PHP versions and a quick confirmation.
function SummaryStep() {
  const { t } = useTranslation('PHPServerWizardPage')
  const [versions, setVersions] = useState<Version[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    api.get<{ versions: Version[] }>('/php-versions')
      .then(r => setVersions((r.data.versions || []).filter(v => v.loaded)))
      .catch(() => { /* leave the list empty; the message covers it */ })
      .finally(() => setLoading(false))
  }, [])
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

      <div className="rounded-xl border border-emerald-200 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-900/15 p-4 text-sm text-emerald-800 dark:text-emerald-200">
        {t('summary.done')}
      </div>
    </div>
  )
}
