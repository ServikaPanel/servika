import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Package = {
  name: string; version?: string; description?: string;
  installed: boolean; protected: boolean
}

type Group = { key: string; icon: string; packages: string[] }

type Tab = 'search' | 'installed'

const ICONS = {
  wrench:   'M11.42 15.17 17.25 21A2.652 2.652 0 0 0 21 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 1 1-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 0 0 4.486-6.336l-3.276 3.277a3.004 3.004 0 0 1-2.25-2.25l3.276-3.276a4.5 4.5 0 0 0-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26',
  code:     'M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5',
  bolt:     'm3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z',
  cube:     'm21 7.5-9-5.25L3 7.5m18 0-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9',
  beaker:   'M9.75 3.104v5.714a2.25 2.25 0 0 1-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 0 1 4.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0 1 12 15a9.065 9.065 0 0 0-6.23-.693L5 14.5m14.8.8 1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0 1 12 21c-2.773 0-5.491-.235-8.135-.687-1.719-.293-2.3-2.379-1.067-3.61L5 14.5',
  cog:      'M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
  server:   'M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3m3 3a3 3 0 1 0 0 6h13.5a3 3 0 1 0 0-6m-16.5-3a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3m-19.5 0a4.5 4.5 0 0 1 .9-2.7L5.737 5.1a3.375 3.375 0 0 1 2.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 0 1 .9 2.7m0 0a3 3 0 0 1-3 3m0 3h.008v.008h-.008v-.008Zm0-6h.008v.008h-.008v-.008Zm-3 6h.008v.008h-.008v-.008Zm0-6h.008v.008h-.008v-.008Z',
  terminal: 'm6.75 7.5 3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25H5.25A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z',
  photo:    'm2.25 15.75 5.159-5.159a2.25 2.25 0 0 1 3.182 0l5.159 5.159m-1.5-1.5 1.409-1.409a2.25 2.25 0 0 1 3.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H3.75A1.5 1.5 0 0 0 2.25 6v12a1.5 1.5 0 0 0 1.5 1.5Zm10.5-11.25h.008v.008h-.008V8.25Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z',
  database: 'M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125',
  shield:   'M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z',
  search:   'm21 21-4.34-4.34M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z',
  chevron:  'M19 9l-7 7-7-7',
}

function IconSvg({ d, className = '' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6}
      aria-hidden="true" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d={d} />
    </svg>
  )
}

const PRESET_GROUPS: Group[] = [
  { key: 'devtools', icon: ICONS.wrench,
    packages: ['gcc', 'gcc-c++', 'make', 'autoconf', 'automake', 'libtool', 'kernel-devel'] },
  { key: 'python', icon: ICONS.code,
    packages: ['python3', 'python3-pip', 'python3-devel', 'python3-virtualenv'] },
  { key: 'nodejs', icon: ICONS.bolt,
    packages: ['nodejs', 'npm'] },
  { key: 'go', icon: ICONS.cube,
    packages: ['golang'] },
  { key: 'java', icon: ICONS.beaker,
    packages: ['java-21-openjdk', 'java-21-openjdk-devel', 'maven'] },
  { key: 'rust', icon: ICONS.cog,
    packages: ['rust', 'cargo'] },
  { key: 'container', icon: ICONS.server,
    packages: ['podman', 'buildah', 'skopeo'] },
  { key: 'systools', icon: ICONS.terminal,
    packages: ['htop', 'ncdu', 'jq', 'tmux', 'vim-enhanced', 'git', 'rsync', 'mtr', 'iftop', 'iotop'] },
  { key: 'imaging', icon: ICONS.photo,
    packages: ['ImageMagick', 'libwebp-tools', 'optipng', 'jpegoptim'] },
  { key: 'dbclients', icon: ICONS.database,
    packages: ['postgresql', 'redis'] },
  { key: 'security', icon: ICONS.shield,
    packages: ['gnupg2', 'openssl', 'fail2ban'] },
]

export default function PackagesPage() {
  const { t } = useTranslation('PackagesPage')
  const { confirm } = useDialog()
  const [tab, setTab] = useState<Tab>('search')
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Package[]>([])
  const [searched, setSearched] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [processing, setProcessing] = useState<string | null>(null)
  const [outputModal, setOutputModal] = useState<{ title: string; output: string } | null>(null)
  const [open, setOpen] = useState<Set<string>>(new Set())
  const [groupStatus, setGroupStatus] = useState<Record<string, boolean>>({})

  async function loadGroupStatus(g: Group) {
    try {
      const r = await api.get<Record<string, boolean>>('/packages/status', {
        params: { names: g.packages.join(',') },
      })
      setGroupStatus(prev => ({ ...prev, ...r.data }))
    } catch {
      // Silently ignore failures so the group expand state remains usable.
    }
  }

  function toggleGroup(g: Group) {
    setOpen(prev => {
      const next = new Set(prev)
      if (next.has(g.key)) {
        next.delete(g.key)
      } else {
        next.add(g.key)
        loadGroupStatus(g)
      }
      return next
    })
  }

  async function togglePackage(pkg: string, currentlyInstalled: boolean) {
    const action = currentlyInstalled ? 'remove' : 'install'
    const msg = currentlyInstalled
      ? t('confirm.remove', { pkg })
      : t('confirm.install', { pkg })
    if (!(await confirm({ message: msg, dangerous: currentlyInstalled }))) return

    setProcessing(pkg); setError(null); setSuccess(null)
    try {
      const r = await api.post(`/packages/${action}`, { package: pkg })
      setSuccess(currentlyInstalled ? t('toast.removed', { pkg }) : t('toast.installed', { pkg }))
      setGroupStatus(prev => ({ ...prev, [pkg]: !currentlyInstalled }))
      setOutputModal({
        title: currentlyInstalled ? t('output.removeTitle', { pkg }) : t('output.installTitle', { pkg }),
        output: r.data.output || '',
      })
      setTimeout(() => setSuccess(null), 3500)
    } catch (e) {
      setError(apiError(e, currentlyInstalled ? t('errors.toggleRemoveFailed') : t('errors.toggleInstallFailed')))
    } finally {
      setProcessing(null)
    }
  }

  async function installPackage(pkg: string) {
    if (!(await confirm({ message: t('confirm.install', { pkg }) }))) return
    setProcessing(pkg); setError(null); setSuccess(null)
    try {
      const r = await api.post('/packages/install', { package: pkg })
      setSuccess(t('toast.installed', { pkg }))
      setOutputModal({ title: t('output.installTitle', { pkg }), output: r.data.output || '' })
      setTimeout(() => setSuccess(null), 4000)
      if (tab === 'search') search()
    } catch (e) { setError(apiError(e, t('errors.installFailed'))) }
    finally { setProcessing(null) }
  }
  async function removePackage(pkg: string) {
    if (!(await confirm({ message: t('confirm.remove', { pkg }), dangerous: true }))) return
    setProcessing(pkg); setError(null); setSuccess(null)
    try {
      const r = await api.post('/packages/remove', { package: pkg })
      setSuccess(t('toast.removed', { pkg }))
      setOutputModal({ title: t('output.removeTitle', { pkg }), output: r.data.output || '' })
      setTimeout(() => setSuccess(null), 4000)
      search()
    } catch (e) { setError(apiError(e, t('errors.removeFailed'))) }
    finally { setProcessing(null) }
  }

  async function search() {
    if (!query.trim()) return
    setLoading(true); setError(null); setSearched(true)
    try {
      const ep = tab === 'search' ? '/packages' : '/packages/installed'
      const r = await api.get<{ content: Package[]; total: number }>(ep, { params: { q: query } })
      setResults(r.data.content || [])
    } catch (e) {
      setError(apiError(e, t('errors.searchFailed')))
    } finally {
      setLoading(false)
    }
  }

  const installedTotal = useMemo(
    () => PRESET_GROUPS.reduce((n, g) => n + g.packages.filter(p => groupStatus[p]).length, 0),
    [groupStatus],
  )

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumbHome'), href: '/' },
        { label: t('breadcrumbTools'), href: '/tools-settings' },
        { label: t('title') },
      ]} />

      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {t('subtitle')}
          </p>
        </div>
        <span className="shrink-0 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400">
          {t('installedCount', { count: installedTotal })}
        </span>
      </div>

      {error && <div className="mb-3 flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-900/15 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-xs text-emerald-700 dark:border-emerald-800/50 dark:bg-emerald-900/15 dark:text-emerald-300">{success}</div>}

      {/* Group accordion */}
      <section className="mb-5 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900/60">
        <div className="mb-3 flex items-center gap-2">
          <IconSvg d={ICONS.cube} className="h-4 w-4 text-slate-400" />
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{t('quickInstallGroups')}</h2>
        </div>
        <div className="space-y-2">
          {PRESET_GROUPS.map(group => {
            const isOpen = open.has(group.key)
            const installedCount = group.packages.filter(p => groupStatus[p]).length
            return (
              <div key={group.key} className="overflow-hidden rounded-xl border border-slate-100 dark:border-slate-800">
                <button onClick={() => toggleGroup(group)}
                  className="flex w-full items-center justify-between px-3 py-2.5 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <div className="flex min-w-0 flex-1 items-center gap-2.5">
                    <IconSvg d={group.icon} className="h-4 w-4 shrink-0 text-slate-400 dark:text-slate-500" />
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t(`groups.${group.key}.name`)}</div>
                      <div className="truncate text-[11px] text-slate-400 dark:text-slate-500">{t(`groups.${group.key}.description`)}</div>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    {isOpen && (
                      <span className="text-[11px] text-slate-400 dark:text-slate-500">
                        <span className="font-semibold text-emerald-600 dark:text-emerald-400">{installedCount}</span>
                        <span> / {group.packages.length}</span>
                      </span>
                    )}
                    <IconSvg d={ICONS.chevron} className={`h-4 w-4 text-slate-300 transition-transform dark:text-slate-600 ${isOpen ? 'rotate-180' : ''}`} />
                  </div>
                </button>
                {isOpen && (
                  <div className="space-y-1 border-t border-slate-100 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950/40">
                    {group.packages.map(p => {
                      const isInstalled = !!groupStatus[p]
                      const pending = processing === p
                      return (
                        <div key={p} className="flex items-center justify-between gap-3 rounded-lg px-2 py-1.5 transition-colors hover:bg-white dark:hover:bg-slate-800/50">
                          <div className="min-w-0 flex-1">
                            <code className="text-sm font-mono text-slate-900 dark:text-slate-100">{p}</code>
                            {isInstalled && <span className="ml-2 rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">{t('badges.installed')}</span>}
                          </div>
                          <button onClick={() => togglePackage(p, isInstalled)}
                            disabled={pending}
                            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
                              isInstalled ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'
                            } ${pending ? 'cursor-wait opacity-50' : ''}`}
                            title={pending ? t('actions.processing') : (isInstalled ? t('actions.remove') : t('actions.install'))}>
                            <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow transition dark:bg-slate-800 ${isInstalled ? 'translate-x-5' : 'translate-x-1'}`} />
                          </button>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Search */}
      <section className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900/60">
        <div className="mb-3 flex items-center gap-0.5 rounded-xl border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-800 dark:bg-slate-800/60">
          <button onClick={() => { setTab('search'); setResults([]); setSearched(false) }}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${tab === 'search' ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
            <IconSvg d={ICONS.search} className="mr-1.5 inline h-3.5 w-3.5" />
            {t('tabs.search')}
          </button>
          <button onClick={() => { setTab('installed'); setResults([]); setSearched(false) }}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${tab === 'installed' ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
            <IconSvg d={ICONS.server} className="mr-1.5 inline h-3.5 w-3.5" />
            {t('tabs.installed')}
          </button>
        </div>

        <div className="mb-4 flex flex-col gap-2 sm:flex-row">
          <input type="text" value={query} onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && search()}
            placeholder={tab === 'search' ? t('searchPlaceholder') : t('installedPlaceholder')}
            className="flex-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-mono placeholder:text-slate-400 focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-500/30 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-100" />
          <button onClick={search} disabled={loading || !query.trim()}
            className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-60 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100 sm:w-auto">
            {loading ? t('actions.searching') : t('actions.search')}
          </button>
        </div>

        {searched && !loading && results.length === 0 && (
          <div className="py-8 text-center text-sm text-slate-400 dark:text-slate-500">{t('noResults')}</div>
        )}

        {results.length > 0 && (
          <div className="space-y-1.5">
            <div className="mb-2 text-xs text-slate-400 dark:text-slate-500">{t('resultsCount', { count: results.length })}</div>
            {results.map(p => (
              <div key={p.name}
                className={`flex flex-col gap-3 rounded-xl px-3 py-2 sm:flex-row sm:items-center ${
                  p.installed ? 'border border-emerald-200 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-900/20' : 'border border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-950/40'}`}>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">{p.name}</span>
                    {p.version && <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">{p.version}</span>}
                    {p.installed && <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">{t('badges.installed')}</span>}
                    {p.protected && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">{t('badges.protected')}</span>}
                  </div>
                  {p.description && <div className="truncate text-xs text-slate-500 dark:text-slate-400">{p.description}</div>}
                </div>
                {p.installed ? (
                  <button onClick={() => removePackage(p.name)}
                    disabled={p.protected || processing === p.name}
                    className="w-full rounded-lg px-3 py-1.5 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-40 dark:text-red-400 dark:hover:bg-red-900/20 sm:w-auto">
                    {processing === p.name ? t('actions.removing') : t('actions.remove')}
                  </button>
                ) : (
                  <button onClick={() => installPackage(p.name)}
                    disabled={processing === p.name}
                    className="w-full rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-60 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100 sm:w-auto">
                    {processing === p.name ? t('actions.installing') : t('actions.install')}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {outputModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={() => setOutputModal(null)}>
          <div className="flex max-h-[80vh] w-full max-w-4xl flex-col rounded-2xl bg-white shadow-xl dark:bg-slate-800" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-700">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{outputModal.title}</h3>
              <button onClick={() => setOutputModal(null)} className="text-slate-400 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-300"><Icon d={ICON.close} className="h-4 w-4" /></button>
            </div>
            <pre className="flex-1 overflow-auto bg-slate-900 p-3 font-mono text-xs text-slate-100 whitespace-pre-wrap">{outputModal.output}</pre>
            <div className="border-t border-slate-200 px-4 py-2 text-right dark:border-slate-700">
              <button onClick={() => setOutputModal(null)}
                className="rounded-lg bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">{t('actions.close')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
