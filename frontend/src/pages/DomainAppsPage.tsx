import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import Modal from '@/components/Modal'

type App = {
  id: number
  domain_id: number
  subdomain_id: number
  name: string
  runtime: 'node' | 'python'
  runtime_version: string
  app_root: string
  start_command: string
  mount_path: string
  port: number
  enabled: boolean
  status: { active_state: string; sub_state: string; restarts: string; installed: boolean }
  resolved_command: string
  url: string
}

type Runtime = { kind: 'node' | 'python'; version: string; path: string; system: boolean }
type RuntimeList = { node: Runtime[]; python: Runtime[] }
type Domain = { id: number; domain_name: string; system_user: string }
type Sub = { id: number; subdomain: string; fqdn: string }

type Draft = {
  name: string
  runtime: 'node' | 'python'
  runtime_version: string
  app_root: string
  start_command: string
  mount_path: string
  subdomain_id: number
}

const EMPTY_DRAFT: Draft = {
  name: '',
  runtime: 'node',
  runtime_version: 'system',
  app_root: 'apps/api',
  start_command: 'node server.js',
  mount_path: '/api/',
  subdomain_id: 0,
}

// A unit that systemd reports as active is running; anything else is not, and
// the distinction is what the badge and the start button both read.
function isRunning(app: App) {
  return app.status.active_state === 'active'
}

const CARD_BUTTON_CLASS = 'rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs text-slate-700 transition hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'

// AppsHeader names the domain this list belongs to.
function AppsHeader({ domain, domainId }: { domain: Domain | null; domainId?: string }) {
  const { t } = useTranslation('DomainAppsPage')
  return (
    <>
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${domainId}` },
        { label: t('breadcrumb.current') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
        {domain && (
          <Link to={`/subscriptions/${domainId}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 font-medium">{domain.domain_name}</Link>
        )}
        {domain && ', '}
        {t('subtitle')}
      </p>
    </>
  )
}

// AppCard is one application: its state, its unit facts and its actions.
function AppCard({ app, busy, onAct, onLog, onEnv, onInstall, onEdit, onRemove }: {
  app: App
  busy: number | null
  onAct: (app: App, action: 'start' | 'stop' | 'restart') => void
  onLog: (app: App) => void
  onEnv: (app: App) => void
  onInstall: (app: App) => void
  onEdit: (app: App) => void
  onRemove: (app: App) => void
}) {
  const { t } = useTranslation('DomainAppsPage')
  const running = isRunning(app)
  const locked = busy === app.id
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/60">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate text-base font-semibold text-slate-900 dark:text-slate-100">{app.name}</span>
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
              running
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
            }`}>
              {running ? t('badges.running') : t('badges.stopped')}
            </span>
            <span className="rounded bg-violet-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-violet-700 dark:bg-violet-900/30 dark:text-violet-300">
              {app.runtime === 'node' ? 'Node.js' : 'Python'} {app.runtime_version}
            </span>
          </div>
          <div className="mt-1 font-mono text-xs text-slate-500 dark:text-slate-400">
            {app.mount_path} &rarr; 127.0.0.1:{app.port}
          </div>
        </div>
      </div>

      <dl className="mb-3 space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-2 font-mono text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400">
        <div className="flex gap-2"><dt className="shrink-0 text-slate-400">{t('card.directory')}</dt><dd className="truncate">~/{app.app_root}</dd></div>
        <div className="flex gap-2"><dt className="shrink-0 text-slate-400">{t('card.command')}</dt><dd className="truncate" title={app.resolved_command}>{app.start_command}</dd></div>
        <div className="flex gap-2"><dt className="shrink-0 text-slate-400">{t('card.state')}</dt><dd>{app.status.active_state || t('card.unknown')} / {app.status.sub_state || '-'}{app.status.restarts ? ' ' + t('card.restarts', { count: Number(app.status.restarts) }) : ''}</dd></div>
      </dl>

      <div className="flex flex-wrap gap-1.5">
        {running ? (
          <button onClick={() => onAct(app, 'stop')} disabled={locked} className={CARD_BUTTON_CLASS}>
            {t('actions.stop')}
          </button>
        ) : (
          <button onClick={() => onAct(app, 'start')} disabled={locked}
            className="rounded-lg bg-emerald-600 px-2.5 py-1.5 text-xs font-medium text-white transition hover:bg-emerald-700 disabled:opacity-50">
            {t('actions.start')}
          </button>
        )}
        <button onClick={() => onAct(app, 'restart')} disabled={locked} className={CARD_BUTTON_CLASS}>
          {t('actions.restart')}
        </button>
        <button onClick={() => onLog(app)} className={CARD_BUTTON_CLASS}>
          {t('actions.log')}
        </button>
        <button onClick={() => onEnv(app)} className={CARD_BUTTON_CLASS}>
          {t('actions.env')}
        </button>
        <button onClick={() => onInstall(app)} disabled={locked} className={CARD_BUTTON_CLASS}>
          {t('actions.installDeps')}
        </button>
        <button onClick={() => onEdit(app)} className={CARD_BUTTON_CLASS}>
          {t('actions.edit')}
        </button>
        <button onClick={() => onRemove(app)} disabled={locked}
          className="ml-auto rounded-lg px-2.5 py-1.5 text-xs text-red-600 transition hover:bg-red-50 disabled:opacity-50 dark:text-red-400 dark:hover:bg-red-900/30">
          {t('actions.delete')}
        </button>
      </div>
    </div>
  )
}

// AppsBody answers with the spinner, the empty state or the cards.
function AppsBody({ apps, loading, busy, onAct, onLog, onEnv, onInstall, onEdit, onRemove }: {
  apps: App[]
  loading: boolean
  busy: number | null
  onAct: (app: App, action: 'start' | 'stop' | 'restart') => void
  onLog: (app: App) => void
  onEnv: (app: App) => void
  onInstall: (app: App) => void
  onEdit: (app: App) => void
  onRemove: (app: App) => void
}) {
  const { t } = useTranslation('DomainAppsPage')
  if (loading) return <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
  if (apps.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white py-16 text-center dark:border-slate-800 dark:bg-slate-900/60">
        <div className="w-14 h-14 mx-auto rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-3">
          <svg className="w-7 h-7 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
          </svg>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400">{t('empty')}</p>
      </div>
    )
  }
  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
      {apps.map(app => (
        <AppCard key={app.id} app={app} busy={busy}
          onAct={onAct} onLog={onLog} onEnv={onEnv} onInstall={onInstall}
          onEdit={onEdit} onRemove={onRemove} />
      ))}
    </div>
  )
}

export default function DomainAppsPage() {
  const { t } = useTranslation('DomainAppsPage')
  const { confirm, notify } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [apps, setApps] = useState<App[]>([])
  const [runtimes, setRuntimes] = useState<RuntimeList>({ node: [], python: [] })
  const [subs, setSubs] = useState<Sub[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [editing, setEditing] = useState<App | null>(null)
  const [creating, setCreating] = useState(false)
  const [envOf, setEnvOf] = useState<App | null>(null)
  const [logOf, setLogOf] = useState<App | null>(null)

  // Split so the mount effect never writes state synchronously: fetchApps
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchApps = useCallback(() => {
    if (!id) return
    api.get<{ apps: App[] }>(`/domains/${id}/apps`)
      .then(r => setApps(r.data.apps || []))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchApps()
  }, [fetchApps])

  useEffect(() => {
    if (!id) return
    fetchApps()
    api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    api.get<RuntimeList>('/app-runtimes')
      .then(r => setRuntimes({ node: r.data.node || [], python: r.data.python || [] }))
      .catch(report('appRuntimes'))
    api.get<Sub[]>(`/domains/${id}/subdomain`).then(r => setSubs(r.data || [])).catch(report('subdomains'))
  }, [id, fetchApps, report])

  async function act(app: App, action: 'start' | 'stop' | 'restart') {
    setBusy(app.id)
    try {
      await api.post(`/domains/${id}/apps/${app.id}/action`, { action })
      fetchApps()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.actionFailed')), tone: 'error' })
    } finally {
      setBusy(null)
    }
  }

  async function remove(app: App) {
    if (!(await confirm({ message: t('confirm.delete', { name: app.name }), dangerous: true }))) return
    setBusy(app.id)
    try {
      await api.delete(`/domains/${id}/apps/${app.id}`)
      load()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.deleteFailed')), tone: 'error' })
    } finally {
      setBusy(null)
    }
  }

  async function install(app: App) {
    if (!(await confirm({ message: t('confirm.install', { name: app.name }) }))) return
    setBusy(app.id)
    try {
      const r = await api.post<{ ok: boolean; output: string }>(`/domains/${id}/apps/${app.id}/install`, {})
      await notify({
        message: r.data.output || t('install.noOutput'),
        tone: r.data.ok ? 'info' : 'error',
      })
    } catch (e) {
      await notify({ message: apiError(e, t('errors.installFailed')), tone: 'error' })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="w-full px-4 py-4 sm:px-6 sm:py-5">
      <AppsHeader domain={domain} domainId={id} />

      <div className="grid grid-cols-2 gap-2 mb-4 sm:flex sm:items-center">
        <button
          onClick={() => setCreating(true)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-md shadow-sm transition"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          {t('actions.add')}
        </button>
        <button onClick={load} className="px-3 py-2 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-sm rounded-md transition">{t('actions.refresh')}</button>
        <span className="col-span-2 text-sm text-slate-500 dark:text-slate-400 sm:col-span-1 sm:ml-auto">{t('count', { count: apps.length })}</span>
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      <AppsBody
        apps={apps} loading={loading} busy={busy}
        onAct={act} onLog={setLogOf} onEnv={setEnvOf} onInstall={install}
        onEdit={setEditing} onRemove={remove}
      />

      {(creating || editing) && (
        // Keyed so switching from one application to another REMOUNTS the form.
        // Seeding the draft from props in an effect would be a synchronous
        // setState on mount, which the panel bars; the key makes React do the
        // reset instead, and the initializer reads the row it is given.
        <AppModal
          key={editing ? `edit-${editing.id}` : 'create'}
          app={editing}
          runtimes={runtimes}
          subs={subs}
          domainId={Number(id)}
          onClose={() => { setCreating(false); setEditing(null) }}
          onSaved={load}
        />
      )}
      {envOf && <EnvModal app={envOf} domainId={Number(id)} onClose={() => setEnvOf(null)} />}
      {logOf && <LogModal app={logOf} domainId={Number(id)} onClose={() => setLogOf(null)} />}
    </div>
  )
}

function AppModal({ app, runtimes, subs, domainId, onClose, onSaved }: {
  app: App | null
  runtimes: RuntimeList
  subs: Sub[]
  domainId: number
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation('DomainAppsPage')
  const [draft, setDraft] = useState<Draft>(() => app
    ? {
      name: app.name,
      runtime: app.runtime,
      runtime_version: app.runtime_version || 'system',
      app_root: app.app_root,
      start_command: app.start_command,
      mount_path: app.mount_path,
      subdomain_id: app.subdomain_id,
    }
    : EMPTY_DRAFT)
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const available = draft.runtime === 'node' ? runtimes.node : runtimes.python

  async function submit(e: React.SubmitEvent) {
    e.preventDefault()
    setProcessing(true); setError(null)
    try {
      if (app) {
        await api.put(`/domains/${domainId}/apps/${app.id}`, draft)
      } else {
        await api.post(`/domains/${domainId}/apps`, draft)
      }
      onSaved()
      onClose()
    } catch (e) {
      setError(apiError(e, t('errors.saveFailed')))
    } finally {
      setProcessing(false)
    }
  }

  return (
    <Modal open title={app ? t('modal.editTitle') : t('modal.createTitle')} onClose={onClose} width="lg">
      <form onSubmit={submit} className="space-y-4">
        <Text label={t('modal.fields.name')} value={draft.name} onChange={v => setDraft({ ...draft, name: v })} required />

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{t('modal.fields.runtime')}</label>
            <select
              value={draft.runtime}
              onChange={e => setDraft({ ...draft, runtime: e.target.value as 'node' | 'python', runtime_version: 'system' })}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-800"
            >
              <option value="node">Node.js</option>
              <option value="python">Python</option>
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{t('modal.fields.version')}</label>
            <select
              value={draft.runtime_version}
              onChange={e => setDraft({ ...draft, runtime_version: e.target.value })}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-800"
            >
              {available.length === 0 && <option value="system">{t('modal.noRuntime')}</option>}
              {available.map(r => (
                <option key={r.version} value={r.version}>
                  {r.system ? t('modal.systemRuntime') : r.version}
                </option>
              ))}
            </select>
          </div>
        </div>

        <Text
          label={t('modal.fields.appRoot')}
          value={draft.app_root}
          onChange={v => setDraft({ ...draft, app_root: v })}
          hint={t('modal.hints.appRoot')}
          mono
          required
        />
        <Text
          label={t('modal.fields.startCommand')}
          value={draft.start_command}
          onChange={v => setDraft({ ...draft, start_command: v })}
          hint={t('modal.hints.startCommand')}
          mono
          required
        />
        <Text
          label={t('modal.fields.mount')}
          value={draft.mount_path}
          onChange={v => setDraft({ ...draft, mount_path: v })}
          hint={t('modal.hints.mount')}
          mono
          required
        />

        {draft.mount_path.trim() === '/' && (
          <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-800/50 dark:bg-amber-900/20 dark:text-amber-300">
            {t('modal.rootWarning')}
          </div>
        )}

        {!app && subs.length > 0 && (
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{t('modal.fields.scope')}</label>
            <select
              value={draft.subdomain_id}
              onChange={e => setDraft({ ...draft, subdomain_id: Number(e.target.value) })}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-800"
            >
              <option value={0}>{t('modal.scopeDomain')}</option>
              {subs.map(s => <option key={s.id} value={s.id}>{s.fqdn}</option>)}
            </select>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('modal.hints.scope')}</p>
          </div>
        )}

        {error && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">{error}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} disabled={processing} className="rounded-md border border-slate-200 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">{t('modal.cancel')}</button>
          <button type="submit" disabled={processing || !draft.name.trim()} className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-60 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
            {processing ? t('modal.saving') : t('modal.save')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function EnvModal({ app, domainId, onClose }: { app: App; domainId: number; onClose: () => void }) {
  const { t } = useTranslation('DomainAppsPage')
  const [rows, setRows] = useState<Array<{ name: string; value: string }>>([])
  const [reserved, setReserved] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.get<{ env: Record<string, string>; reserved: string[] }>(`/domains/${domainId}/apps/${app.id}/env`)
      .then(r => {
        setReserved(r.data.reserved || [])
        setRows(Object.entries(r.data.env || {}).map(([name, value]) => ({ name, value })))
      })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [app.id, domainId])

  async function save() {
    setProcessing(true); setError(null)
    const env: Record<string, string> = {}
    for (const row of rows) {
      const name = row.name.trim()
      if (name) env[name] = row.value
    }
    try {
      await api.put(`/domains/${domainId}/apps/${app.id}/env`, { env })
      onClose()
    } catch (e) {
      setError(apiError(e, t('errors.envSaveFailed')))
    } finally {
      setProcessing(false)
    }
  }

  return (
    <Modal open title={t('env.title', { name: app.name })} onClose={onClose} width="lg">
      <div className="space-y-3">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {t('env.hint', { port: app.port, reserved: reserved.join(', ') })}
        </p>

        {loading ? (
          <div className="py-8 text-center text-sm text-slate-400">{t('loading')}</div>
        ) : (
          <div className="space-y-2">
            {rows.map((row, index) => (
              <div key={index} className="flex gap-2">
                <input
                  value={row.name}
                  onChange={e => setRows(rows.map((r, i) => i === index ? { ...r, name: e.target.value } : r))}
                  placeholder={t('env.namePlaceholder')}
                  className="w-1/3 rounded-md border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500 dark:border-slate-600 dark:bg-slate-800"
                />
                <input
                  value={row.value}
                  onChange={e => setRows(rows.map((r, i) => i === index ? { ...r, value: e.target.value } : r))}
                  placeholder={t('env.valuePlaceholder')}
                  className="flex-1 rounded-md border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500 dark:border-slate-600 dark:bg-slate-800"
                />
                <button type="button" onClick={() => setRows(rows.filter((_, i) => i !== index))}
                  className="rounded-md px-2 text-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/30">
                  {t('env.removeRow')}
                </button>
              </div>
            ))}
            <button type="button" onClick={() => setRows([...rows, { name: '', value: '' }])}
              className="rounded-md border border-slate-200 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">
              {t('env.addRow')}
            </button>
          </div>
        )}

        {error && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">{error}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} disabled={processing} className="rounded-md border border-slate-200 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">{t('modal.cancel')}</button>
          <button type="button" onClick={save} disabled={processing || loading} className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-60 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
            {processing ? t('env.saving') : t('env.save')}
          </button>
        </div>
      </div>
    </Modal>
  )
}

function LogModal({ app, domainId, onClose }: { app: App; domainId: number; onClose: () => void }) {
  const { t } = useTranslation('DomainAppsPage')
  const [log, setLog] = useState('')
  const boxRef = useRef<HTMLPreElement>(null)

  // Poll while the modal is open so a restart's output appears without the
  // customer having to close and reopen the panel.
  useEffect(() => {
    let done = false
    const tick = () => {
      api.get<{ log: string }>(`/domains/${domainId}/apps/${app.id}/log`)
        .then(r => { if (!done) setLog(r.data.log || '') })
        .catch(() => { // Keep polling through transient network failures.
        })
    }
    const id = window.setInterval(tick, 3000)
    tick()
    return () => { done = true; window.clearInterval(id) }
  }, [app.id, domainId])

  useEffect(() => { boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight }) }, [log])

  return (
    <Modal open title={t('log.title', { name: app.name })} onClose={onClose} width="lg">
      <pre ref={boxRef} className="max-h-96 overflow-auto rounded-xl bg-slate-900 p-3 font-mono text-xs text-slate-100">{log || t('log.empty')}</pre>
    </Modal>
  )
}

function Text({ label, value, onChange, hint, mono, required }: {
  label: string
  value: string
  onChange: (value: string) => void
  hint?: string
  mono?: boolean
  required?: boolean
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{label}</label>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        required={required}
        className={`w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-800 ${mono ? 'font-mono' : ''}`}
      />
      {hint && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  )
}
