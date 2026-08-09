import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

type Status = {
  installed: boolean
  exists: boolean
  app_root: string
  system_user: string
  directory: string
  php_version: string
  node_version: string
  composer_json: boolean
  git_present: boolean
  last_commit: string
  maintenance: boolean
  schedule_enabled: boolean
  worker_count: number
  workers_running: number
  last_deploy_status: string
  php_binary: string
}

type Worker = {
  id: number
  name: string
  connection: string
  queues: string
  processes: number
  tries: number
  timeout_sec: number
  sleep_sec: number
  max_jobs: number
  memory_mb: number
  enabled: boolean
  status: { installed: boolean; running: number; failed: number; restarts: number }
}

type WorkerList = { workers: Worker[]; max_processes: number }

// A definition the customer is editing. It carries no id while it is new.
type WorkerDraft = {
  id: number | null
  name: string
  connection: string
  queues: string
  processes: number
  tries: number
  timeout_sec: number
  sleep_sec: number
  max_jobs: number
  memory_mb: number
  enabled: boolean
}

const newWorker: WorkerDraft = {
  id: null, name: '', connection: 'database', queues: '',
  processes: 1, tries: 3, timeout_sec: 60, sleep_sec: 3,
  max_jobs: 1000, memory_mb: 128, enabled: true,
}

type NodeVersions = { versions: string[] }
type AppCandidates = { current: string; candidates: string[] }
type OperationStatus = { running: boolean; status: string; log: string }

type Tab = 'overview' | 'install' | 'commands' | 'env' | 'deploy' | 'workers'
type InstallMode = 'remote' | 'scaffold' | 'local'
type ActionResult = { data?: { output?: string; log?: string } }

const fieldClass = 'w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm text-slate-900 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

const tabs: Tab[] = ['overview', 'install', 'commands', 'env', 'deploy', 'workers']

export default function DomainLaravelPage() {
  const { t } = useTranslation('DomainLaravelPage')
  const { confirm } = useDialog()
  const { id } = useParams()
  const [active, setActive] = useState<Tab>('overview')
  const [status, setStatus] = useState<Status | null>(null)
  const [nodeVersions, setNodeVersions] = useState<string[]>([])
  const [candidates, setCandidates] = useState<AppCandidates | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [output, setOutput] = useState('')
  const [running, setRunning] = useState<string | null>(null)
  const [installMode, setInstallMode] = useState<InstallMode>('remote')
  const [repoURL, setRepoURL] = useState('')
  const [branch, setBranch] = useState('main')
  const [appRoot, setAppRoot] = useState('public_html')
  const [artisanCommand, setArtisanCommand] = useState('about')
  const [composerCommand, setComposerCommand] = useState('install')
  const [composerPackage, setComposerPackage] = useState('')
  const [npmCommand, setNpmCommand] = useState('install')
  const [npmScript, setNpmScript] = useState('build')
  const [nodeVersion, setNodeVersion] = useState('system')
  const [envContent, setEnvContent] = useState('')
  const [envLoaded, setEnvLoaded] = useState(false)
  const [workers, setWorkers] = useState<Worker[]>([])
  const [maxProcesses, setMaxProcesses] = useState(10)
  // Null means the list has never been read. A failed read must not draw the
  // empty state, which would tell the customer no worker is running when the
  // truth is that nobody knows.
  const [workersFailed, setWorkersFailed] = useState<boolean | null>(null)
  const [draft, setDraft] = useState<WorkerDraft | null>(null)
  const [workerLog, setWorkerLog] = useState<{ id: number; text: string } | null>(null)

  const canPoll = useMemo(() => status?.last_deploy_status === 'installing' || status?.last_deploy_status === 'running', [status])

  // Split so the mount effect never writes state synchronously: fetchStatus
  // settles only through promise callbacks, and load() adds the spinner plus the
  // error reset for the poll and the refreshes that follow an action.
  const fetchStatus = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<Status>(`/domains/${id}/laravel`),
      api.get<NodeVersions>(`/domains/${id}/laravel/node`),
      api.get<AppCandidates>(`/domains/${id}/laravel/app-candidates`),
    ]).then(([statusResponse, nodeResponse, candidateResponse]) => {
      setStatus(statusResponse.data)
      setNodeVersions(nodeResponse.data.versions || [])
      setCandidates(candidateResponse.data)
      setAppRoot(statusResponse.data.app_root || candidateResponse.data.current || 'public_html')
      setNodeVersion(statusResponse.data.node_version || nodeResponse.data.versions[0] || 'system')
    }).catch(error => setError(apiError(error)))
      .finally(() => setLoading(false))
    // The workers are read separately so a systemd query that goes wrong does
    // not take the whole page down with it.
    api.get<WorkerList>(`/domains/${id}/laravel/workers`)
      .then(response => {
        setWorkers(response.data.workers || [])
        setMaxProcesses(response.data.max_processes || 10)
        setWorkersFailed(false)
      })
      .catch(() => { setWorkers([]); setWorkersFailed(true) })
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchStatus()
  }, [fetchStatus])

  useEffect(() => { fetchStatus() }, [fetchStatus])

  useEffect(() => {
    if (!id || !canPoll) return
    const timer = window.setInterval(load, 5000)
    return () => window.clearInterval(timer)
  }, [id, canPoll, load])

  async function runAction(label: string, fn: () => Promise<unknown>, refresh = true) {
    setRunning(label); setError(null); setSuccess(null)
    try {
      const result = await fn()
      const data = (result as ActionResult).data
      if (data?.output) setOutput(data.output)
      if (data?.log) setOutput(data.log)
      setSuccess(t('messages.actionCompleted'))
      if (refresh) load()
    } catch (error) {
      setError(apiError(error, t('messages.actionFailed')))
    } finally {
      setRunning(null)
    }
  }

  async function startInstall() {
    await runAction('install', () => api.post(`/domains/${id}/laravel/install`, {
      mode: installMode,
      repo_url: repoURL,
      branch,
      app_root: appRoot,
    }))
  }

  async function pollInstall() {
    await runAction('install-status', () => api.get<OperationStatus>(`/domains/${id}/laravel/install/status`), false)
    load()
  }

  async function pollDeploy() {
    await runAction('deploy-status', () => api.get<OperationStatus>(`/domains/${id}/laravel/deploy/status`), false)
    load()
  }

  async function saveAppRoot(nextRoot: string) {
    setAppRoot(nextRoot)
    await runAction('app-root', () => api.put(`/domains/${id}/laravel/app-root`, { app_root: nextRoot }))
  }

  async function runArtisan() {
    await runAction('artisan', () => api.post(`/domains/${id}/laravel/artisan`, { command: artisanCommand }))
  }

  async function runComposer() {
    await runAction('composer', () => api.post(`/domains/${id}/laravel/composer`, { command: composerCommand, package: composerPackage }))
  }

  async function runNpm() {
    await runAction('npm', () => api.post(`/domains/${id}/laravel/npm`, { command: npmCommand, script: npmScript, node_version: nodeVersion }))
  }

  async function loadEnv() {
    await runAction('env-load', async () => {
      const response = await api.get<{ exists: boolean; content: string }>(`/domains/${id}/laravel/env`)
      setEnvContent(response.data.content || '')
      setEnvLoaded(true)
      return response
    }, false)
  }

  async function saveEnv() {
    await runAction('env-save', () => api.put(`/domains/${id}/laravel/env`, { content: envContent }))
  }

  async function setMaintenance(enabled: boolean) {
    await runAction('maintenance', () => api.post(`/domains/${id}/laravel/maintenance`, { enabled }))
  }

  async function startDeploy() {
    await runAction('deploy', () => api.post(`/domains/${id}/laravel/deploy`, { migrate: true, npm_build: true, node_version: nodeVersion }))
  }

  async function setSchedule(enabled: boolean) {
    await runAction('schedule', () => api.post(`/domains/${id}/laravel/schedule`, { enabled }))
  }

  // A refused write carries a stable reason code beside its English message.
  // The code is what maps to a sentence in the reader's own language.
  function workerFailure(caught: unknown): string {
    const reason = apiReason(caught)
    return reason
      ? t([`workers.reasons.${reason}`, 'workers.saveFailed'])
      : apiError(caught, t('workers.saveFailed'))
  }

  async function saveWorker(entry: WorkerDraft) {
    setRunning('worker-save'); setError(null); setSuccess(null)
    try {
      const body = {
        name: entry.name, connection: entry.connection, queues: entry.queues,
        processes: entry.processes, tries: entry.tries, timeout_sec: entry.timeout_sec,
        sleep_sec: entry.sleep_sec, max_jobs: entry.max_jobs, memory_mb: entry.memory_mb,
        enabled: entry.enabled,
      }
      if (entry.id === null) await api.post(`/domains/${id}/laravel/workers`, body)
      else await api.put(`/domains/${id}/laravel/workers/${entry.id}`, body)
      setDraft(null)
      setSuccess(t('messages.actionCompleted'))
      load()
    } catch (caught) {
      setError(workerFailure(caught))
    } finally { setRunning(null) }
  }

  async function toggleWorker(worker: Worker) {
    if (worker.enabled && !(await confirm({ message: t('workers.confirmStop', { name: worker.name }), dangerous: true }))) return
    await saveWorker({ ...worker, id: worker.id, enabled: !worker.enabled })
  }

  async function restartWorker(worker: Worker) {
    setRunning(`worker-restart-${worker.id}`); setError(null); setSuccess(null)
    try {
      await api.post(`/domains/${id}/laravel/workers/${worker.id}/restart`, {})
      setSuccess(t('workers.restarted', { name: worker.name }))
      load()
    } catch (caught) {
      setError(workerFailure(caught))
    } finally { setRunning(null) }
  }

  async function removeWorker(worker: Worker) {
    if (!(await confirm({ message: t('workers.confirmDelete', { name: worker.name }), dangerous: true }))) return
    setRunning(`worker-delete-${worker.id}`); setError(null); setSuccess(null)
    try {
      await api.delete(`/domains/${id}/laravel/workers/${worker.id}`)
      if (workerLog?.id === worker.id) setWorkerLog(null)
      load()
    } catch (caught) {
      setError(workerFailure(caught))
    } finally { setRunning(null) }
  }

  async function showWorkerLog(worker: Worker) {
    setRunning(`worker-log-${worker.id}`); setError(null)
    try {
      const response = await api.get<{ log: string }>(`/domains/${id}/laravel/workers/${worker.id}/log`)
      setWorkerLog({ id: worker.id, text: response.data.log })
    } catch (caught) {
      setError(workerFailure(caught))
    } finally { setRunning(null) }
  }

  if (loading && !status) return <div className="px-6 py-5 text-sm text-slate-400">{t('loading')}</div>

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' }, { label: t('breadcrumb.laravel') }]} />
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('subtitle')}</p>
        </div>
        <Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link>
      </div>

      {error && <div className="mb-3 px-3 py-2 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 rounded-lg border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20 text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      <div className="mb-4 flex flex-wrap gap-2">
        {tabs.map(tab => (
          <button key={tab} onClick={() => setActive(tab)} className={`px-3 py-1.5 rounded-lg text-sm font-medium ${active === tab ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900' : 'border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300'}`}>{t(`tabs.${tab}`)}</button>
        ))}
      </div>

      {active === 'overview' && status && (
        <Card title={t('overview.title')}>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
            <Metric label={t('overview.installed')} value={status.installed ? t('overview.yes') : t('overview.no')} />
            <Metric label={t('overview.appRoot')} value={status.app_root} />
            <Metric label={t('overview.documentPath')} value={status.directory} mono />
            <Metric label={t('overview.php')} value={`${status.php_version} (${status.php_binary})`} />
            <Metric label={t('overview.composerManifest')} value={status.composer_json ? t('overview.found') : t('overview.missing')} />
            <Metric label={t('overview.git')} value={status.git_present ? status.last_commit || t('overview.repositoryFound') : t('overview.notConnected')} />
            <Metric label={t('overview.maintenance')} value={status.maintenance ? t('overview.enabled') : t('overview.disabled')} />
            <Metric label={t('overview.schedule')} value={status.schedule_enabled ? t('overview.enabled') : t('overview.disabled')} />
            <Metric label={t('overview.queue')} value={t('overview.workerSummary', { total: status.worker_count, running: status.workers_running })} />
          </div>
        </Card>
      )}

      {active === 'install' && (
        <Card title={t('install.title')}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field label={t('install.mode')}><select value={installMode} onChange={e => setInstallMode(e.target.value as InstallMode)} className={fieldClass}><option value="remote">{t('install.modeRemote')}</option><option value="scaffold">{t('install.modeScaffold')}</option><option value="local">{t('install.modeLocal')}</option></select></Field>
            <Field label={t('install.appRoot')}><RootSelect value={appRoot} candidates={candidates?.candidates || []} onChange={setAppRoot} onSave={saveAppRoot} /></Field>
            {installMode === 'remote' && <Field label={t('install.repositoryUrl')}><input value={repoURL} onChange={e => setRepoURL(e.target.value)} className={fieldClass} placeholder={t('install.repositoryUrlPlaceholder')} /></Field>}
            {installMode === 'remote' && <Field label={t('install.branch')}><input value={branch} onChange={e => setBranch(e.target.value)} className={fieldClass} placeholder={t('install.branchPlaceholder')} /></Field>}
          </div>
          <div className="mt-4 flex flex-wrap gap-2"><Button disabled={!!running} onClick={startInstall}>{t('install.startInstall')}</Button><Button variant="secondary" disabled={!!running} onClick={pollInstall}>{t('install.checkInstallStatus')}</Button></div>
        </Card>
      )}

      {active === 'commands' && (
        <Card title={t('commands.title')}>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <CommandBox title="Artisan" value={artisanCommand} setValue={setArtisanCommand} options={['about','migrate','migrate:status','config:cache','cache:clear','queue:restart','storage:link']} onRun={runArtisan} />
            <CommandBox title="Composer" value={composerCommand} setValue={setComposerCommand} options={['install','update','dump-autoload','validate','show','diagnose','require','remove']} onRun={runComposer}><input value={composerPackage} onChange={e => setComposerPackage(e.target.value)} className={`${fieldClass} mt-2`} placeholder={t('commands.packagePlaceholder')} /></CommandBox>
            <CommandBox title="npm" value={npmCommand} setValue={setNpmCommand} options={['install','ci','run','prune','ls','outdated','audit','--version']} onRun={runNpm}><input value={npmScript} onChange={e => setNpmScript(e.target.value)} className={`${fieldClass} mt-2`} placeholder={t('commands.scriptPlaceholder')} /><NodeSelect value={nodeVersion} versions={nodeVersions} onChange={setNodeVersion} /></CommandBox>
          </div>
        </Card>
      )}

      {active === 'env' && (
        <Card title={t('env.title')}>
          {!envLoaded ? <Button disabled={!!running} onClick={loadEnv}>{t('env.load')}</Button> : <><textarea value={envContent} onChange={e => setEnvContent(e.target.value)} rows={16} className={`${fieldClass} font-mono text-xs`} /><div className="mt-3"><Button disabled={!!running} onClick={saveEnv}>{t('env.save')}</Button></div></>}
        </Card>
      )}

      {active === 'deploy' && (
        <Card title={t('deploy.title')}>
          <div className="flex flex-wrap gap-2 mb-4"><NodeSelect value={nodeVersion} versions={nodeVersions} onChange={setNodeVersion} /><Button disabled={!!running} onClick={startDeploy}>{t('deploy.deployWithMigrate')}</Button><Button variant="secondary" disabled={!!running} onClick={pollDeploy}>{t('deploy.checkDeployStatus')}</Button><Button variant="secondary" disabled={!!running} onClick={() => setMaintenance(!status?.maintenance)}>{status?.maintenance ? t('deploy.disableMaintenance') : t('deploy.enableMaintenance')}</Button></div>
        </Card>
      )}

      {active === 'workers' && status && (
        <>
          <Card title={t('workers.scheduleTitle')}>
            <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">{t('workers.scheduleHint')}</p>
            <Button disabled={!!running} onClick={() => setSchedule(!status.schedule_enabled)}>
              {status.schedule_enabled ? t('workers.disableSchedule') : t('workers.enableSchedule')}
            </Button>
          </Card>

          <Card title={t('workers.title')}>
            <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">{t('workers.hint')}</p>
            {workersFailed ? (
              <div className="py-6 text-center text-sm text-red-600 dark:text-red-400">{t('workers.loadFailed')}</div>
            ) : workers.length === 0 ? (
              <div className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('workers.empty')}</div>
            ) : (
              <div className="space-y-3">
                {workers.map(worker => (
                  <WorkerRow
                    key={worker.id}
                    worker={worker}
                    busy={!!running}
                    onEdit={() => setDraft({ ...worker, id: worker.id })}
                    onToggle={() => toggleWorker(worker)}
                    onRestart={() => restartWorker(worker)}
                    onDelete={() => removeWorker(worker)}
                    onLog={() => showWorkerLog(worker)}
                  />
                ))}
              </div>
            )}
            {!draft && (
              <div className="mt-4">
                <Button disabled={!!running} onClick={() => setDraft({ ...newWorker })}>{t('workers.add')}</Button>
              </div>
            )}
          </Card>

          {draft && (
            <Card title={draft.id === null ? t('workers.addTitle') : t('workers.editTitle', { name: draft.name })}>
              <WorkerForm
                draft={draft}
                maxProcesses={maxProcesses}
                onChange={setDraft}
              />
              <div className="mt-4 flex flex-wrap gap-2">
                <Button disabled={!!running} onClick={() => saveWorker(draft)}>{t('common.save')}</Button>
                <Button variant="secondary" disabled={!!running} onClick={() => setDraft(null)}>{t('workers.cancel')}</Button>
              </div>
            </Card>
          )}

          {workerLog && (
            <Card title={t('workers.logTitle')}>
              <pre className="bg-slate-950 text-slate-100 rounded-xl p-4 text-xs font-mono whitespace-pre-wrap break-words max-h-[360px] overflow-auto">
                {workerLog.text || t('workers.logEmpty')}
              </pre>
            </Card>
          )}
        </>
      )}

      {output && <pre className="mt-4 bg-slate-950 text-slate-100 rounded-2xl p-4 text-xs font-mono whitespace-pre-wrap break-words max-h-[420px] overflow-auto">{output}</pre>}
    </div>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4"><h2 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{title}</h2>{children}</section>
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="rounded-xl border border-slate-100 dark:border-slate-700 p-3"><div className="text-xs text-slate-500 dark:text-slate-400 mb-1">{label}</div><div className={`text-sm text-slate-900 dark:text-slate-100 ${mono ? 'font-mono break-all' : 'font-medium'}`}>{value || '—'}</div></div>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block text-sm"><span className="block mb-1 text-slate-600 dark:text-slate-400">{label}</span>{children}</label>
}

function Button({ children, onClick, disabled, variant = 'primary' }: { children: ReactNode; onClick: () => void; disabled?: boolean; variant?: 'primary' | 'secondary' }) {
  return <button onClick={onClick} disabled={disabled} className={`px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 ${variant === 'primary' ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900' : 'border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300'}`}>{children}</button>
}

function RootSelect({ value, candidates, onChange, onSave }: { value: string; candidates: string[]; onChange: (value: string) => void; onSave: (value: string) => void }) {
  const { t } = useTranslation('DomainLaravelPage')
  return <div className="flex gap-2"><input list="laravel-root-candidates" value={value} onChange={e => onChange(e.target.value)} className={fieldClass} /><datalist id="laravel-root-candidates">{candidates.map(candidate => <option key={candidate || 'public_html'} value={candidate || 'public_html'} />)}</datalist><Button variant="secondary" onClick={() => onSave(value)}>{t('common.save')}</Button></div>
}

function NodeSelect({ value, versions, onChange }: { value: string; versions: string[]; onChange: (value: string) => void }) {
  const list = versions.length ? versions : ['system']
  return <select value={value} onChange={e => onChange(e.target.value)} className={`${fieldClass} max-w-[180px]`}>{list.map(version => <option key={version} value={version}>{version}</option>)}</select>
}

function WorkerRow({ worker, busy, onEdit, onToggle, onRestart, onDelete, onLog }: {
  worker: Worker
  busy: boolean
  onEdit: () => void
  onToggle: () => void
  onRestart: () => void
  onDelete: () => void
  onLog: () => void
}) {
  const { t } = useTranslation('DomainLaravelPage')
  // A worker with even one failed instance is drawn as failing. The others
  // carrying the load is exactly what hides the process that is not.
  const failing = worker.status.failed > 0
  const short = worker.enabled && worker.status.running < worker.processes
  const stateClass = failing ? 'text-red-600 dark:text-red-400'
    : short ? 'text-amber-600 dark:text-amber-400'
      : worker.enabled ? 'text-emerald-600 dark:text-emerald-400'
        : 'text-slate-500 dark:text-slate-400'

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-slate-900 dark:text-slate-100">{worker.name}</span>
            <span className={`text-xs ${stateClass}`}>
              {failing ? t('workers.stateFailed', { failed: worker.status.failed })
                : worker.enabled ? t('workers.stateRunning', { running: worker.status.running, total: worker.processes })
                  : t('workers.stateStopped')}
            </span>
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {t('workers.summary', {
              connection: worker.connection,
              queues: worker.queues || t('workers.defaultQueue'),
              timeout: worker.timeout_sec,
              memory: worker.memory_mb,
            })}
          </div>
          {worker.status.restarts > 0 && (
            <div className="mt-1 text-xs text-slate-400">{t('workers.restartCount', { restarts: worker.status.restarts })}</div>
          )}
        </div>
        <div className="flex flex-wrap gap-3 text-xs whitespace-nowrap">
          <button onClick={onEdit} disabled={busy} className="text-brand-600 hover:underline disabled:opacity-50 dark:text-brand-400">{t('workers.edit')}</button>
          <button onClick={onToggle} disabled={busy} className="text-brand-600 hover:underline disabled:opacity-50 dark:text-brand-400">{worker.enabled ? t('workers.stop') : t('workers.start')}</button>
          <button onClick={onRestart} disabled={busy || !worker.enabled} className="text-brand-600 hover:underline disabled:opacity-50 dark:text-brand-400">{t('workers.restart')}</button>
          <button onClick={onLog} disabled={busy} className="text-brand-600 hover:underline disabled:opacity-50 dark:text-brand-400">{t('workers.log')}</button>
          <button onClick={onDelete} disabled={busy} className="text-red-600 hover:underline disabled:opacity-50 dark:text-red-400">{t('workers.delete')}</button>
        </div>
      </div>
    </div>
  )
}

function WorkerForm({ draft, maxProcesses, onChange }: {
  draft: WorkerDraft
  maxProcesses: number
  onChange: (draft: WorkerDraft) => void
}) {
  const { t } = useTranslation('DomainLaravelPage')
  const number = (key: keyof WorkerDraft, value: string) => onChange({ ...draft, [key]: parseInt(value, 10) || 0 })

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
      <Field label={t('workers.name')}>
        <input value={draft.name} onChange={e => onChange({ ...draft, name: e.target.value })} className={fieldClass} placeholder={t('workers.namePlaceholder')} />
      </Field>
      <Field label={t('workers.connection')}>
        <input value={draft.connection} onChange={e => onChange({ ...draft, connection: e.target.value })} className={fieldClass} />
      </Field>
      <Field label={t('workers.queues')}>
        <input value={draft.queues} onChange={e => onChange({ ...draft, queues: e.target.value })} className={fieldClass} placeholder={t('workers.queuesPlaceholder')} />
      </Field>
      <Field label={t('workers.processes', { max: maxProcesses })}>
        <input type="number" min={1} max={maxProcesses} value={draft.processes} onChange={e => number('processes', e.target.value)} className={fieldClass} />
      </Field>
      <Field label={t('workers.tries')}>
        <input type="number" min={1} max={10} value={draft.tries} onChange={e => number('tries', e.target.value)} className={fieldClass} />
      </Field>
      <Field label={t('workers.timeout')}>
        <input type="number" min={5} max={600} value={draft.timeout_sec} onChange={e => number('timeout_sec', e.target.value)} className={fieldClass} />
      </Field>
      <Field label={t('workers.sleep')}>
        <input type="number" min={0} max={60} value={draft.sleep_sec} onChange={e => number('sleep_sec', e.target.value)} className={fieldClass} />
      </Field>
      <Field label={t('workers.maxJobs')}>
        <input type="number" min={0} max={100000} value={draft.max_jobs} onChange={e => number('max_jobs', e.target.value)} className={fieldClass} />
      </Field>
      <Field label={t('workers.memory')}>
        <input type="number" min={64} max={1024} value={draft.memory_mb} onChange={e => number('memory_mb', e.target.value)} className={fieldClass} />
      </Field>
    </div>
  )
}

function CommandBox({ title, value, setValue, options, onRun, children }: { title: string; value: string; setValue: (value: string) => void; options: string[]; onRun: () => void; children?: ReactNode }) {
  const { t } = useTranslation('DomainLaravelPage')
  return <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4"><h3 className="text-sm font-semibold mb-2 text-slate-900 dark:text-slate-100">{title}</h3><select value={value} onChange={e => setValue(e.target.value)} className={fieldClass}>{options.map(option => <option key={option} value={option}>{option}</option>)}</select>{children}<div className="mt-3"><Button onClick={onRun}>{t('commands.run')}</Button></div></div>
}
