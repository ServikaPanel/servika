import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams, Link } from 'react-router'
import { api, apiError as apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import ConfirmDialog from '@/components/ConfirmDialog'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Domain = { id: number; domain_name: string; system_user: string; ipv4: string }
type Repo = {
  id: number; domain_id: number; repo_url: string; branch: string; target_dir: string;
  deploy_key_pub: string; webhook_secret: string; last_sync?: string; last_commit?: string; last_status: string; created_at: string
}
type GHConn = {
  missing?: boolean
  login?: string; full_name?: string; avatar_url?: string
  selected_repo?: string; selected_branch?: string
  webhook_id?: number; webhook_url?: string
}
type GHRepo = { full_name: string; name: string; description?: string; private: boolean; default_branch: string; updated_at: string }

export default function DomainGitPage() {
  const { t } = useTranslation('DomainGitPage')
  const { confirm, notify } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [repo, setRepo] = useState<Repo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [processing, setProcessing] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [cloneConfirmOpen, setCloneConfirmOpen] = useState(false)
  const [latestLog, setLatestLog] = useState<string | null>(null)

  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [targetDir, setTargetDir] = useState('public_html')

  // GitHub connector state.
  const [ghConn, setGhConn] = useState<GHConn>({ missing: true })
  const [ghToken, setGhToken] = useState('')
  const [ghRepos, setGhRepos] = useState<GHRepo[]>([])
  const [ghBranches, setGhBranches] = useState<string[]>([])
  const [ghSelectedRepo, setGhSelectedRepo] = useState('')
  const [ghSelectedBranch, setGhSelectedBranch] = useState('')
  const [ghAutoDeploy, setGhAutoDeploy] = useState(true)
  const [ghLoading, setGhLoading] = useState(false)

  // Declared before the loader that calls it: a function hoisted past its own
  // use site cannot pick up a later definition, so the earlier call would keep
  // an older closure over id and t.
  const ghLoadRepos = useCallback(async () => {
    try {
      const r = await api.get<GHRepo[]>(`/domains/${id}/github/repos`)
      setGhRepos(r.data || [])
    } catch (e) {
      setError(apiError(e, t('errors.loadReposFailed')))
    }
  }, [id, t])

  // Split so the mount effect never writes state synchronously: fetchRepo
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchRepo = useCallback(() => {
    if (!id) return
    api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    api.get<Repo | null>(`/domains/${id}/git`)
      .then(r => { setRepo(r.data); if (r.data) { setRepoUrl(r.data.repo_url); setBranch(r.data.branch); setTargetDir(r.data.target_dir) } })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
    api.get<GHConn>(`/domains/${id}/github`).then(r => {
      setGhConn(r.data)
      if (!r.data.missing) {
        if (r.data.selected_repo) setGhSelectedRepo(r.data.selected_repo)
        if (r.data.selected_branch) setGhSelectedBranch(r.data.selected_branch)
        ghLoadRepos()
      }
    }).catch(report('githubConnection'))
  }, [id, ghLoadRepos, report])

  const load = useCallback(() => {
    setLoading(true)
    fetchRepo()
  }, [fetchRepo])

  useEffect(() => { fetchRepo() }, [fetchRepo])

  async function ghConnect() {
    if (!ghToken.trim()) { setError(t('errors.patRequired')); return }
    setGhLoading(true); setError(null); setSuccess(null)
    try {
      const r = await api.post<GHConn>(`/domains/${id}/github/connect`, { token: ghToken.trim() })
      setGhConn(r.data); setGhToken('')
      setSuccess(t('messages.connected', { login: r.data.login }))
      ghLoadRepos()
    } catch (e) {
      setError(apiError(e, t('errors.connectFailed')))
    } finally { setGhLoading(false) }
  }

  async function ghLoadBranches(repoFull: string) {
    setGhSelectedRepo(repoFull)
    const rp = ghRepos.find(x => x.full_name === repoFull)
    if (rp) setGhSelectedBranch(rp.default_branch || 'main')
    try {
      const r = await api.get<string[]>(`/domains/${id}/github/branches?repo=${encodeURIComponent(repoFull)}`)
      setGhBranches(r.data || [])
    } catch {
      setGhBranches([])
    }
  }

  async function ghUse() {
    if (!ghSelectedRepo || !ghSelectedBranch) { setError(t('errors.selectRepoBranch')); return }
    setGhLoading(true); setError(null); setSuccess(null)
    try {
      const r = await api.post<{ ok: boolean; webhook_ok?: boolean; webhook_error?: string }>(
        `/domains/${id}/github/use`,
        { repo: ghSelectedRepo, branch: ghSelectedBranch, target_dir: targetDir, auto_deploy: ghAutoDeploy }
      )
      let msg = t('messages.repoConnected', { repo: ghSelectedRepo, branch: ghSelectedBranch })
      if (ghAutoDeploy) {
        if (r.data.webhook_ok) msg += t('messages.webhookEnabled')
        else if (r.data.webhook_error) msg += t('messages.webhookError', { error: r.data.webhook_error })
      }
      setSuccess(msg)
      load()
    } catch (e) {
      setError(apiError(e, t('errors.connectionFailed')))
    } finally { setGhLoading(false) }
  }

  async function ghDisconnect() {
    if (!(await confirm({ message: t('confirm.ghDisconnect'), dangerous: true }))) return
    try {
      await api.delete(`/domains/${id}/github`)
      setGhConn({ missing: true })
      setGhRepos([])
      setGhBranches([])
      setGhSelectedRepo('')
      setGhSelectedBranch('')
      setSuccess(t('messages.ghDisconnected'))
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function connectRepo() {
    setProcessing(true); setError(null); setSuccess(null)
    try {
      await api.post(`/domains/${id}/git`, { repo_url: repoUrl, branch, target_dir: targetDir })
      setSuccess(t('messages.connectHint'))
      load()
    } catch (e) {
      setError(apiError(e, t('errors.connectionFailed')))
    } finally {
      setProcessing(false)
    }
  }

  async function cloneRepo() {
    setProcessing(true); setError(null); setSuccess(null); setLatestLog(null); setCloneConfirmOpen(false)
    try {
      const { data } = await api.post(`/domains/${id}/git/clone`)
      setSuccess(t('messages.cloned', { commit: data.commit.slice(0, 7) }))
      setLatestLog(data.log)
      load()
    } catch (e) {
      setError(apiError(e, t('messages.cloneFailed')))
    } finally {
      setProcessing(false)
    }
  }

  async function pull() {
    setProcessing(true); setError(null); setSuccess(null); setLatestLog(null)
    try {
      const { data } = await api.post(`/domains/${id}/git/pull`)
      setSuccess(t('messages.pullDone', { commit: data.commit.slice(0, 7) }))
      setLatestLog(data.log)
      load()
    } catch (e) {
      setError(apiError(e, t('messages.pullFailed')))
    } finally {
      setProcessing(false)
    }
  }

  async function remove() {
    try {
      await api.delete(`/domains/${id}/git`)
      setRepo(null); setDeleteConfirmOpen(false); setSuccess(t('messages.repoRemoved'))
    } catch (e) {
      await notify({ message: apiError(e), tone: 'error' })
    }
  }

  function copy(s: string) {
    navigator.clipboard.writeText(s)
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.git') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
        {t('intro.pre')}{t('intro.text')}
      </p>}

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> : (
        <>
          {/* GitHub connector */}
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <svg viewBox="0 0 24 24" fill="currentColor" className="w-6 h-6 text-slate-900 dark:text-slate-100">
                  <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
                </svg>
                <div>
                  <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('github.title')}</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-500">{t('github.subtitle')}</p>
                </div>
              </div>
              {ghConn.login && (
                <button onClick={ghDisconnect} className="text-xs px-2 py-1 border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 rounded">{t('github.removeConnection')}</button>
              )}
            </div>

            {ghConn.missing || !ghConn.login ? (
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('github.patLabel')}</label>
                <div className="flex gap-2">
                  <input type="password" value={ghToken}
                    onChange={e => setGhToken(e.target.value)}
                    placeholder="ghp_..." autoComplete="off"
                    className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
                  <button onClick={ghConnect} disabled={ghLoading || !ghToken.trim()}
                    className="px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-sm font-medium rounded">
                    {ghLoading ? t('github.connecting') : t('github.connect')}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-500 mt-2">
                  <a href="https://github.com/settings/tokens?type=beta" target="_blank" rel="noreferrer"
                    className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300">{t('github.patHintLink')}</a>{t('github.patHintPre')}<code className="bg-slate-100 dark:bg-slate-800 px-1 rounded">{t('github.patHintScope1')}</code>{t('github.patHintMid')}
                  <code className="bg-slate-100 dark:bg-slate-800 px-1 rounded ml-1">{t('github.patHintScope2')}</code>{t('github.patHintPost')}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-900 rounded-md">
                  {ghConn.avatar_url && <img src={ghConn.avatar_url} alt="" className="w-10 h-10 rounded-full"/>}
                  <div className="flex-1">
                    <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{ghConn.full_name || ghConn.login}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-500 font-mono">@{ghConn.login}</div>
                  </div>
                  {ghConn.webhook_url && (
                    <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300">{t('github.autoDeployBadge')}</span>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('github.repo')}</label>
                    <select value={ghSelectedRepo} onChange={e => ghLoadBranches(e.target.value)}
                      className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono bg-white dark:bg-slate-800">
                      <option value="">{t('github.selectPlaceholder')}</option>
                      {ghRepos.map(r => (
                        <option key={r.full_name} value={r.full_name}>
                          {r.private && <Icon d={ICON.lock} className="inline h-3.5 w-3.5 mr-1" />}{r.full_name}
                        </option>
                      ))}
                    </select>
                    <span className="text-[10px] text-slate-500 dark:text-slate-500 mt-0.5 block">{t('github.reposFound', { count: ghRepos.length })}</span>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('github.branch')}</label>
                    <select value={ghSelectedBranch} onChange={e => setGhSelectedBranch(e.target.value)}
                      disabled={!ghSelectedRepo}
                      className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono bg-white dark:bg-slate-800 disabled:bg-slate-50 dark:bg-slate-900">
                      {!ghSelectedBranch && <option value="">{t('github.selectPlaceholder')}</option>}
                      {ghBranches.map(b => <option key={b} value={b}>{b}</option>)}
                      {ghSelectedBranch && !ghBranches.includes(ghSelectedBranch) && <option value={ghSelectedBranch}>{ghSelectedBranch}</option>}
                    </select>
                  </div>
                </div>

                <div className="flex items-center justify-between flex-wrap gap-2">
                  <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input type="checkbox" checked={ghAutoDeploy} onChange={e => setGhAutoDeploy(e.target.checked)} className="cursor-pointer"/>
                    {t('github.autoDeployLabel')}
                  </label>
                  <button onClick={ghUse} disabled={ghLoading || !ghSelectedRepo || !ghSelectedBranch}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-emerald-300 text-white text-sm font-medium rounded">
                    {ghLoading ? t('github.connecting') : t('github.useRepo')}
                  </button>
                </div>

                {ghConn.webhook_url && (
                  <div className="text-[11px] text-slate-500 dark:text-slate-500 font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded p-2 truncate" title={ghConn.webhook_url}>
                    {t('github.webhookLabel', { url: ghConn.webhook_url })}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Repository connection and updates */}
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5">
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{repo ? t('repoCard.settingsTitle') : t('repoCard.connectTitle')}</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('repoCard.gitUrl')}</label>
                <input type="text" value={repoUrl} onChange={e => setRepoUrl(e.target.value)}
                  placeholder={t('repoCard.gitUrlPlaceholder')}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
                <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">{t('repoCard.gitUrlHint')}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('repoCard.branch')}</label>
                  <input type="text" value={branch} onChange={e => setBranch(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('repoCard.targetDir')}</label>
                  <input type="text" value={targetDir} onChange={e => setTargetDir(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono" />
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={connectRepo} disabled={processing || !repoUrl} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
                  {repo ? t('repoCard.update') : t('repoCard.connect')}
                </button>
                {repo && (
                  <button onClick={() => setCloneConfirmOpen(true)} disabled={processing} className="px-4 py-2 bg-amber-100 dark:bg-amber-900/30 hover:bg-amber-200 text-amber-800 dark:text-amber-200 text-sm font-medium rounded-md">
                    {processing ? '...' : t('repoCard.clone')}
                  </button>
                )}
                {repo && (
                  <button onClick={pull} disabled={processing} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-emerald-300 text-white text-sm font-medium rounded-md">
                    {processing ? '...' : t('repoCard.pull')}
                  </button>
                )}
                {repo && (
                  <button onClick={() => setDeleteConfirmOpen(true)} className="ml-auto px-4 py-2 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 text-sm rounded-md">
                    {t('repoCard.removeConnection')}
                  </button>
                )}
              </div>
            </div>
          </div>

          {repo && (
            <>
              {/* Deploy key */}
              <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('deployKey.title')}</h3>
                  <button onClick={() => copy(repo.deploy_key_pub)} className="text-xs px-2 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-brand-100 dark:bg-brand-900/30 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 rounded">{t('deployKey.copy')}</button>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-500 mb-2">{t('deployKey.hint')}</p>
                <textarea readOnly value={repo.deploy_key_pub} rows={3}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-md text-xs font-mono break-all" />
              </div>

              {/* Webhook */}
              <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('webhook.title')}</h3>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-500 mb-3">{t('webhook.hintPre')}<code className="font-mono">application/json</code>{t('webhook.hintPost')}</p>
                <div className="space-y-2">
                  <Row e={t('webhook.payloadUrl')} d={`http://${domain?.ipv4 || ''}:8443/api/v1/git-webhook/${repo.webhook_secret}`} onCopy={copy} />
                  <Row e={t('webhook.secret')} d={repo.webhook_secret} onCopy={copy} />
                  <Row e={t('webhook.contentType')} d={t('webhook.contentTypeValue')} />
                  <Row e={t('webhook.events')} d={t('webhook.eventsValue')} />
                </div>
              </div>

              {/* Status */}
              <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
                <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('status.title')}</h3>
                <div className="grid grid-cols-3 gap-3 text-sm">
                  <Stat e={t('status.latestSync')} d={repo.last_sync || t('status.noneYet')} />
                  <Stat e={t('status.latestCommit')} d={repo.last_commit ? repo.last_commit.slice(0, 8) : '—'} mono />
                  <Stat e={t('status.statusLabel')}
                    d={repo.last_status === 'successful' ? t('status.successful') : (repo.last_status === 'error' || repo.last_status.startsWith('error') ? t('status.error') : repo.last_status)}
                    color={repo.last_status === 'successful' ? 'emerald' : (repo.last_status.startsWith('error') ? 'red' : 'slate')}
                  />
                </div>
                {latestLog && (
                  <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-700">
                    <div className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-1">{t('status.latestLog')}</div>
                    <pre className="text-xs bg-slate-900 text-slate-100 p-3 rounded-md overflow-auto max-h-60 font-mono whitespace-pre-wrap">{latestLog}</pre>
                  </div>
                )}
              </div>
            </>
          )}
        </>
      )}

      <ConfirmDialog
        open={cloneConfirmOpen}
        title={t('cloneDialog.title')}
        message={t('cloneDialog.message', { dir: targetDir, branch })}
        dangerous
        confirmText={t('cloneDialog.confirm')}
        onConfirm={cloneRepo}
        onCancel={() => setCloneConfirmOpen(false)}
      />

      <ConfirmDialog
        open={deleteConfirmOpen}
        title={t('deleteDialog.title')}
        message={t('deleteDialog.message')}
        dangerous
        confirmText={t('deleteDialog.confirm')}
        onConfirm={remove}
        onCancel={() => setDeleteConfirmOpen(false)}
      />
    </div>
  )
}

function Row({ e, d, onCopy }: { e: string; d: string; onCopy?: (s: string) => void }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 w-28">{e}</span>
      <code className="flex-1 text-xs bg-slate-50 dark:bg-slate-900 px-2 py-1 rounded font-mono break-all">{d}</code>
      {onCopy && <button onClick={() => onCopy(d)} className="text-xs px-2 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-brand-100 dark:bg-brand-900/30 rounded">⧉</button>}
    </div>
  )
}

function Stat({ e, d, mono, color }: { e: string; d: string; mono?: boolean; color?: string }) {
  const c: Record<string, string> = {
    emerald: 'text-emerald-700 dark:text-emerald-300',
    red: 'text-red-700 dark:text-red-300',
    slate: 'text-slate-700 dark:text-slate-300',
  }
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500">{e}</div>
      <div className={`mt-0.5 ${mono ? 'font-mono text-xs' : 'text-sm font-medium'} ${c[color || ''] || 'text-slate-800 dark:text-slate-200'}`}>{d}</div>
    </div>
  )
}