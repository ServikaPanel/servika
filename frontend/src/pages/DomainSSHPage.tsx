import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'

type Status = {
  domain_name: string
  username: string
  active: boolean
  shell: string
  ssh_host: string
  ssh_port: number
  has_key: boolean
}

function Banners({ error, success }: { error: string | null; success: string | null }) {
  return (
    <>
      {error && <div className="my-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="my-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}
    </>
  )
}

function PageHeader({ domainName, active }: { domainName: string; active: boolean }) {
  const { t } = useTranslation('DomainSSHPage')
  return (
    <div className="flex items-start justify-between gap-4 mb-1">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          <span className="font-mono">{domainName}</span> {t('subtitle')}
        </p>
      </div>
      <span className={`shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${
        active ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-300'
      }`}>
        <span className={`w-2 h-2 rounded-full ${active ? 'bg-emerald-500' : 'bg-slate-400'}`} />
        {active ? t('badge.on') : t('badge.off')}
      </span>
    </div>
  )
}

function ShellCard({ status, busy, onToggle }: { status: Status; busy: boolean; onToggle: (active: boolean) => void }) {
  const { t } = useTranslation('DomainSSHPage')
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4 shadow-sm">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('shell.title')}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            {t('shell.enabledPrefix')} <code className="font-mono">/bin/bash</code> · {t('shell.disabledPrefix')} <code className="font-mono">/usr/sbin/nologin</code>.
            {' '}{t('shell.currentPrefix')} <code className="font-mono">{status.shell || '—'}</code>
          </p>
        </div>
        {status.active ? (
          <button onClick={() => onToggle(false)} disabled={busy}
            className="shrink-0 px-4 py-2 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 text-sm font-medium rounded-lg">
            {t('shell.disable')}
          </button>
        ) : (
          <button onClick={() => onToggle(true)} disabled={busy}
            className="shrink-0 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-lg">
            {t('shell.enable')}
          </button>
        )}
      </div>
    </div>
  )
}

function ConnectionCard({ status }: { status: Status }) {
  const { t } = useTranslation('DomainSSHPage')
  const sshCommand = `ssh ${status.username}@${status.ssh_host} -p ${status.ssh_port}`
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('connection.title')}</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
        <Info label={t('connection.user')} value={status.username} />
        <Info label={t('connection.host')} value={status.ssh_host} />
        <Info label={t('connection.port')} value={String(status.ssh_port)} />
      </div>
      <div className="mt-3">
        <label className="text-xs font-medium text-slate-600 dark:text-slate-400">{t('connection.commandLabel')}</label>
        <div className="mt-1 flex items-center gap-2">
          <code className="flex-1 px-3 py-2 bg-slate-900 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto">{sshCommand}</code>
          <button onClick={() => navigator.clipboard?.writeText(sshCommand)} className="shrink-0 text-xs px-2.5 py-2 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700">{t('connection.copy')}</button>
        </div>
      </div>
      <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">{t('connection.passwordPrefix')} <strong>{t('connection.passwordBold')}</strong>{t('connection.passwordSuffix')}</p>
    </div>
  )
}

function KeyCard({ hasKey, value, onValue, busy, onSave }: {
  hasKey: boolean; value: string; onValue: (value: string) => void; busy: boolean; onSave: () => void
}) {
  const { t } = useTranslation('DomainSSHPage')
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('key.title')}</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
        {t('key.descPrefix')} {hasKey
          ? <span className="text-emerald-600 dark:text-emerald-400">{t('key.configured')}</span>
          : <span className="text-slate-500">{t('key.notConfigured')}</span>}
      </p>
      <textarea
        value={value}
        onChange={e => onValue(e.target.value)}
        rows={4}
        spellCheck={false}
        placeholder="ssh-ed25519 AAAA... user@host"
        className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-xs font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
      />
      <div className="mt-3 flex items-center justify-between">
        <p className="text-xs text-slate-400">{t('key.removeHint')}</p>
        <button onClick={onSave} disabled={busy}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-lg">
          {t('key.save')}
        </button>
      </div>
    </div>
  )
}

export default function DomainSSHPage() {
  const { t } = useTranslation('DomainSSHPage')
  const { id } = useParams()
  const [status, setStatus] = useState<Status | null>(null)
  const [loading, setLoading] = useState(true)
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [key, setKey] = useState('')

  // Split in two on purpose. fetchStatus touches state only from the promise
  // callbacks, so the mount effect can call it without forcing a second render
  // pass; loading already starts true there. Raising the spinner belongs to the
  // event path, so reload() wraps it for the handlers that refetch on change.
  const fetchStatus = useCallback(() => {
    if (!id) return
    api.get<Status>(`/domains/${id}/ssh`)
      .then(r => setStatus(r.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  function reload() {
    setLoading(true)
    setError(null)
    fetchStatus()
  }

  useEffect(() => { fetchStatus() }, [fetchStatus])

  async function toggle(active: boolean) {
    setIsProcessing(true); setError(null); setSuccess(null)
    try {
      await api.put(`/domains/${id}/ssh`, { active: active })
      setSuccess(active ? t('toast.accessActive') : t('toast.accessDisabled'))
      setTimeout(() => setSuccess(null), 4000)
      reload()
    } catch (e) {
      setError(apiError(e, t('toast.operationFailed')))
    } finally { setIsProcessing(false) }
  }

  async function saveKey() {
    setIsProcessing(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.put(`/domains/${id}/ssh/key`, { key })
      setSuccess(data.has_key ? t('toast.keySaved') : t('toast.keysCleared'))
      setTimeout(() => setSuccess(null), 4000)
      setKey('')
      reload()
    } catch (e) {
      setError(apiError(e, t('toast.keySaveFailed')))
    } finally { setIsProcessing(false) }
  }

  if (loading) return <div className="px-6 py-5 text-slate-400">{t('loading')}</div>
  if (!status) return <div className="px-6 py-5"><div className="text-sm text-red-600">{error || t('notFound')}</div></div>

  return (
    <div className="px-6 py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: status.domain_name, href: `/subscriptions/${id}` },
          { label: t('breadcrumb.sshAccess') },
        ]} />

        <PageHeader domainName={status.domain_name} active={status.active} />

        <Banners error={error} success={success} />

        <ShellCard status={status} busy={isProcessing} onToggle={toggle} />

        <ConnectionCard status={status} />

        <KeyCard hasKey={status.has_key} value={key} onValue={setKey} busy={isProcessing} onSave={saveKey} />

        <div className="mt-4">
          <Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link>
        </div>
      </div>
    </div>
  )
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-3 py-2 bg-slate-50 dark:bg-slate-900/40 rounded-lg border border-slate-200 dark:border-slate-700">
      <div className="text-[10px] uppercase tracking-wider text-slate-400">{label}</div>
      <div className="font-mono text-slate-800 dark:text-slate-200 truncate">{value}</div>
    </div>
  )
}
