import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useCopyOrOffer } from '@/lib/useCopyOrOffer'
import { getCookie, setCookie, deleteCookie } from '@/lib/cookies'
import Breadcrumb from '@/components/Breadcrumb'

type Domain = { id: number; domain_name: string }
type Mailbox = {
  id: number; local_part: string; email: string; status: string
  quota_bytes: number; used_bytes: number; usage_checked_at?: string | null
}
type Connection = {
  hostname?: string; imap_port?: number; submission_port?: number
  security?: string; username: string; reason?: string
  // Every name the domain's mail certificate carries. The announced hostname is
  // one of them, so showing the list is what makes it checkable rather than
  // taken on trust.
  covered?: string[]
}
type Autoresponder = {
  mailbox_id: number; email: string; enabled: boolean
  subject: string; body: string; interval_days: number
}
type Forwarding = { enabled: boolean; destinations: string[]; keep_copy: boolean }
type ImportFormats = {
  maildir_tar_supported: boolean; mbox_supported: boolean
  pst_supported: boolean; max_bytes: number
}

type Candidate = { host: string; port: number; security: string; source: string; responds: boolean }
type MigrationJob = {
  id: number; status: string; remote_host: string; remote_user: string
  folders_total: number; folders_done: number
  messages_total: number; messages_done: number; bytes_done: number
  error_code: string; started_at: string; finished_at: string
}

type Tab = 'general' | 'autoresponder' | 'forwarding' | 'migration' | 'transfer'

/**
 * Maps a server reason code onto a translation key.
 *
 * The table is explicit rather than built by camel-casing whatever arrives: a
 * code the server adds later would otherwise become a key that does not exist
 * and render as its own name in every language. Anything unlisted falls back to
 * one sentence that says what happened without pretending to know why.
 */
const MIGRATION_REASONS: Record<string, string> = {
  unreachable: 'reasons.unreachable',
  tls_failed: 'reasons.tlsFailed',
  blocked_host: 'reasons.blockedHost',
  bad_security: 'reasons.badSecurity',
  auth_failed: 'reasons.authFailed',
  basic_auth_disabled: 'reasons.basicAuthDisabled',
  app_password_required: 'reasons.appPasswordRequired',
  timed_out: 'reasons.timedOut',
  interrupted: 'reasons.interrupted',
  migration_already_running: 'reasons.alreadyRunning',
  too_many_migrations: 'reasons.tooManyMigrations',
}

// The draft outlives a page reload so a long discovery is not repeated, and it
// carries the server only. The password is never written anywhere: it goes from
// the field into one request and is gone when the tab closes.
const DRAFT_MAX_AGE_SEC = 24 * 60 * 60
type MigrationDraft = { host: string; port: number; security: string; username: string }
const EMPTY_DRAFT: MigrationDraft = { host: '', port: 143, security: 'starttls', username: '' }

/**
 * Reads the saved server half of a wizard draft.
 *
 * A cookie written by an older shape of this page no longer parses. Dropping it
 * is better than leaving one that fails on every load, and there is nothing to
 * lose: it holds a hostname, never a credential.
 */
function readDraft(name: string): MigrationDraft {
  const stored = getCookie(name)
  if (!stored) return EMPTY_DRAFT
  try {
    const draft = JSON.parse(stored) as Partial<MigrationDraft>
    return {
      host: draft.host || '', port: draft.port || 143,
      security: draft.security || 'starttls', username: draft.username || '',
    }
  } catch {
    deleteCookie(name)
    return EMPTY_DRAFT
  }
}

// A quota of zero is not a limit of zero; it is the absence of one, which the
// userdb query turns into a NULL quota_rule. Drawing it as a full bar would tell
// a customer their unlimited mailbox is out of space.
function quotaPercent(used: number, quota: number): number | null {
  if (quota <= 0) return null
  return Math.min(100, Math.round((used / quota) * 100))
}

function formatBytes(value: number): string {
  if (value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const power = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)))
  const scaled = value / Math.pow(1024, power)
  return `${power === 0 ? scaled : scaled.toFixed(1)} ${units[power]}`
}

export default function DomainMailboxPage() {
  const { t } = useTranslation('DomainMailboxPage')
  const { notify, confirm } = useDialog()
  const copy = useCopyOrOffer()
  const { id, mid } = useParams()

  const [domain, setDomain] = useState<Domain | null>(null)
  const [mailbox, setMailbox] = useState<Mailbox | null>(null)
  const [connection, setConnection] = useState<Connection | null>(null)
  const [formats, setFormats] = useState<ImportFormats | null>(null)
  const [tab, setTab] = useState<Tab>('general')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [isRecalculating, setIsRecalculating] = useState(false)
  const [autoresponder, setAutoresponder] = useState<Autoresponder | null>(null)
  const [isSavingAutoresponder, setIsSavingAutoresponder] = useState(false)
  const [forwarding, setForwarding] = useState<Forwarding>({ enabled: false, destinations: [], keep_copy: true })
  const [destinationText, setDestinationText] = useState('')
  const [isSavingForwarding, setIsSavingForwarding] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [isImporting, setIsImporting] = useState(false)

  const draftCookie = `servika.mailmigration.${mid}`
  // Read once at first render rather than in an effect: this is initial state
  // taken from a store that is already there, not a synchronisation with one.
  const [draft] = useState<MigrationDraft>(() => readDraft(draftCookie))

  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [providerNotice, setProviderNotice] = useState('')
  const [isDiscovering, setIsDiscovering] = useState(false)
  const [remoteHost, setRemoteHost] = useState(draft.host)
  const [remotePort, setRemotePort] = useState(draft.port)
  const [remoteSecurity, setRemoteSecurity] = useState(draft.security)
  const [remoteUser, setRemoteUser] = useState(draft.username)
  // Deliberately not persisted anywhere, not even in memory across a reload.
  const [remotePassword, setRemotePassword] = useState('')
  const [isVerifying, setIsVerifying] = useState(false)
  const [verified, setVerified] = useState(false)
  const [verifyReason, setVerifyReason] = useState('')
  const [isStarting, setIsStarting] = useState(false)
  const [job, setJob] = useState<MigrationJob | null>(null)

  // A code the panel does not know is still reported, just without a claim
  // about the cause it cannot make.
  const reasonText = useCallback((code: string) => (
    code ? t(MIGRATION_REASONS[code] || 'reasons.unknown', { code }) : ''
  ), [t])

  // Split so the mount effect never writes state synchronously: fetchMailbox
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchMailbox = useCallback(() => {
    if (!id || !mid) return
    Promise.all([
      api.get<Domain>(`/domains/${id}`),
      api.get<Mailbox[]>(`/domains/${id}/mail`),
      api.get<Connection>(`/domains/${id}/mail/${mid}/connection`),
      api.get<Autoresponder>(`/domains/${id}/mail/${mid}/autoresponder`),
      api.get<Forwarding>(`/domains/${id}/mail/${mid}/forwarding`),
      api.get<ImportFormats>(`/domains/${id}/mail/${mid}/import`),
    ])
      .then(([domainResponse, mailboxesResponse, connectionResponse, autoresponderResponse, forwardingResponse, formatsResponse]) => {
        setDomain(domainResponse.data)
        const found = (mailboxesResponse.data || []).find(box => String(box.id) === mid) || null
        setMailbox(found)
        setConnection(connectionResponse.data)
        setAutoresponder(autoresponderResponse.data)
        setForwarding(forwardingResponse.data)
        setDestinationText((forwardingResponse.data.destinations || []).join('\n'))
        setFormats(formatsResponse.data)
        setError(null)
      })
      .catch(cause => setError(apiError(cause, t('errors.loadFailed'))))
      .finally(() => setLoading(false))
  }, [id, mid, t])

  const load = useCallback(() => { setLoading(true); fetchMailbox() }, [fetchMailbox])

  useEffect(() => { fetchMailbox() }, [fetchMailbox])

  // The server is the source of truth for what is running: a copy started in
  // another tab, or before this page was closed, has to appear here too.
  const fetchJob = useCallback(() => {
    if (!id || !mid) return
    api.get<{ job: MigrationJob | null }>(`/domains/${id}/mail/${mid}/migration`)
      .then(response => setJob(response.data.job))
      .catch(() => setJob(null))
  }, [id, mid])

  useEffect(() => { fetchJob() }, [fetchJob])

  // While a copy runs the page asks again, so progress moves without a reload.
  useEffect(() => {
    if (job?.status !== 'running' && job?.status !== 'queued') return
    const timer = setInterval(fetchJob, 5000)
    return () => clearInterval(timer)
  }, [job?.status, fetchJob])

  function rememberDraft(next: Partial<MigrationDraft>) {
    const draft: MigrationDraft = {
      host: remoteHost, port: remotePort, security: remoteSecurity, username: remoteUser, ...next,
    }
    setCookie(draftCookie, JSON.stringify(draft), DRAFT_MAX_AGE_SEC)
  }

  async function discover() {
    if (!mailbox) return
    setIsDiscovering(true)
    setCandidates([])
    try {
      const response = await api.post<{ candidates: Candidate[]; provider_notice: string }>(
        `/domains/${id}/mail/migration/discover`, { email: remoteUser || mailbox.email })
      setCandidates(response.data.candidates || [])
      setProviderNotice(response.data.provider_notice || '')
      const answering = (response.data.candidates || []).find(entry => entry.responds)
      if (answering) chooseCandidate(answering)
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.discoverFailed')), tone: 'error' })
    } finally {
      setIsDiscovering(false)
    }
  }

  function chooseCandidate(candidate: Candidate) {
    setRemoteHost(candidate.host)
    setRemotePort(candidate.port)
    setRemoteSecurity(candidate.security)
    // A different server means the previous approval no longer says anything.
    setVerified(false)
    setVerifyReason('')
    rememberDraft({ host: candidate.host, port: candidate.port, security: candidate.security })
  }

  async function verify() {
    setIsVerifying(true)
    setVerifyReason('')
    try {
      const response = await api.post<{ ok: boolean; reason: string }>(
        `/domains/${id}/mail/migration/verify`,
        { host: remoteHost, port: remotePort, security: remoteSecurity, username: remoteUser, password: remotePassword })
      setVerified(response.data.ok)
      setVerifyReason(response.data.ok ? '' : response.data.reason)
      if (response.data.ok) rememberDraft({ username: remoteUser })
    } catch (cause) {
      setVerified(false)
      await notify({ message: apiError(cause, t('errors.verifyFailed')), tone: 'error' })
    } finally {
      setIsVerifying(false)
    }
  }

  async function startMigration() {
    setIsStarting(true)
    try {
      await api.post(`/domains/${id}/mail/${mid}/migration`,
        { host: remoteHost, port: remotePort, security: remoteSecurity, username: remoteUser, password: remotePassword })
      // The password has done its one job. Clearing it now means a page left
      // open for the hours a copy takes is not also holding it.
      setRemotePassword('')
      fetchJob()
    } catch (cause) {
      // A refusal carries a reason code, and the panel ships twelve languages
      // while the API is English. Preferring the code keeps the refusal readable
      // in the language the screen is drawn in; apiError is the fallback for
      // anything that arrives without one.
      const refused = (cause as { response?: { data?: { reason?: string } } })?.response?.data?.reason
      await notify({
        message: refused ? reasonText(refused) : apiError(cause, t('errors.startFailed')),
        tone: 'error',
      })
    } finally {
      setIsStarting(false)
    }
  }

  async function cancelMigration() {
    if (!(await confirm({ message: t('migration.confirmCancel'), dangerous: true }))) return
    try {
      await api.delete(`/domains/${id}/mail/${mid}/migration`)
      fetchJob()
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.cancelFailed')), tone: 'error' })
    }
  }

  async function recalculateQuota() {
    setIsRecalculating(true)
    try {
      const response = await api.post<{ used_bytes: number; quota_bytes: number; dovecot_recount: boolean }>(
        `/domains/${id}/mail/${mid}/quota-recalc`)
      setMailbox(current => current ? { ...current, used_bytes: response.data.used_bytes, quota_bytes: response.data.quota_bytes } : current)
      // The panel's own number is right either way; saying which half did not
      // land is the difference between a customer who waits and one who knows.
      setSuccess(response.data.dovecot_recount ? t('quota.recalculated') : t('quota.recalculatedPartly'))
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.recalculateFailed')), tone: 'error' })
    } finally {
      setIsRecalculating(false)
    }
  }

  async function saveAutoresponder(event: React.SubmitEvent) {
    event.preventDefault()
    if (!autoresponder) return
    setIsSavingAutoresponder(true)
    try {
      await api.put(`/domains/${id}/mail/${mid}/autoresponder`, autoresponder)
      setSuccess(t('autoresponder.saved'))
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.saveAutoresponderFailed')), tone: 'error' })
    } finally {
      setIsSavingAutoresponder(false)
    }
  }

  async function saveForwarding(event: React.SubmitEvent) {
    event.preventDefault()
    const destinations = destinationText.split(/[\n,]/).map(value => value.trim()).filter(Boolean)
    if (forwarding.enabled && destinations.length === 0) {
      await notify({ message: t('forwarding.needsADestination'), tone: 'error' })
      return
    }
    if (forwarding.enabled && !forwarding.keep_copy) {
      // Mail that arrives is forwarded and then dropped, so nothing is left here
      // to go back to. That is worth one question before it is switched on.
      if (!(await confirm({ message: t('forwarding.confirmNoCopy'), dangerous: true }))) return
    }
    setIsSavingForwarding(true)
    try {
      const response = await api.put<Forwarding & { applied: boolean; reason?: string }>(
        `/domains/${id}/mail/${mid}/forwarding`,
        { enabled: forwarding.enabled, destinations, keep_copy: forwarding.keep_copy })
      setForwarding({ enabled: response.data.enabled, destinations: response.data.destinations || [], keep_copy: response.data.keep_copy })
      setDestinationText((response.data.destinations || []).join('\n'))
      setSuccess(response.data.applied ? t('forwarding.saved') : t('forwarding.savedNotApplied'))
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.saveForwardingFailed')), tone: 'error' })
    } finally {
      setIsSavingForwarding(false)
    }
  }

  async function runImport(event: React.SubmitEvent) {
    event.preventDefault()
    if (!uploadFile) return
    setIsImporting(true)
    try {
      const body = new FormData()
      body.append('file', uploadFile)
      const response = await api.post<{ messages: number; folders: number }>(
        `/domains/${id}/mail/${mid}/import`, body)
      setSuccess(t('transfer.imported', { messages: response.data.messages, folders: response.data.folders }))
      setUploadFile(null)
      load()
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.importFailed')), tone: 'error' })
    } finally {
      setIsImporting(false)
    }
  }

  // A download carries the session cookie, so it goes through the same origin
  // with credentials rather than through a link the browser sends anonymously.
  async function exportMailbox() {
    try {
      const response = await fetch(`/api/v1/domains/${id}/mail/${mid}/export`, { credentials: 'include' })
      if (!response.ok) throw new Error(String(response.status))
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `${mailbox?.local_part || 'mailbox'}-maildir.tar.gz`
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.exportFailed')), tone: 'error' })
    }
  }

  const percent = mailbox ? quotaPercent(mailbox.used_bytes, mailbox.quota_bytes) : null
  const tabs: { key: Tab; label: string }[] = [
    { key: 'general', label: t('tabs.general') },
    { key: 'autoresponder', label: t('tabs.autoresponder') },
    { key: 'forwarding', label: t('tabs.forwarding') },
    { key: 'migration', label: t('tabs.migration') },
    { key: 'transfer', label: t('tabs.transfer') },
  ]
  const jobRunning = job?.status === 'running' || job?.status === 'queued'

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.email'), href: `/subscriptions/${id}/mail` },
        { label: mailbox?.email || '...' },
      ]} />

      <h1 className="mt-4 text-xl font-semibold text-slate-900 dark:text-slate-100">{mailbox?.email || t('title')}</h1>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('subtitle')}</p>

      {error && <div className="mt-4 rounded-lg bg-red-50 dark:bg-red-900/20 px-4 py-3 text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mt-4 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 px-4 py-3 text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? (
        <p className="mt-6 text-sm text-slate-500 dark:text-slate-400">{t('loading')}</p>
      ) : !mailbox ? (
        <p className="mt-6 text-sm text-slate-500 dark:text-slate-400">{t('notFound')}</p>
      ) : (
        <>
          <div className="mt-5 inline-flex gap-1 rounded-xl bg-slate-100 p-1 dark:bg-slate-800">
            {tabs.map(entry => (
              <button key={entry.key} type="button" onClick={() => { setTab(entry.key); setSuccess(null) }}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${tab === entry.key ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
                {entry.label}
              </button>
            ))}
          </div>

          {tab === 'general' && (
            <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('quota.title')}</h3>
                <p className="text-sm text-slate-700 dark:text-slate-300">
                  {percent === null
                    ? t('quota.unlimited', { used: formatBytes(mailbox.used_bytes) })
                    : t('quota.used', { used: formatBytes(mailbox.used_bytes), quota: formatBytes(mailbox.quota_bytes) })}
                </p>
                {percent !== null && (
                  <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-700">
                    <div className={`h-full ${percent >= 90 ? 'bg-red-500' : 'bg-brand-500'}`} style={{ width: `${percent}%` }} />
                  </div>
                )}
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {mailbox.usage_checked_at ? t('quota.checkedAt', { when: new Date(mailbox.usage_checked_at).toLocaleString() }) : t('quota.neverChecked')}
                </p>
                <button type="button" onClick={recalculateQuota} disabled={isRecalculating}
                  className="mt-3 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                  {isRecalculating ? t('quota.recalculating') : t('quota.recalculate')}
                </button>
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('connection.title')}</h3>
                <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('connection.description')}</p>
                {connection?.reason === 'no_mail_hostname' ? (
                  <>
                    <p className="text-sm text-amber-700 dark:text-amber-300">{t('connection.hostnamePending')}</p>
                    {/* Which names the certificate does carry separates the two ways of
                        being pending: names present but none usable is a DNS problem,
                        an empty list means nothing was ever issued. */}
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                      {t('connection.covered', {
                        names: connection.covered?.length
                          ? connection.covered.join(', ')
                          : t('connection.coveredNone'),
                      })}
                    </p>
                  </>
                ) : (
                  <dl className="space-y-2 text-sm">
                    {[
                      { label: t('connection.server'), value: connection?.hostname || '' },
                      { label: t('connection.username'), value: connection?.username || '' },
                      { label: t('connection.imap'), value: `${connection?.imap_port} (${connection?.security})` },
                      { label: t('connection.submission'), value: `${connection?.submission_port} (${connection?.security})` },
                      ...(connection?.covered?.length
                        ? [{ label: t('connection.coveredLabel'), value: connection.covered.join(', ') }]
                        : []),
                    ].map(row => (
                      <div key={row.label} className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500 dark:text-slate-400">{row.label}</dt>
                        <dd className="flex items-center gap-2">
                          <span className="font-mono text-slate-800 dark:text-slate-200">{row.value}</span>
                          <button type="button" onClick={() => copy(row.value)}
                            className="text-xs text-brand-600 hover:underline dark:text-brand-400">{t('connection.copy')}</button>
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}
              </div>
            </div>
          )}

          {tab === 'autoresponder' && autoresponder && (
            <form onSubmit={saveAutoresponder} className="mt-5 max-w-xl space-y-3 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                <input type="checkbox" checked={autoresponder.enabled}
                  onChange={event => setAutoresponder({ ...autoresponder, enabled: event.target.checked })} />
                {t('autoresponder.enabled')}
              </label>
              <input value={autoresponder.subject} onChange={event => setAutoresponder({ ...autoresponder, subject: event.target.value })}
                placeholder={t('autoresponder.subject')}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900" />
              <textarea value={autoresponder.body} onChange={event => setAutoresponder({ ...autoresponder, body: event.target.value })}
                rows={6} placeholder={t('autoresponder.body')}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900" />
              <label className="block text-sm text-slate-700 dark:text-slate-300">
                {t('autoresponder.intervalDays')}
                <input type="number" min={1} value={autoresponder.interval_days}
                  onChange={event => setAutoresponder({ ...autoresponder, interval_days: Number(event.target.value) })}
                  className="ml-2 w-20 rounded-lg border border-slate-300 px-2 py-1 text-sm dark:border-slate-600 dark:bg-slate-900" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('autoresponder.intervalHint')}</p>
              <button disabled={isSavingAutoresponder}
                className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                {isSavingAutoresponder ? t('saving') : t('save')}
              </button>
            </form>
          )}

          {tab === 'forwarding' && (
            <form onSubmit={saveForwarding} className="mt-5 max-w-xl space-y-3 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('forwarding.description')}</p>
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                <input type="checkbox" checked={forwarding.enabled}
                  onChange={event => setForwarding({ ...forwarding, enabled: event.target.checked })} />
                {t('forwarding.enabled')}
              </label>
              <textarea value={destinationText} onChange={event => setDestinationText(event.target.value)}
                rows={4} placeholder={t('forwarding.destinationsPlaceholder')} disabled={!forwarding.enabled}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-900" />
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                <input type="checkbox" checked={forwarding.keep_copy} disabled={!forwarding.enabled}
                  onChange={event => setForwarding({ ...forwarding, keep_copy: event.target.checked })} />
                {t('forwarding.keepCopy')}
              </label>
              <button disabled={isSavingForwarding}
                className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                {isSavingForwarding ? t('saving') : t('save')}
              </button>
            </form>
          )}

          {tab === 'migration' && (
            <div className="mt-5 max-w-2xl space-y-5">
              {job && (
                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                  <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('migration.jobTitle')}</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {t(`migration.status.${job.status}`, { defaultValue: job.status })} · {job.remote_user} @ {job.remote_host}
                  </p>
                  <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">
                    {t('migration.progress', {
                      messages: job.messages_done, total: job.messages_total,
                      folders: job.folders_done, folderTotal: job.folders_total,
                    })}
                  </p>
                  {job.error_code && (
                    <p className="mt-2 text-sm text-red-600 dark:text-red-400">{reasonText(job.error_code)}</p>
                  )}
                  {jobRunning && (
                    <button type="button" onClick={cancelMigration}
                      className="mt-3 rounded-lg border border-red-300 px-3 py-2 text-sm font-medium text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-900/20">
                      {t('migration.cancel')}
                    </button>
                  )}
                </div>
              )}

              {!jobRunning && (
                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                  <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('migration.title')}</h3>
                  <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">{t('migration.description')}</p>

                  <ol className="space-y-5">
                    <li>
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{t('migration.stepFind')}</p>
                      <div className="flex flex-col gap-2 sm:flex-row">
                        <input value={remoteUser} onChange={event => { setRemoteUser(event.target.value); setVerified(false) }}
                          placeholder={mailbox.email} autoComplete="off"
                          className="flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900" />
                        <button type="button" onClick={discover} disabled={isDiscovering}
                          className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                          {isDiscovering ? t('migration.searching') : t('migration.search')}
                        </button>
                      </div>
                      {providerNotice && (
                        <p className="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-900/20 dark:text-amber-300">
                          {reasonText(providerNotice)}
                        </p>
                      )}
                      {candidates.length > 0 && (
                        <ul className="mt-3 divide-y divide-slate-100 dark:divide-slate-700/50">
                          {candidates.map(candidate => (
                            <li key={`${candidate.host}:${candidate.port}:${candidate.security}`} className="flex items-center justify-between py-2">
                              <span className="font-mono text-sm text-slate-700 dark:text-slate-300">
                                {candidate.host}:{candidate.port}
                                <span className="ml-2 text-xs text-slate-400">{candidate.security} · {t(`migration.source.${candidate.source}`, { defaultValue: candidate.source })}</span>
                                {/* A published record can outlive the server it names, so
                                    whether it actually answered is worth its own mark. */}
                                {candidate.responds && (
                                  <span className="ml-2 rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
                                    {t('migration.answers')}
                                  </span>
                                )}
                              </span>
                              <button type="button" onClick={() => chooseCandidate(candidate)}
                                className="text-xs text-brand-600 hover:underline dark:text-brand-400">{t('migration.use')}</button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>

                    <li>
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{t('migration.stepVerify')}</p>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                        <input value={remoteHost} onChange={event => { setRemoteHost(event.target.value); setVerified(false) }}
                          placeholder={t('migration.host')} autoComplete="off"
                          className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900 sm:col-span-2" />
                        <input value={remotePort} onChange={event => { setRemotePort(Number(event.target.value)); setVerified(false) }}
                          type="number" min={1} max={65535} placeholder={t('migration.port')}
                          className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900" />
                        <select value={remoteSecurity} onChange={event => { setRemoteSecurity(event.target.value); setVerified(false) }}
                          className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 dark:border-slate-600 dark:bg-slate-900">
                          <option value="ssl">{t('migration.security.ssl')}</option>
                          <option value="starttls">{t('migration.security.starttls')}</option>
                          <option value="plain">{t('migration.security.plain')}</option>
                        </select>
                        <input value={remotePassword} onChange={event => { setRemotePassword(event.target.value); setVerified(false) }}
                          type="password" placeholder={t('migration.password')} autoComplete="new-password"
                          className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 dark:border-slate-600 dark:bg-slate-900 sm:col-span-2" />
                      </div>
                      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('migration.passwordHint')}</p>
                      <button type="button" onClick={verify} disabled={isVerifying || !remoteHost || !remoteUser || !remotePassword}
                        className="mt-3 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 disabled:opacity-50 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700/50">
                        {isVerifying ? t('migration.verifying') : t('migration.verify')}
                      </button>
                      {verified && <p className="mt-2 text-sm text-emerald-600 dark:text-emerald-400">{t('migration.verified')}</p>}
                      {verifyReason && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{reasonText(verifyReason)}</p>}
                    </li>

                    <li>
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{t('migration.stepStart')}</p>
                      <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">{t('migration.startHint')}</p>
                      <button type="button" onClick={startMigration} disabled={isStarting || !verified}
                        className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                        {isStarting ? t('migration.starting') : t('migration.start')}
                      </button>
                    </li>
                  </ol>
                </div>
              )}
            </div>
          )}

          {tab === 'transfer' && (
            <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('transfer.exportTitle')}</h3>
                <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('transfer.exportDescription')}</p>
                <button type="button" onClick={exportMailbox}
                  className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                  {t('transfer.export')}
                </button>
              </div>

              <form onSubmit={runImport} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('transfer.importTitle')}</h3>
                <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">
                  {formats?.pst_supported ? t('transfer.importFormatsWithPst') : t('transfer.importFormats')}
                </p>
                <input type="file" onChange={event => setUploadFile(event.target.files?.[0] || null)}
                  className="w-full text-sm text-slate-700 dark:text-slate-300" />
                <button disabled={isImporting || !uploadFile}
                  className="mt-3 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100">
                  {isImporting ? t('transfer.importing') : t('transfer.import')}
                </button>
              </form>
            </div>
          )}
        </>
      )}
    </div>
  )
}
