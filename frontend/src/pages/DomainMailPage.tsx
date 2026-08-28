import { useCallback, useEffect, useState } from 'react'
import type { AxiosError } from 'axios'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import ResourceNotice from '@/components/ResourceNotice'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Domain = { id: number; domain_name: string; ssl: boolean }
type Mailbox = { id: number; local_part: string; email: string; status: string; created_at: string }
type MailStatus = { enabled: boolean; dkim_selector?: string; infrastructure_missing?: string[] }
type Alias = { id: number; source: string; destination: string; catch_all: boolean; status: string; created_at: string }
type SpamSettings = { enabled: boolean; greylist_score: number; add_header_score: number; reject_score: number }
type SpamResponse = { settings: SpamSettings; rspamd: boolean }
type Autoresponder = { mailbox_id: number; email: string; enabled: boolean; subject: string; body: string; interval_days: number }
type MailFilter = {
  id: number; mailbox_id: number; email: string; name: string; match_field: 'from' | 'to' | 'subject'
  match_value: string; action_type: 'move' | 'redirect' | 'discard'; action_value: string; priority: number; enabled: boolean
}
type SendLimits = { mailbox_id: number; email: string; hour_limit: number; day_limit: number; sent_hour: number; sent_day: number; spam_suspended_at?: string }
type DeliveryEntry = { timestamp: string; direction: 'in' | 'out'; sender: string; recipient: string; status: string; reason?: string }

// Colour carries the same meaning as the label, so a glance down the column
// separates delivered from stuck from rejected without reading every row.
function deliveryBadge(status: string): string {
  switch (status) {
    case 'sent': return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
    case 'deferred': return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
    default: return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
  }
}

export default function DomainMailPage() {
  const { t } = useTranslation('DomainMailPage')
  const report = useReportError()
  const { confirm, notify } = useDialog()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [status, setStatus] = useState<MailStatus | null>(null)
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [aliases, setAliases] = useState<Alias[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [localPart, setLocalPart] = useState('')
  const [password, setPassword] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [isPurging, setIsPurging] = useState(false)
  const [purgeConfirmOpen, setPurgeConfirmOpen] = useState(false)
  const [purgeConfirmationText, setPurgeConfirmationText] = useState('')
  const [generatedPassword, setGeneratedPassword] = useState<{ email: string; password: string } | null>(null)
  const [aliasLocalPart, setAliasLocalPart] = useState('')
  const [aliasDestination, setAliasDestination] = useState('')
  const [aliasCatchAll, setAliasCatchAll] = useState(false)
  const [isSavingAlias, setIsSavingAlias] = useState(false)
  const [deliveries, setDeliveries] = useState<DeliveryEntry[]>([])
  const [deliveryLoading, setDeliveryLoading] = useState(false)
  const [deliveryDirection, setDeliveryDirection] = useState('')
  const [deliveryStatus, setDeliveryStatus] = useState('')
  const [deliverySearch, setDeliverySearch] = useState('')
  const [spam, setSpam] = useState<SpamSettings>({ enabled: true, greylist_score: 4, add_header_score: 6, reject_score: 15 })
  const [rspamd, setRspamd] = useState(false)
  const [isSavingSpam, setIsSavingSpam] = useState(false)
  const [autoresponder, setAutoresponder] = useState<Autoresponder>({ mailbox_id: 0, email: '', enabled: true, subject: 'Automatic reply', body: '', interval_days: 7 })
  const [isSavingAutoresponder, setIsSavingAutoresponder] = useState(false)
  const [filters, setFilters] = useState<MailFilter[]>([])
  const [filter, setFilter] = useState<Omit<MailFilter, 'id' | 'email'>>({
    mailbox_id: 0, name: '', match_field: 'subject', match_value: '', action_type: 'move', action_value: 'Junk', priority: 100, enabled: true,
  })
  const [isSavingFilter, setIsSavingFilter] = useState(false)
  const [limits, setLimits] = useState<SendLimits>({ mailbox_id: 0, email: '', hour_limit: 100, day_limit: 500, sent_hour: 0, sent_day: 0 })
  const [isSavingLimits, setIsSavingLimits] = useState(false)

  // Derived, not state: the server decides this and the page only reflects it.
  const missingServices = (status?.infrastructure_missing || []).join(', ')
  const stackDown = missingServices !== ''

  // Declared before the loaders that call them: a function hoisted past its own
  // use site cannot pick up a later definition, so the earlier call would keep
  // an older closure over id and t.
  // Promise callbacks rather than await/try: the seeding effect below calls
  // both, and writes in an awaited body still count as the effect's own
  // continuation.
  const loadAutoresponder = useCallback((mailboxID: number) => {
    if (!mailboxID) return
    api.get<Autoresponder>(`/domains/${id}/mail/${mailboxID}/autoresponder`)
      .then(response => setAutoresponder(response.data))
      .catch(cause => setError(apiError(cause, t('errors.readAutoresponderFailed'))))
  }, [id, t])

  const loadSendLimits = useCallback((mailboxID: number) => {
    if (!mailboxID) return
    api.get<SendLimits>(`/domains/${id}/mail/${mailboxID}/send-limits`)
      .then(response => setLimits(response.data))
      .catch(cause => setError(apiError(cause, t('errors.readSendLimitsFailed'))))
  }, [id, t])

  // Split so the mount effect never writes state synchronously: fetchMail
  // settles only through promise callbacks, and loadMail() adds the spinner for
  // the refreshes that follow a write.
  const fetchMail = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<MailStatus>(`/domains/${id}/mail/status`),
      api.get<Mailbox[]>(`/domains/${id}/mail`),
      api.get<Alias[]>(`/domains/${id}/mail/aliases`),
      // Null rather than the current settings on failure: keeping the existing
      // spam state out of this closure is what lets the fetch depend on id alone.
      api.get<SpamResponse>(`/domains/${id}/mail/spam`).then(r => r.data)
        .catch(err => { report('spamSettings')(err); return null }),
      api.get<MailFilter[]>(`/domains/${id}/mail/filters`).catch(() => ({ data: [] as MailFilter[] })),
    ])
      .then(([statusResponse, mailboxesResponse, aliasesResponse, spamResponse, filtersResponse]) => {
        setStatus(statusResponse.data)
        setMailboxes(mailboxesResponse.data || [])
        setAliases(aliasesResponse.data || [])
        if (spamResponse) {
          setSpam(spamResponse.settings)
          setRspamd(spamResponse.rspamd)
        }
        setFilters(filtersResponse.data || [])
        const boxes = mailboxesResponse.data || []
        if (boxes.length) setFilter(current => current.mailbox_id ? current : { ...current, mailbox_id: boxes[0].id })
      })
      .catch(cause => setError(apiError(cause)))
      .finally(() => setLoading(false))
  }, [id, report])

  const loadMail = useCallback(() => {
    setLoading(true)
    fetchMail()
  }, [fetchMail])

  useEffect(() => {
    if (!id) return
    api.get<Domain>(`/domains/${id}`)
      .then(response => setDomain(response.data))
      .catch(cause => setError(apiError(cause, t('errors.loadDomainFailed'))))
    fetchMail()
  }, [id, t, fetchMail])

  // Seed both pickers from the first mailbox once the list arrives; a picker the
  // user has already chosen keeps its own mailbox.
  const firstMailboxID = mailboxes[0]?.id ?? 0
  const autoresponderMailbox = autoresponder.mailbox_id
  const limitsMailbox = limits.mailbox_id
  useEffect(() => {
    if (!firstMailboxID) return
    if (!autoresponderMailbox) loadAutoresponder(firstMailboxID)
    if (!limitsMailbox) loadSendLimits(firstMailboxID)
  }, [firstMailboxID, autoresponderMailbox, limitsMailbox, loadAutoresponder, loadSendLimits])

  // Debounced so typing in the search box does not issue one query per keystroke.
  useEffect(() => {
    if (!id || !status?.enabled) return
    const timer = setTimeout(() => {
      setDeliveryLoading(true)
      const params = new URLSearchParams()
      if (deliveryDirection) params.set('direction', deliveryDirection)
      if (deliveryStatus) params.set('status', deliveryStatus)
      if (deliverySearch.trim()) params.set('search', deliverySearch.trim())
      api.get<DeliveryEntry[]>(`/domains/${id}/mail/delivery-log?${params.toString()}`)
        .then(response => setDeliveries(response.data || []))
        .catch(report('deliveryLog'))
        .finally(() => setDeliveryLoading(false))
    }, 300)
    return () => clearTimeout(timer)
  }, [id, status?.enabled, deliveryDirection, deliveryStatus, deliverySearch, report])

  async function enableMail() {
    setIsSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await api.post(`/domains/${id}/mail/enable`)
      setSuccess(t('messages.enabled'))
      loadMail()
    } catch (cause) {
      // 503 is the server's own stack check. The button is disabled from the
      // status response, so this only happens on a tab that loaded before the
      // services went down; answering it in the reader's language rather than
      // with the API's English keeps that case readable.
      if ((cause as AxiosError)?.response?.status === 503) {
        setError(t('enable.infrastructureMissingGeneric'))
      } else {
        setError(apiError(cause, t('errors.enableFailed')))
      }
      loadMail()
    } finally {
      setIsSaving(false)
    }
  }

  // Turning the service off is NOT a deletion. DisableDomain only sets
  // mail_domains.status='suspended'; mailboxes, forwarders and the Maildir on
  // disk all stay, and enabling again restores them untouched. What the
  // suspended status does change is real: the Postfix virtual-domain lookup and
  // both Dovecot queries require status='active', so delivery stops and nobody
  // can sign in. The confirmation has to state both halves.
  async function disableMail() {
    if (!(await confirm({ message: t('confirm.disableMail', { domain: domain?.domain_name }), dangerous: true }))) return
    setIsSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await api.delete(`/domains/${id}/mail/enable`)
      setSuccess(t('messages.disabled'))
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.disableFailed')))
    } finally {
      setIsSaving(false)
    }
  }

  // The destructive counterpart. The server answers 200 with a warning code when
  // it cleared the database but could not remove the files: the service is gone
  // either way, so this is not an error, but the disk is still occupied and
  // saying nothing would leave the customer looking for space that never came
  // back.
  async function purgeMail() {
    setIsPurging(true)
    setError(null)
    setSuccess(null)
    try {
      const response = await api.delete<{ ok: boolean; warning?: string }>(`/domains/${id}/mail/service`)
      setPurgeConfirmOpen(false)
      if (response.data.warning) setError(t(`purge.warning.${response.data.warning}`))
      else setSuccess(t('messages.purged'))
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.purgeFailed')))
    } finally {
      setIsPurging(false)
    }
  }

  async function addMailbox(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    setSuccess(null)
    setGeneratedPassword(null)
    setIsSaving(true)
    try {
      const response = await api.post<{ email: string; password: string }>(`/domains/${id}/mail`, { local_part: localPart, password })
      setGeneratedPassword({ email: response.data.email, password: response.data.password })
      setLocalPart('')
      setPassword('')
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.createMailboxFailed')))
    } finally {
      setIsSaving(false)
    }
  }

  async function addAlias(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    setSuccess(null)
    setIsSavingAlias(true)
    try {
      await api.post(`/domains/${id}/mail/aliases`, {
        local_part: aliasCatchAll ? '' : aliasLocalPart,
        destination: aliasDestination,
      })
      setAliasLocalPart('')
      setAliasDestination('')
      setAliasCatchAll(false)
      setSuccess(t('messages.forwarderAdded'))
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.addForwarderFailed')))
    } finally {
      setIsSavingAlias(false)
    }
  }

  async function removeMailbox(mailbox: Mailbox) {
    if (!(await confirm({ message: t('confirm.deleteMailbox', { email: mailbox.email }), dangerous: true }))) return
    setError(null)
    setSuccess(null)
    try {
      await api.delete(`/domains/${id}/mail/${mailbox.id}`)
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.deleteMailboxFailed')))
    }
  }

  async function removeAlias(alias: Alias) {
    if (!(await confirm({ message: t('confirm.deleteForwarder', { source: alias.source }), dangerous: true }))) return
    setError(null)
    setSuccess(null)
    try {
      await api.delete(`/domains/${id}/mail/aliases/${alias.id}`)
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.deleteForwarderFailed')))
    }
  }

  async function resetPassword(mailbox: Mailbox) {
    setError(null)
    setSuccess(null)
    setGeneratedPassword(null)
    try {
      const response = await api.put<{ password: string }>(`/domains/${id}/mail/${mailbox.id}/password`, {})
      setGeneratedPassword({ email: mailbox.email, password: response.data.password })
    } catch (cause) {
      setError(apiError(cause, t('errors.resetPasswordFailed')))
    }
  }

  async function toggleAliasStatus(alias: Alias) {
    setError(null)
    setSuccess(null)
    try {
      await api.post(`/domains/${id}/mail/aliases/${alias.id}/status`, { status: alias.status === 'active' ? 'suspended' : 'active' })
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.updateForwarderFailed')))
    }
  }

  // Opening webmail without asking for the mailbox password again.
  //
  // The panel holds only a hash of that password, so the sign-in is carried by a
  // single-use token the webmail side redeems over the loopback. The token goes
  // in a POST body rather than the URL, so it cannot reach browser history, a
  // proxy log, or a Referer header.
  async function openWebmail(mailbox: Mailbox) {
    try {
      const { data } = await api.post<{ token: string }>(`/domains/${id}/mail/${mailbox.id}/webmail-token`)
      const form = document.createElement('form')
      form.method = 'POST'
      // The same address the page advertises, so the Roundcube session lands on
      // the host the customer is told to use rather than on the panel origin.
      form.action = `${webmailURL}index.php`
      form.target = '_blank'
      for (const [name, value] of [['_task', 'login'], ['_action', 'login'], ['_servika_token', data.token]]) {
        const input = document.createElement('input')
        input.type = 'hidden'
        input.name = name
        input.value = value
        form.appendChild(input)
      }
      document.body.appendChild(form)
      form.submit()
      form.remove()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.webmail')), tone: 'error' })
    }
  }

  async function toggleMailboxStatus(mailbox: Mailbox) {
    setError(null)
    setSuccess(null)
    try {
      await api.post(`/domains/${id}/mail/${mailbox.id}/status`, { status: mailbox.status === 'active' ? 'suspended' : 'active' })
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.updateMailboxFailed')))
    }
  }

  async function saveSpam(event: React.FormEvent) {
    event.preventDefault()
    setIsSavingSpam(true)
    setError(null)
    setSuccess(null)
    try {
      const response = await api.put<{ settings: SpamSettings }>(`/domains/${id}/mail/spam`, spam)
      setSpam(response.data.settings)
      setRspamd(true)
      setSuccess(t('messages.spamApplied'))
    } catch (cause) {
      setError(apiError(cause, t('errors.applySpamFailed')))
    } finally {
      setIsSavingSpam(false)
    }
  }

  async function saveAutoresponder(event: React.FormEvent) {
    event.preventDefault()
    setIsSavingAutoresponder(true)
    setError(null)
    setSuccess(null)
    try {
      await api.put(`/domains/${id}/mail/${autoresponder.mailbox_id}/autoresponder`, autoresponder)
      setSuccess(t('messages.autoresponderSaved'))
    } catch (cause) {
      setError(apiError(cause, t('errors.saveAutoresponderFailed')))
    } finally {
      setIsSavingAutoresponder(false)
    }
  }

  async function deleteAutoresponder() {
    setIsSavingAutoresponder(true)
    setError(null)
    try {
      await api.delete(`/domains/${id}/mail/${autoresponder.mailbox_id}/autoresponder`)
      setAutoresponder(current => ({ ...current, enabled: false, body: '' }))
      setSuccess(t('messages.autoresponderRemoved'))
    } catch (cause) {
      setError(apiError(cause))
    } finally {
      setIsSavingAutoresponder(false)
    }
  }

  async function addFilter(event: React.FormEvent) {
    event.preventDefault()
    setIsSavingFilter(true)
    setError(null)
    setSuccess(null)
    try {
      await api.post(`/domains/${id}/mail/filters`, filter)
      setFilter(current => ({ ...current, name: '', match_value: '' }))
      setSuccess(t('messages.filterAdded'))
      loadMail()
    } catch (cause) {
      setError(apiError(cause, t('errors.addFilterFailed')))
    } finally {
      setIsSavingFilter(false)
    }
  }

  async function deleteFilter(item: MailFilter) {
    if (!(await confirm({ message: t('confirm.deleteFilter', { name: item.name }), dangerous: true }))) return
    setError(null)
    try {
      await api.delete(`/domains/${id}/mail/filters/${item.id}`)
      loadMail()
    } catch (cause) {
      setError(apiError(cause))
    }
  }

  async function saveSendLimits(event: React.FormEvent) {
    event.preventDefault()
    setIsSavingLimits(true)
    setError(null)
    setSuccess(null)
    try {
      await api.put(`/domains/${id}/mail/${limits.mailbox_id}/send-limits`, limits)
      setSuccess(t('messages.sendLimitsSaved'))
      loadSendLimits(limits.mailbox_id)
    } catch (cause) {
      setError(apiError(cause, t('errors.saveSendLimitsFailed')))
    } finally {
      setIsSavingLimits(false)
    }
  }

  // Webmail is served from the customer's OWN domain, through the /webmail/
  // block the panel renders into their vhost. The panel origin is only a
  // fallback: it is what the address was before, and it is still the only
  // encrypted route while the domain has no certificate, since the block is
  // rendered onto the TLS vhost alone.
  const webmailURL = domain?.ssl
    ? `https://${domain.domain_name}/webmail/`
    : `${window.location.origin}/webmail/`

  async function copyWebmailURL() {
    setError(null)
    setSuccess(null)
    // The clipboard API is unavailable outside a secure context, and a silent
    // no-op would look like the copy worked.
    if (!navigator.clipboard || !window.isSecureContext) {
      setError(t('webmail.copyUnavailable'))
      return
    }
    try {
      await navigator.clipboard.writeText(webmailURL)
      setSuccess(t('webmail.copied'))
    } catch {
      setError(t('webmail.copyUnavailable'))
    }
  }

  return (
    <div className="px-6 py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
          { label: t('breadcrumb.email') },
        ]} />
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('subtitle')}
        </p>

        {status?.enabled && stackDown && (
          <div className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg text-sm text-amber-800 dark:text-amber-200">
            {t('enable.deliveryStopped', { services: missingServices })}
          </div>
        )}

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
        {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

        {generatedPassword && (
          <div className="mb-3 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg p-4">
            <p className="text-sm text-emerald-800 dark:text-emerald-200 font-medium mb-1">{t('generatedPassword.title', { email: generatedPassword.email })}</p>
            <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-2">{t('generatedPassword.saveNote')}</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-white dark:bg-slate-800 px-3 py-2 font-mono text-sm text-slate-900 dark:text-slate-100 rounded border border-emerald-200 dark:border-emerald-800 break-all">{generatedPassword.password}</code>
              <button type="button" onClick={() => navigator.clipboard.writeText(generatedPassword.password)} className="px-3 py-2 bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 text-emerald-800 dark:text-emerald-200 text-xs rounded">{t('generatedPassword.copy')}</button>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-sm text-slate-400">{t('loading')}</div>
        ) : !status?.enabled ? (
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 text-center">
            <div className="mb-2"><Icon d={ICON.mail} className="h-8 w-8" /></div>
            <p className="text-sm text-slate-600 dark:text-slate-300 mb-1">{t('enable.notEnabled')}</p>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-4">{t('enable.info')}</p>
            {/* Enabling mail starts a whole stack on the server, not a setting on
                this domain alone, so the cost is stated before the button. */}
            <div className="flex justify-center mb-4">
              <ResourceNotice>{t('enable.resourceWarning')}</ResourceNotice>
            </div>
            {/* The server refuses this while its mail services are down, and
                enabling would otherwise publish MX for a service that never
                runs. Saying so here beats letting the click fail. */}
            {stackDown && (
              <div className="mx-auto mb-4 max-w-lg px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg text-xs text-amber-800 dark:text-amber-200">
                {t('enable.infrastructureMissing', { services: missingServices })}
              </div>
            )}
            <button type="button" onClick={enableMail} disabled={isSaving || stackDown}
              className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed">
              {isSaving ? t('enable.enabling') : t('enable.button')}
            </button>
          </div>
        ) : (
          <>
            {/* Roundcube is one shared installation reached under /webmail/ on
                the domain's own TLS vhost. It is NOT at mail.<domain>: that
                record exists to be the MX target and has no vhost, so a request
                to it falls through to the catch-all. */}
            <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5 shadow-sm flex flex-wrap items-center gap-4">
              <div className="w-11 h-11 shrink-0 rounded-xl bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300 flex items-center justify-center">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
                </svg>
              </div>
              <div className="min-w-[200px] flex-1">
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('webmail.title')}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t('webmail.description')}</div>
                <code className="text-[11px] text-slate-500 dark:text-slate-500 font-mono break-all">{webmailURL}</code>
              </div>
              <div className="flex items-center gap-2">
                <a href={webmailURL} target="_blank" rel="noopener noreferrer"
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white text-sm font-medium rounded-lg">
                  {t('webmail.open')}
                </a>
                <button type="button" onClick={copyWebmailURL}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 text-sm rounded-lg">
                  {t('webmail.copy')}
                </button>
              </div>
            </div>

            <form onSubmit={addMailbox} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('mailboxAdd.title')}</h3>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <input value={localPart} onChange={event => setLocalPart(event.target.value)} required placeholder={t('mailboxAdd.localPlaceholder')}
                  className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
                <span className="text-slate-500 dark:text-slate-400 text-sm">@{domain?.domain_name}</span>
                <input value={password} onChange={event => setPassword(event.target.value)} type="password" placeholder={t('mailboxAdd.passwordPlaceholder')}
                  className="sm:w-60 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
                <button disabled={isSaving || !localPart} className="px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                  {isSaving ? t('mailboxAdd.adding') : t('mailboxAdd.add')}
                </button>
              </div>
            </form>

            <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('mailboxes.title')}</h3>
              {mailboxes.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-sm text-slate-500 dark:text-slate-400">{t('mailboxes.empty')}</p>
                </div>
              ) : (
                <ul className="divide-y divide-slate-50 dark:divide-slate-700/50">
                  {mailboxes.map(mailbox => (
                    <li key={mailbox.id} className="flex items-center justify-between py-2.5">
                      <div>
                        <span className="text-sm font-mono text-slate-800 dark:text-slate-200">{mailbox.email}</span>
                        {mailbox.status !== 'active' && (
                          <span className="ml-2 text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-300 bg-amber-100 dark:bg-amber-900/30 px-1.5 py-0.5 rounded">{t('mailboxes.suspended')}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <Link to={`/subscriptions/${id}/mail/${mailbox.id}`} className="text-xs text-brand-600 dark:text-brand-400 hover:underline">{t('mailboxes.details')}</Link>
                        {mailbox.status === 'active' && (
                          <button type="button" onClick={() => openWebmail(mailbox)} className="text-xs text-brand-600 dark:text-brand-400 hover:underline">{t('mailboxes.openWebmail')}</button>
                        )}
                        <button type="button" onClick={() => toggleMailboxStatus(mailbox)} className="text-xs text-slate-600 dark:text-slate-300 hover:underline">
                          {mailbox.status === 'active' ? t('mailboxes.suspend') : t('mailboxes.activate')}
                        </button>
                        <button type="button" onClick={() => resetPassword(mailbox)} className="text-xs text-slate-600 dark:text-slate-300 hover:underline">{t('mailboxes.resetPassword')}</button>
                        <button type="button" onClick={() => removeMailbox(mailbox)} className="text-xs text-red-600 dark:text-red-400 hover:underline">{t('mailboxes.delete')}</button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* The settings cards pair up on a wide screen; gap-5 replaces the
                per-card margin they carried while they were stacked, and
                items-start keeps a short card from stretching to its
                neighbour's height. The mailbox list and the delivery table stay
                full width: both hold rows too wide for half a column. */}
            <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
            <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('forwarders.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                {t('forwarders.description')}
              </p>
              <form onSubmit={addAlias} className="mb-4 space-y-2">
                <div className="flex items-center gap-2">
                  {aliasCatchAll ? (
                    <span className="flex-1 px-3 py-2 border border-dashed border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-500 dark:text-slate-400 font-mono">*@{domain?.domain_name}</span>
                  ) : (
                    <>
                      <input value={aliasLocalPart} onChange={event => setAliasLocalPart(event.target.value)} required={!aliasCatchAll} placeholder={t('forwarders.sourcePlaceholder')}
                        className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
                      <span className="text-slate-500 dark:text-slate-400 text-sm">@{domain?.domain_name}</span>
                    </>
                  )}
                </div>
                <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
                  <input type="checkbox" checked={aliasCatchAll} onChange={event => setAliasCatchAll(event.target.checked)} />
                  {t('forwarders.catchAll')}
                </label>
                <div className="flex items-center gap-2">
                  <input value={aliasDestination} onChange={event => setAliasDestination(event.target.value)} required placeholder={t('forwarders.destinationPlaceholder')}
                    className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
                  <button disabled={isSavingAlias || !aliasDestination || (!aliasCatchAll && !aliasLocalPart)}
                    className="px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                    {isSavingAlias ? t('forwarders.adding') : t('forwarders.add')}
                  </button>
                </div>
              </form>

              {aliases.length === 0 ? (
                <div className="text-center py-6">
                  <p className="text-sm text-slate-500 dark:text-slate-400">{t('forwarders.empty')}</p>
                </div>
              ) : (
                <ul className="divide-y divide-slate-50 dark:divide-slate-700/50">
                  {aliases.map(alias => (
                    <li key={alias.id} className="flex items-center justify-between py-2.5">
                      <div>
                        <span className="text-sm font-mono text-slate-800 dark:text-slate-200">
                          {alias.catch_all ? `*@${domain?.domain_name}` : alias.source}
                        </span>
                        <span className="mx-1.5 text-slate-400">→</span>
                        <span className="text-sm font-mono text-slate-600 dark:text-slate-400">{alias.destination}</span>
                        {alias.status !== 'active' && (
                          <span className="ml-2 text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-300 bg-amber-100 dark:bg-amber-900/30 px-1.5 py-0.5 rounded">{t('forwarders.suspended')}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <button type="button" onClick={() => toggleAliasStatus(alias)} className="text-xs text-slate-600 dark:text-slate-300 hover:underline">
                          {alias.status === 'active' ? t('forwarders.suspend') : t('forwarders.activate')}
                        </button>
                        <button type="button" onClick={() => removeAlias(alias)} className="text-xs text-red-600 dark:text-red-400 hover:underline">{t('forwarders.delete')}</button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <form onSubmit={saveSpam} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('spam.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                {t('spam.description')}
                {!rspamd && <span className="text-amber-600 dark:text-amber-400">{t('spam.notInstalled')}</span>}
              </p>
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200 mb-3">
                <input type="checkbox" checked={spam.enabled} onChange={event => setSpam({ ...spam, enabled: event.target.checked })} />
                {t('spam.enable')}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
                {([['greylist_score', t('spam.greylist')], ['add_header_score', t('spam.addHeader')], ['reject_score', t('spam.reject')]] as const).map(([key, label]) => (
                  <label key={key} className="text-xs text-slate-600 dark:text-slate-300">
                    {label}
                    <input type="number" step="0.5" min="0" max="50" value={spam[key]}
                      onChange={event => setSpam({ ...spam, [key]: Number(event.target.value) })}
                      className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm outline-none" />
                  </label>
                ))}
              </div>
              <button disabled={isSavingSpam} className="mt-3 px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                {isSavingSpam ? t('spam.applying') : t('spam.apply')}
              </button>
            </form>

            {mailboxes.length > 0 && (
            <form onSubmit={saveAutoresponder} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('autoresponder.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('autoresponder.description')}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                <label className="text-xs text-slate-600 dark:text-slate-300">{t('autoresponder.mailbox')}
                  <select value={autoresponder.mailbox_id} onChange={event => loadAutoresponder(Number(event.target.value))}
                    className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                    {mailboxes.map(mailbox => <option key={mailbox.id} value={mailbox.id}>{mailbox.email}</option>)}
                  </select>
                </label>
                <label className="text-xs text-slate-600 dark:text-slate-300">{t('autoresponder.interval')}
                  <input type="number" min="1" max="30" value={autoresponder.interval_days}
                    onChange={event => setAutoresponder({ ...autoresponder, interval_days: Number(event.target.value) })}
                    className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
                </label>
              </div>
              <input value={autoresponder.subject} onChange={event => setAutoresponder({ ...autoresponder, subject: event.target.value })}
                placeholder={t('autoresponder.subjectPlaceholder')} className="w-full mb-2 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
              <textarea value={autoresponder.body} onChange={event => setAutoresponder({ ...autoresponder, body: event.target.value })}
                placeholder={t('autoresponder.bodyPlaceholder')} rows={3} className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200 my-3">
                <input type="checkbox" checked={autoresponder.enabled} onChange={event => setAutoresponder({ ...autoresponder, enabled: event.target.checked })} />
                {t('autoresponder.enable')}
              </label>
              <div className="flex gap-2">
                <button disabled={isSavingAutoresponder} className="px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                  {isSavingAutoresponder ? t('autoresponder.saving') : t('autoresponder.save')}
                </button>
                <button type="button" onClick={deleteAutoresponder} disabled={isSavingAutoresponder} className="px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:underline">{t('autoresponder.remove')}</button>
              </div>
            </form>
            )}

            {mailboxes.length > 0 && (
            <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('filters.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('filters.description')}</p>
              <form onSubmit={addFilter} className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
                <select value={filter.mailbox_id} onChange={event => setFilter({ ...filter, mailbox_id: Number(event.target.value) })}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                  {mailboxes.map(mailbox => <option key={mailbox.id} value={mailbox.id}>{mailbox.email}</option>)}
                </select>
                <input value={filter.name} onChange={event => setFilter({ ...filter, name: event.target.value })} required placeholder={t('filters.namePlaceholder')}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
                <select value={filter.match_field} onChange={event => setFilter({ ...filter, match_field: event.target.value as MailFilter['match_field'] })}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                  <option value="subject">{t('filters.subjectContains')}</option><option value="from">{t('filters.fromContains')}</option><option value="to">{t('filters.toContains')}</option>
                </select>
                <input value={filter.match_value} onChange={event => setFilter({ ...filter, match_value: event.target.value })} required placeholder={t('filters.matchedTextPlaceholder')}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
                <select value={filter.action_type} onChange={event => setFilter({ ...filter, action_type: event.target.value as MailFilter['action_type'] })}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                  <option value="move">{t('filters.moveToFolder')}</option><option value="redirect">{t('filters.redirectTo')}</option><option value="discard">{t('filters.discard')}</option>
                </select>
                {filter.action_type !== 'discard' &&
                  <input value={filter.action_value} onChange={event => setFilter({ ...filter, action_value: event.target.value })} required
                    placeholder={filter.action_type === 'move' ? t('filters.folderPlaceholder') : t('filters.targetPlaceholder')}
                    className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono" />}
                <button disabled={isSavingFilter} className="sm:col-span-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                  {isSavingFilter ? t('filters.adding') : t('filters.add')}
                </button>
              </form>
              {filters.length === 0 ? <p className="text-sm text-slate-500 dark:text-slate-400 text-center py-4">{t('filters.empty')}</p> : (
                <ul className="divide-y divide-slate-50 dark:divide-slate-700/50">
                  {filters.map(item => (
                    <li key={item.id} className="flex items-center justify-between py-2.5 text-sm">
                      <div>
                        <span className="font-mono text-xs text-slate-500">{item.email}</span>{' '}
                        <span className="text-slate-800 dark:text-slate-200">{item.name}</span>
                        <div className="text-xs text-slate-500">{item.match_field} ∋ “{item.match_value}” → {item.action_type} {item.action_value}</div>
                      </div>
                      <button type="button" onClick={() => deleteFilter(item)} className="text-xs text-red-600 dark:text-red-400 hover:underline">{t('filters.delete')}</button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            )}

            {mailboxes.length > 0 && (
            <form onSubmit={saveSendLimits} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('sendLimits.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                {t('sendLimits.description')}
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
                <label className="text-xs text-slate-600 dark:text-slate-300">{t('sendLimits.mailbox')}
                  <select value={limits.mailbox_id} onChange={event => loadSendLimits(Number(event.target.value))}
                    className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                    {mailboxes.map(mailbox => <option key={mailbox.id} value={mailbox.id}>{mailbox.email}</option>)}
                  </select>
                </label>
                <label className="text-xs text-slate-600 dark:text-slate-300">{t('sendLimits.hourly', { count: limits.sent_hour })}
                  <input type="number" min="0" max="100000" value={limits.hour_limit}
                    onChange={event => setLimits({ ...limits, hour_limit: Number(event.target.value) })}
                    className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
                </label>
                <label className="text-xs text-slate-600 dark:text-slate-300">{t('sendLimits.daily', { count: limits.sent_day })}
                  <input type="number" min="0" max="100000" value={limits.day_limit}
                    onChange={event => setLimits({ ...limits, day_limit: Number(event.target.value) })}
                    className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
                </label>
              </div>
              {limits.spam_suspended_at &&
                <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">{t('sendLimits.suspendedNote', { time: limits.spam_suspended_at })}</p>}
              <button disabled={isSavingLimits} className="mt-3 px-3 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                {isSavingLimits ? t('sendLimits.saving') : t('sendLimits.save')}
              </button>
            </form>
            )}
            </div>

            {/* Delivery history. The Postfix queue above only shows what has not
                gone out yet; this answers "did it arrive?" after the fact. */}
            <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm mt-5">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('delivery.title')}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('delivery.description')}</p>
              <div className="flex flex-wrap gap-2 mb-3">
                <select value={deliveryDirection} onChange={event => setDeliveryDirection(event.target.value)}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                  <option value="">{t('delivery.anyDirection')}</option>
                  <option value="out">{t('delivery.outgoing')}</option>
                  <option value="in">{t('delivery.incoming')}</option>
                </select>
                <select value={deliveryStatus} onChange={event => setDeliveryStatus(event.target.value)}
                  className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm">
                  <option value="">{t('delivery.anyStatus')}</option>
                  <option value="sent">{t('delivery.status.sent')}</option>
                  <option value="deferred">{t('delivery.status.deferred')}</option>
                  <option value="bounced">{t('delivery.status.bounced')}</option>
                  <option value="expired">{t('delivery.status.expired')}</option>
                </select>
                <input value={deliverySearch} onChange={event => setDeliverySearch(event.target.value)}
                  placeholder={t('delivery.searchPlaceholder')}
                  className="flex-1 min-w-[12rem] px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm" />
              </div>
              {deliveryLoading ? (
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('delivery.loading')}</p>
              ) : deliveries.length === 0 ? (
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('delivery.empty')}</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                        <th className="py-1.5 pr-3 font-medium">{t('delivery.column.time')}</th>
                        <th className="py-1.5 pr-3 font-medium">{t('delivery.column.from')}</th>
                        <th className="py-1.5 pr-3 font-medium">{t('delivery.column.to')}</th>
                        <th className="py-1.5 font-medium">{t('delivery.column.result')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deliveries.map((entry, index) => (
                        <tr key={`${entry.timestamp}-${index}`} className="border-b border-slate-100 dark:border-slate-700/60 last:border-0">
                          <td className="py-1.5 pr-3 font-mono text-xs whitespace-nowrap text-slate-600 dark:text-slate-300">{entry.timestamp}</td>
                          <td className="py-1.5 pr-3 break-all text-slate-700 dark:text-slate-200">{entry.sender || '-'}</td>
                          <td className="py-1.5 pr-3 break-all text-slate-700 dark:text-slate-200">{entry.recipient}</td>
                          <td className="py-1.5">
                            <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${deliveryBadge(entry.status)}`}>
                              {t(`delivery.status.${entry.status}`)}
                            </span>
                            {entry.reason && <span className="ml-2 text-xs text-slate-400 dark:text-slate-500 break-all">{entry.reason}</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* The two ways to stop the service, side by side and outside the
                settings grid: both act on the whole service rather than one
                setting. The difference has to be legible before the click, so
                the reversible one is amber and outlined while the irreversible
                one is red and filled. In one colour they would read as equals. */}
            <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
              <div className="bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-900/50 rounded-2xl p-5 shadow-sm">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('disable.title')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('disable.description')}</p>
                <button type="button" onClick={disableMail} disabled={isSaving || isPurging}
                  className="mt-3 px-4 py-2 border border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-900/30 disabled:opacity-50 text-sm font-medium rounded-lg">
                  {isSaving ? t('disable.working') : t('disable.button')}
                </button>
              </div>

              <div className="bg-white dark:bg-slate-800 border border-red-300 dark:border-red-800 rounded-2xl p-5 shadow-sm">
                <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">{t('purge.title')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('purge.description')}</p>
                <ul className="mt-2 space-y-0.5 text-xs text-slate-500 dark:text-slate-400 list-disc list-inside">
                  <li>{t('purge.itemMailboxes')}</li>
                  <li>{t('purge.itemFiles')}</li>
                  <li>{t('purge.itemDNS')}</li>
                </ul>
                <button type="button" onClick={() => { setPurgeConfirmationText(''); setPurgeConfirmOpen(true) }}
                  disabled={isSaving || isPurging}
                  className="mt-3 px-4 py-2 bg-red-600 hover:bg-red-700 text-white disabled:opacity-50 text-sm font-medium rounded-lg">
                  {isPurging ? t('purge.working') : t('purge.button')}
                </button>
              </div>
            </div>
          </>
        )}

        {/* A single confirmation is not enough for something this final, so the
            domain name has to be typed, the same bar the panel already sets for
            deleting a subscription. */}
        {purgeConfirmOpen && (() => {
          const expected = domain?.domain_name || ''
          const confirmed = purgeConfirmationText.trim().toLowerCase() === expected.toLowerCase()
          return (
            <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setPurgeConfirmOpen(false)}>
              <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={event => event.stopPropagation()}>
                <h3 className="text-base font-semibold text-red-700 dark:text-red-300 mb-2">{t('purge.confirmTitle')}</h3>
                <p className="text-sm text-slate-700 dark:text-slate-300 mb-4">{t('purge.confirmBody', { domain: expected })}</p>
                <label className="block text-xs text-slate-500 dark:text-slate-500 mb-1.5">
                  {t('purge.typeLabel')}<span className="font-mono font-semibold text-red-700 dark:text-red-300">{expected}</span>
                </label>
                <input
                  type="text"
                  autoFocus
                  value={purgeConfirmationText}
                  onChange={event => setPurgeConfirmationText(event.target.value)}
                  onKeyDown={event => { if (event.key === 'Enter' && confirmed && !isPurging) purgeMail() }}
                  placeholder={expected}
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 mb-4 focus:outline-none focus:ring-2 focus:ring-red-500" />
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={() => setPurgeConfirmOpen(false)}
                    className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('purge.cancel')}</button>
                  <button type="button" onClick={purgeMail} disabled={isPurging || !confirmed}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded font-medium">
                    {isPurging ? t('purge.working') : t('purge.confirm')}
                  </button>
                </div>
              </div>
            </div>
          )
        })()}

        <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('back')}</Link></div>
      </div>
    </div>
  )
}
