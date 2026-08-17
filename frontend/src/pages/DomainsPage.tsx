import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDomainRefusal } from '@/lib/domainRefusal'
import { useCopyOrOffer } from '@/lib/useCopyOrOffer'
import { useAuth } from '@/store/auth'
import { sslState } from '@/lib/ssl'
import Breadcrumb from '@/components/Breadcrumb'
import EmptyState from '@/components/EmptyState'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Domain = {
  id: number; domain_name: string; system_user: string
  size_kb: number; traffic_kb: number; status: string; suspended?: boolean
  php_version?: string; is_demo?: boolean
  created_at?: string; plan_id?: number; plan_name?: string
  ssl?: boolean; ssl_expiry?: string; ssl_source?: string; reseller_name?: string
}
type Customer = { id: number; name: string; owner_user_id?: number | null }
/** A row from GET /users, narrowed to what the owner picker needs. */
type PanelUser = { id: number; username: string; full_name?: string; role: string; status: string }
type Subdomain = {
  id: number; subdomain: string; fqdn: string
  parent_id: number; parent_name: string; system_user: string
  php_version: string; docroot: string; created_at: string
  ssl?: boolean; ssl_source?: string
}
type Plan = { id: number; name: string; disk_quota_mb?: number }
type PHPVer = { version: string }
type SiteType = 'php' | 'wordpress' | 'static'
type CreateResult = {
  id: number
  domain_name: string; system_user: string; ftp_user: string; ftp_host: string
  db_host: string; db_user: string; db_name: string
  site_type: SiteType
  created_passwords: { ftp: string; db: string }
  // Omitted by the backend when the server has no shared nameservers, because
  // the vanity values it would fall back to cannot be given to a customer; the
  // section is then not shown at all.
  nameservers?: { ns1: string; ns2: string }
  // A stable code naming something the create could not do. The domain itself
  // was created, so this is not an error; it is shown so a placement that did
  // not happen is never read as one that did.
  warning?: string
}

/**
 * The reason codes POST /domains refuses with, mapped to the key that words
 * each one. The mapping is explicit rather than derived from the code because
 * the codes are snake_case, which i18next reads as its plural and context
 * separator, and every other key in these files is camelCase.
 */
const CREATE_REFUSAL_KEYS: Record<string, string> = {
  customer_not_found: 'errors.customerNotFound',
  plan_not_found: 'errors.planNotFound',
  owner_not_reseller: 'errors.ownerNotReseller',
  owner_with_customer: 'errors.ownerWithCustomer',
  owner_not_allowed: 'errors.ownerNotAllowed',
}

function fmtKB(kb: number) {
  if (kb < 1024) return kb + ' KB'
  if (kb < 1024 * 1024) return (kb / 1024).toFixed(1) + ' MB'
  return (kb / 1024 / 1024).toFixed(2) + ' GB'
}

export default function DomainsPage() {
  const { t } = useTranslation('DomainsPage')
  const copyOrOffer = useCopyOrOffer()
  const domainRefusal = useDomainRefusal()
  const [items, setItems] = useState<Domain[]>([])
  const [subdomains, setSubdomains] = useState<Subdomain[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  // Subdomain ids live in their own set: they share the numeric id space with
  // domains, so one combined set would delete the wrong resource.
  const [selectedSubs, setSelectedSubs] = useState<Set<number>>(new Set())
  const [subDeleteOpen, setSubDeleteOpen] = useState(false)
  const [processing, setProcessing] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = useState(false)
  const [deleteConfirmationText, setDeleteConfirmationText] = useState('')
  const [ownerOpen, setOwnerOpen] = useState(false)
  const [ownerCustomers, setOwnerCustomers] = useState<Customer[]>([])
  const [ownerTarget, setOwnerTarget] = useState('')
  const isAdmin = useAuth((state) => state.username?.role) === 'admin'

  const [plans, setPlans] = useState<Plan[]>([])
  const [phpVersions, setPhpVersions] = useState<PHPVer[]>([])
  const [modalLoading, setModalLoading] = useState(false)
  const [modalReady, setModalReady] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  // Which of the create's three calls is running. Named stages rather than a
  // percentage: the server reports no progress, so a number would be invented.
  const [createStage, setCreateStage] = useState<'domain' | 'ssl' | 'redirect'>('domain')
  const [creationResult, setCreationResult] = useState<CreateResult | null>(null)
  // Whether an SSL installation was queued for the domain the result modal is
  // about. Kept apart from the form's checkbox so the modal reports the request
  // that was actually SENT rather than whatever the form happens to hold.
  const [sslQueued, setSslQueued] = useState(false)
  const [resultCopied, setResultCopied] = useState(false)
  const [formDomainName, setFormDomainName] = useState('')
  const [formPhpVersion, setFormPhpVersion] = useState('8.3')
  const [formSiteType, setFormSiteType] = useState<SiteType>('php')
  const [formPlanId, setFormPlanId] = useState<number | ''>('')
  // Who the domain belongs to. '' on the first means the administrator itself,
  // '' on the second means "open a new customer record". They are sent as
  // owner_user_id and customer_id, which the backend refuses TOGETHER, so at
  // most one of them ever leaves this form.
  const [formOwnerUserID, setFormOwnerUserID] = useState<number | ''>('')
  const [formCustomerID, setFormCustomerID] = useState<number | ''>('')
  const [createResellers, setCreateResellers] = useState<PanelUser[]>([])
  const [createCustomers, setCreateCustomers] = useState<Customer[]>([])
  const [formIssueSSL, setFormIssueSSL] = useState(false)
  const [formWWWRedirect, setFormWWWRedirect] = useState<'off' | 'to_www' | 'to_apex'>('off')

  // The domain list depends only on /domains. /plans and /php/versions (which can be
  // slow due to dnf discovery) are loaded lazily when the create modal opens.
  // The list renders as soon as domains arrive and never blocks on dnf.
  // Split so the mount effect never writes state synchronously: fetchDomains
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  // Returns a promise so a caller can wait for the refresh it asked for; the
  // refresh button uses it to know when to stop being disabled.
  const fetchDomains = useCallback(() => {
    const domains = api.get<Domain[]>('/domains')
      .then(r => setItems(r.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
    // Subdomains render nested under their parent. The endpoint is administrator-only,
    // so a customer session simply shows no nested rows instead of an error.
    const subs = api.get<Subdomain[]>('/subdomains')
      .then(r => setSubdomains(r.data))
      .catch(() => setSubdomains([]))
    return Promise.all([domains, subs])
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    fetchDomains()
  }, [fetchDomains])

  useEffect(() => { fetchDomains() }, [fetchDomains])

  // Load plans and PHP versions for the create modal separately from the list load.
  // Called lazily when the modal first opens; cached after the first successful fetch.
  function loadModalData() {
    if (modalReady || modalLoading) return
    setModalLoading(true)
    Promise.all([
      api.get<Plan[]>('/plans').catch(() => ({ data: [] })),
      api.get<PHPVer[]>('/php/versions').catch(() => ({ data: [] })),
      // Only an administrator can name an owner, so only an administrator pays
      // for these two requests. A reseller is never offered the field: it must
      // already name one of its own customers, and the server enforces that.
      isAdmin ? api.get<PanelUser[]>('/users').catch(() => ({ data: [] })) : Promise.resolve({ data: [] }),
      isAdmin ? api.get<Customer[]>('/customers').catch(() => ({ data: [] })) : Promise.resolve({ data: [] }),
    ]).then(([plansResponse, phpVersionsResponse, usersResponse, customersResponse]) => {
      const pl = plansResponse.data as Plan[]
      setPlans(pl)
      setPhpVersions(phpVersionsResponse.data as PHPVer[])
      // Only an ACTIVE reseller can own a customer; the server refuses anything
      // else, so offering it here would only produce a rejected create.
      setCreateResellers((usersResponse.data as PanelUser[]).filter(u => u.role === 'reseller' && u.status === 'active'))
      setCreateCustomers(customersResponse.data as Customer[])
      setModalReady(true)
      // If no plan has been selected yet (modal opened before data arrived) pick the default.
      setFormPlanId(prev => {
        if (prev !== '') return prev
        const d = pl.find(p => p.name === 'Starter') || pl[0]
        return d ? d.id : ''
      })
    }).finally(() => setModalLoading(false))
  }

  function openCreate() {
    setError(null); setSuccess(null); setCreationResult(null); setSslQueued(false)
    // Default plan = "Starter" (if data has already arrived, pick it now; otherwise
    // loadModalData sets it once the fetch completes).
    const defaultPlan = plans.find(plan => plan.name === 'Starter') || plans[0]
    setFormDomainName(''); setFormPhpVersion('8.3'); setFormSiteType('php'); setFormPlanId(defaultPlan ? defaultPlan.id : ''); setFormIssueSSL(false); setFormWWWRedirect('off')
    setFormOwnerUserID(''); setFormCustomerID('')
    setCreateOpen(true)
    loadModalData() // lazy: fetch plans/php versions if they haven't been loaded yet
  }

  async function submitCreate(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const domainName = formDomainName.trim().toLowerCase()
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domainName)) {
      setError(t('errors.invalidDomain'))
      return
    }
    setCreating(true)
    setCreateStage('domain')
    try {
      const request: {
        domain_name: string; php_version: string; site_type: SiteType
        plan_id?: number; customer_id?: number; owner_user_id?: number
      } = { domain_name: domainName, php_version: formPhpVersion, site_type: formSiteType }
      if (formPlanId !== '') request.plan_id = formPlanId
      // Never both: naming an existing customer already fixes the owner, and the
      // server refuses the pair rather than guessing which one was meant.
      if (formCustomerID !== '') request.customer_id = formCustomerID
      else if (formOwnerUserID !== '') request.owner_user_id = formOwnerUserID
      const response = await api.post<CreateResult>('/domains', request)
      // Refresh the list HERE, before the steps that follow. The domain exists
      // the moment this POST returns, but the refresh used to sit at the very
      // bottom, so the list stayed stale for as long as the canonical-hostname
      // call took. Silent, because the table is already populated and emptying
      // it for a moment reads as the domain having vanished.
      fetchDomains()
      let successMsg = t('toast.created', { name: domainName })
      try {
        if (formIssueSSL) {
          setCreateStage('ssl')
          try {
            // The endpoint answers 202 and installs in the background: two ACME
            // orders with a per-name pre-flight run for minutes. So this can only
            // report that the work STARTED. What was actually installed, and
            // whether it fell back to a self-signed certificate, is on the
            // domain's SSL page, which polls the progress endpoint.
            await api.post(`/domains/${response.data.id}/ssl/issue`, { type: 'letsencrypt' })
            setSslQueued(true)
            successMsg += t('toast.sslStarted')
          } catch {
            successMsg += t('toast.sslNotStarted')
          }
        }
        // After SSL, but note that SSL has only been QUEUED at this point, so the
        // certificate that would name the canonical hostname does not exist yet
        // and the backend's certificate check cannot run. What still protects the
        // site is the DNS check: a target that does not resolve here is refused,
        // and the reason is surfaced verbatim so the operator can fix it and retry
        // from the domain's page.
        if (formWWWRedirect !== 'off') {
          setCreateStage('redirect')
          try {
            await api.put(`/domains/${response.data.id}/www-redirect`, { mode: formWWWRedirect })
            successMsg += t('toast.wwwRedirectSet')
          } catch (error) {
            successMsg += t('toast.wwwRedirectFailed', { reason: apiError(error, '') })
          }
        }
      } finally {
        // The form stays open until here so the operator watches the work
        // finish instead of reading "ready" while the canonical hostname is
        // still being written and its outcome lands in a toast behind the
        // result. A finally rather than the tail of the try because the
        // passwords are shown ONCE: whatever went wrong above, they still have
        // to be handed over.
        setCreateOpen(false)
        setCreationResult(response.data)
      }
      setSuccess(successMsg)
      setTimeout(() => setSuccess(null), 10000)
      // The canonical hostname is stored on the domain row, so pick it up. Still
      // silent, for the same reason as above.
      if (formWWWRedirect !== 'off') fetchDomains()
    } catch (error) {
      // A refused create answers with a stable CODE rather than a sentence: the
      // API is English and the interface ships twelve languages, so wording
      // produced on the server could not be translated. Anything that is not one
      // of these codes is passed through as the server wrote it.
      const key = CREATE_REFUSAL_KEYS[apiError(error, '')]
      setError(key ? t(key) : domainRefusal(error, t('errors.createFailed')))
    } finally {
      setCreating(false)
    }
  }

  // The passwords in this modal are shown once and never again, so the whole set
  // has to leave the screen in one action. Both buttons render the same text, so
  // a copy and a downloaded file cannot disagree.
  function resultText(result: CreateResult) {
    return [
      `Servika - ${result.domain_name}`,
      '',
      t('resultModal.ftp'),
      `  ${t('resultModal.host')}: ${result.ftp_host || '-'}`,
      `  ${t('resultModal.username')}: ${result.ftp_user}`,
      `  ${t('resultModal.password')}: ${result.created_passwords.ftp}`,
      '',
      // Mirrors the modal: a static site was given no database, and listing an
      // empty one here would contradict what the screen showed.
      ...(result.site_type !== 'static' ? [
        t('resultModal.mysql'),
        `  ${t('resultModal.host')}: ${result.db_host || 'localhost'}`,
        `  ${t('resultModal.database')}: ${result.db_name}`,
        `  ${t('resultModal.username')}: ${result.db_user}`,
        `  ${t('resultModal.password')}: ${result.created_passwords.db}`,
        '',
      ] : []),
      ...(result.nameservers ? [
        t('resultModal.nameservers'),
        `  NS1: ${result.nameservers.ns1}`,
        `  NS2: ${result.nameservers.ns2}`,
        `  ${t('resultModal.nameserversNote')}`,
        '',
      ] : []),
      `${t('resultModal.systemUser')}${result.system_user}`,
    ].join('\n')
  }

  function downloadResultText(result: CreateResult) {
    const url = URL.createObjectURL(new Blob([resultText(result)], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `${result.domain_name}-credentials.txt`
    // Safari only honours a download from an anchor that is in the document, and
    // revoking the object URL in the same tick can cancel the transfer, so the
    // anchor is attached for the click and the URL is released on the next tick.
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  // Subdomains grouped by parent domain id so each domain row can render its own
  // nested children without rescanning the flat list for every row.
  const subdomainsByParent = useMemo(() => {
    const grouped = new Map<number, Subdomain[]>()
    for (const sub of subdomains) {
      const bucket = grouped.get(sub.parent_id)
      if (bucket) bucket.push(sub)
      else grouped.set(sub.parent_id, [sub])
    }
    return grouped
  }, [subdomains])

  // A domain stays visible when its own name or user matches, or when any of its
  // subdomains match, so searching for a subdomain still reveals it in place.
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return items
    const parentsWithMatchingSubdomain = new Set(
      subdomains.filter(sub => sub.fqdn.toLowerCase().includes(normalizedQuery)).map(sub => sub.parent_id),
    )
    return items.filter(domain => domain.domain_name.toLowerCase().includes(normalizedQuery)
      || domain.system_user.toLowerCase().includes(normalizedQuery)
      || parentsWithMatchingSubdomain.has(domain.id))
  }, [items, subdomains, query])

  // The customers the chosen owner already has. An unowned customer belongs
  // directly to the administrator, which is what the default selection means, so
  // the same filter serves both halves of the picker.
  const ownerCustomerChoices = useMemo(
    () => createCustomers.filter(customer => (formOwnerUserID === ''
      ? customer.owner_user_id === null || customer.owner_user_id === undefined
      : customer.owner_user_id === formOwnerUserID)),
    [createCustomers, formOwnerUserID],
  )

  function toggleSelection(id: number) {
    setSelected(prev => {
      const nextSelection = new Set(prev)
      if (nextSelection.has(id)) nextSelection.delete(id); else nextSelection.add(id)
      return nextSelection
    })
  }
  function selectAllItems(shouldSelect: boolean) {
    if (shouldSelect) setSelected(new Set(filtered.map(d => d.id)))
    else setSelected(new Set())
  }

  // The customer list is already scoped by the server: GET /customers returns a
  // reseller only its own, so the picker cannot offer a customer the transfer
  // would be refused for.
  function openOwnerDialog() {
    setOwnerTarget('')
    setOwnerOpen(true)
    api.get<Customer[]>('/customers')
      .then(response => setOwnerCustomers(response.data || []))
      .catch(cause => setError(apiError(cause, t('owner.loadFailed'))))
  }

  async function changeOwner() {
    setOwnerOpen(false); setProcessing(true); setError(null)
    const ids = Array.from(selected)
    try {
      // An empty selection detaches the domains, which the server allows only for
      // an administrator; the option is hidden from anyone else.
      const response = await api.post<{ updated: number }>('/domains/bulk/owner', {
        ids, customer_id: ownerTarget === '' ? null : Number(ownerTarget),
      })
      setSelected(new Set())
      setSuccess(t('toast.ownerChanged', { count: response.data.updated }))
      setTimeout(() => setSuccess(null), 4000)
    } catch (cause) {
      setError(apiError(cause, t('owner.failed')))
    } finally {
      setProcessing(false); load()
    }
  }

  async function bulkDelete() {
    setDeleteConfirmationOpen(false); setDeleteConfirmationText(''); setProcessing(true); setError(null)
    const ids = Array.from(selected); let successCount = 0
    for (const id of ids) {
      // One domain failing must not abandon the rest; the toast below reports the
      // successful count against the total, so failures stay visible.
      try { await api.delete(`/domains/${id}`); successCount++ } catch { /* counted as a failure */ }
    }
    setSelected(new Set()); setSuccess(t('toast.deleted', { success: successCount, total: ids.length }))
    setTimeout(() => setSuccess(null), 4000)
    setProcessing(false); load()
  }

  function toggleSubSelection(id: number) {
    setSelectedSubs(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  // Each subdomain is deleted through its own endpoint rather than a new bulk one:
  // a delete already removes the vhost, the DNS record, the certificate and the
  // document root, so the sequence is the same work either way.
  async function bulkDeleteSubdomains() {
    setSubDeleteOpen(false); setProcessing(true); setError(null)
    const targets = subdomains.filter(sub => selectedSubs.has(sub.id))
    let successCount = 0
    for (const sub of targets) {
      // One failure must not abandon the rest; the toast reports the successful
      // count against the total, so failures stay visible.
      try { await api.delete(`/domains/${sub.parent_id}/subdomain/${sub.id}`); successCount++ } catch { /* counted as a failure */ }
    }
    setSelectedSubs(new Set())
    setSuccess(t('toast.subdomainsDeleted', { success: successCount, total: targets.length }))
    setTimeout(() => setSuccess(null), 4000)
    setProcessing(false); load()
  }

  async function changeStatus(newStatus: 'active' | 'passive') {
    setProcessing(true); setError(null)
    const ids = Array.from(selected)
    try {
      await api.post('/domains/bulk/status', { ids, status: newStatus })
      setSuccess(t('toast.statusChanged', { count: ids.length, status: newStatus }))
      setTimeout(() => setSuccess(null), 4000)
      setSelected(new Set()); load()
    } catch (error) { setError(apiError(error, t('errors.statusFailed'))) }
    finally { setProcessing(false) }
  }

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains') }]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        {t('subtitle')}
      </p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {/* Toolbar */}
      <div className="flex flex-col gap-2 mb-3 sm:flex-row sm:items-center sm:flex-wrap">
        <div className="w-full sm:max-w-md sm:flex-1">
          <input type="text" value={query} onChange={e => setQuery(e.target.value)}
            placeholder={t('searchPlaceholder')}
            className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 outline-none" />
        </div>
        <span className="text-xs text-slate-500 dark:text-slate-500">{filtered.length} / {items.length}</span>
        {/* Provisioning finishes work after the create call returns: the SSL job
            runs in the background for minutes, so a domain's SSL badge appears
            long after its row does. Without this the only way to see it was to
            reload the page. Silent, so the table does not empty while it runs. */}
        <button onClick={() => { setRefreshing(true); fetchDomains().finally(() => setRefreshing(false)) }}
          disabled={refreshing}
          className="px-3 py-1.5 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm rounded-md">
          {t('actions.refresh')}
        </button>
        <button onClick={openCreate}
          className="inline-flex items-center justify-center gap-1.5 text-sm px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-md font-medium shadow-sm sm:ml-auto">
          <span className="text-base leading-none">+</span> {t('newDomain')}
        </button>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-md flex items-center gap-2 flex-wrap">
          <span className="text-sm font-semibold text-amber-800 dark:text-amber-200">{t('bulk.selected', { count: selected.size })}</span>
          <button onClick={() => changeStatus('active')} disabled={processing}
            className="text-xs px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded">
            {t('bulk.activate')}
          </button>
          <button onClick={() => changeStatus('passive')} disabled={processing}
            className="text-xs px-3 py-1.5 bg-slate-600 hover:bg-slate-700 text-white rounded">
            {t('bulk.deactivate')}
          </button>
          <button onClick={() => { setDeleteConfirmationText(''); setDeleteConfirmationOpen(true) }} disabled={processing}
            className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">
            {t('bulk.delete', { count: selected.size })}
          </button>
          <button onClick={openOwnerDialog} disabled={processing}
            className="text-xs px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded">
            {t('bulk.changeOwner')}
          </button>
          <button onClick={() => setSelected(new Set())} disabled={processing}
            className="text-xs px-3 py-1.5 border border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-200 hover:bg-amber-100 dark:bg-amber-900/30 rounded">
            {t('bulk.clear')}
          </button>
        </div>
      )}

      {selectedSubs.size > 0 && (
        <div className="mb-3 px-3 py-2 bg-sky-50 dark:bg-sky-900/20 border border-sky-300 dark:border-sky-700 rounded-md flex items-center gap-2 flex-wrap">
          <span className="text-sm font-semibold text-sky-800 dark:text-sky-200">{t('bulkSub.selected', { count: selectedSubs.size })}</span>
          <button onClick={() => setSubDeleteOpen(true)} disabled={processing}
            className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">
            {t('bulkSub.delete', { count: selectedSubs.size })}
          </button>
          <button onClick={() => setSelectedSubs(new Set())} disabled={processing}
            className="text-xs px-3 py-1.5 border border-sky-300 dark:border-sky-700 text-sky-800 dark:text-sky-200 hover:bg-sky-100 dark:bg-sky-900/30 rounded">
            {t('bulk.clear')}
          </button>
        </div>
      )}

      {loading ? (
        <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
      ) : items.length === 0 ? (
        <EmptyState title={t('empty.title')}
          description={t('empty.description')}
          button={{ label: t('empty.button'), onClick: openCreate }} />
      ) : (
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="px-3 py-2.5 w-10 text-center">
                  <input type="checkbox"
                    checked={filtered.length > 0 && selected.size === filtered.length}
                    ref={ref => { if (ref) ref.indeterminate = selected.size > 0 && selected.size < filtered.length }}
                    onChange={e => selectAllItems(e.target.checked)}
                    className="cursor-pointer" />
                </th>
                <th className="text-left px-4 py-2.5">{t('columns.domainName')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.systemUser')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.plan')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.php')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.disk')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.status')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.created')}</th>
                <th className="text-right px-4 py-2.5">{t('columns.actions')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {filtered.map(d => {
                const children = subdomainsByParent.get(d.id) || []
                return (
                  <Fragment key={d.id}>
                  <tr className={`${responsiveTableRowClass} ${selected.has(d.id) ? 'bg-brand-50 dark:bg-brand-900/20' : ''}`}>
                    <td className={responsiveTableCellClass}>
                      <input type="checkbox" checked={selected.has(d.id)}
                        onChange={() => toggleSelection(d.id)} className="cursor-pointer" />
                    </td>
                    <td data-label={t('columns.domainName')} className={responsiveTableCellClass}>
                      <div className="text-right lg:text-left">
                        <Link to={`/subscriptions/${d.id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">
                          {d.domain_name}
                        </Link>
                        {' '}
                        <a href={`https://${d.domain_name}`} target="_blank" rel="noopener noreferrer" title={t('openInNewTab')} className="text-slate-400 dark:text-slate-500 hover:text-brand-500 dark:hover:text-brand-400 text-xs">↗</a>
                        <SslPill
                          enabled={d.ssl}
                          source={d.ssl_source}
                          trustedTitle={d.ssl_expiry ? t('sslExpires', { date: d.ssl_expiry }) : t('sslActive')}
                          selfSignedTitle={t('sslSelfSigned')}
                        />
                        {d.is_demo && <span className="ml-1.5 text-[10px] uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 rounded">{t('demoBadge')}</span>}
                      </div>
                    </td>
                    <td data-label={t('columns.systemUser')} className={responsiveTableCodeCellClass}>
                      {d.system_user}
                      {d.reseller_name && <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">{t('reseller', { name: d.reseller_name })}</div>}
                    </td>
                    <td data-label={t('columns.plan')} className={responsiveTableCellClass}>
                      {d.plan_name ? <span className="text-slate-700 dark:text-slate-300">{d.plan_name}</span> : <span className="text-slate-400 dark:text-slate-500 italic">{t('noPlan')}</span>}
                    </td>
                    <td data-label={t('columns.php')} className={responsiveTableCodeCellClass}>{d.php_version || '-'}</td>
                    <td data-label={t('columns.disk')} className={responsiveTableCodeCellClass}>{fmtKB(d.size_kb)}</td>
                    <td data-label={t('columns.status')} className={responsiveTableCellClass}>
                      <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded font-semibold ${
                        d.status === 'active' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-500'
                      }`}>{d.status}</span>
                    </td>
                    <td data-label={t('columns.created')} className={responsiveTableCodeCellClass}>{d.created_at || '-'}</td>
                    <td className={responsiveTableActionCellClass}>
                      <Link to={`/subscriptions/${d.id}/subdomains`} className="text-xs text-slate-500 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400">{t('addSubdomain')}</Link>
                      <Link to={`/subscriptions/${d.id}`} className="text-xs text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300">{t('manage')}</Link>
                    </td>
                  </tr>
                  {children.map(sub => (
                    <tr key={`s${sub.id}`} className={`${responsiveTableRowClass} bg-slate-50/60 dark:bg-slate-900/30`}>
                      <td className={responsiveTableCellClass}>
                        <input type="checkbox" checked={selectedSubs.has(sub.id)}
                          onChange={() => toggleSubSelection(sub.id)}
                          aria-label={t('bulkSub.selectOne', { name: sub.fqdn })}
                          className="rounded border-slate-300 dark:border-slate-600" />
                      </td>
                      <td data-label={t('columns.domainName')} className={responsiveTableCellClass}>
                        <div className="text-right lg:text-left lg:pl-5">
                          <span className="text-slate-300 dark:text-slate-600 mr-1 hidden lg:inline">└</span>
                          <Link to={`/domains/${d.id}/subdomain/${sub.id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">
                            {sub.fqdn}
                          </Link>
                          {/* The type badge stays. On the stacked mobile layout
                              there is no indent to read the nesting from, so
                              removing it to make room would cost the one thing
                              that says what this row is. */}
                          <span className="ml-2 text-[10px] uppercase tracking-wider bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded">{t('subdomain')}</span>
                          <SslPill
                            enabled={sub.ssl}
                            source={sub.ssl_source}
                            trustedTitle={t('sslActive')}
                            selfSignedTitle={t('sslSelfSigned')}
                          />
                        </div>
                      </td>
                      <td data-label={t('columns.systemUser')} className={responsiveTableCodeCellClass}>{sub.system_user}</td>
                      <td data-label={t('columns.plan')} className={responsiveTableCellClass}>
                        <span className="text-slate-400 dark:text-slate-500 italic">{t('subdomainParentPlan')}</span>
                      </td>
                      <td data-label={t('columns.php')} className={responsiveTableCodeCellClass}>{sub.php_version || '-'}</td>
                      <td data-label={t('columns.disk')} className={responsiveTableCodeCellClass}>-</td>
                      <td data-label={t('columns.status')} className={responsiveTableCellClass}>
                        <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded font-semibold bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400">{t('subdomainStatus')}</span>
                      </td>
                      <td data-label={t('columns.created')} className={responsiveTableCodeCellClass}>{sub.created_at || '-'}</td>
                      <td className={responsiveTableActionCellClass}>
                        <Link to={`/domains/${d.id}/subdomain/${sub.id}`} className="text-xs text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">{t('manage')}</Link>
                      </td>
                    </tr>
                  ))}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Domain creation modal */}
      {createOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => !creating && setCreateOpen(false)}>
          <form onSubmit={submitCreate} className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-lg p-5 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('createModal.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-4">
              {t('createModal.subtitle')}
            </p>

            {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('createModal.domainName')} <span className="text-red-500">*</span></label>
                <input
                  type="text"
                  value={formDomainName}
                  onChange={e => setFormDomainName(e.target.value)}
                  placeholder={t('createModal.domainNamePlaceholder')}
                  autoFocus
                  required
                  disabled={creating}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/15 outline-none"
                />
                <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">{t('createModal.domainNameHintPre')}<span className="font-mono">{t('createModal.domainNameHintExample1')}</span>{t('createModal.domainNameHintMid')}<span className="font-mono">{t('createModal.domainNameHintExample2')}</span>.</div>
              </div>

              {/* Placed before the PHP version because it decides whether a
                  database is opened at all, and that choice is easy to regret
                  quietly: nothing fails until the site first tries to connect. */}
              <div>
                <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('createModal.siteType')}</span>
                <div className="space-y-1.5">
                  {(['php', 'wordpress', 'static'] as const).map(type => (
                    <label key={type} className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="site-type"
                        value={type}
                        checked={formSiteType === type}
                        onChange={() => setFormSiteType(type)}
                        disabled={creating}
                        className="mt-0.5"
                      />
                      <span>
                        <span className="block text-sm text-slate-700 dark:text-slate-300">{t(`createModal.siteTypes.${type}`)}</span>
                        <span className={`block text-[11px] ${type === 'static' ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400 dark:text-slate-500'}`}>
                          {t(`createModal.siteTypeHints.${type}`)}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">
                  {t('createModal.phpVersion')}
                  {modalLoading && phpVersions.length === 0 && <span className="ml-2 text-[11px] text-slate-400 dark:text-slate-500">{t('createModal.loading')}</span>}
                </label>
                <select
                  value={formPhpVersion}
                  onChange={e => setFormPhpVersion(e.target.value)}
                  disabled={creating}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 outline-none bg-white dark:bg-slate-800"
                >
                  {phpVersions.length === 0
                    ? <option value="8.3">{t('createModal.phpDefault')}</option>
                    : phpVersions.map(p => (
                        <option key={p.version} value={p.version}>PHP {p.version}</option>
                      ))
                  }
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">
                  {t('createModal.servicePlan')}
                  {modalLoading && plans.length === 0 && <span className="ml-2 text-[11px] text-slate-400 dark:text-slate-500">{t('createModal.loading')}</span>}
                </label>
                <select
                  value={formPlanId}
                  onChange={e => setFormPlanId(e.target.value === '' ? '' : Number(e.target.value))}
                  disabled={creating}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 outline-none bg-white dark:bg-slate-800"
                >
                  <option value="">{t('createModal.planNone')}</option>
                  {plans.map(p => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>

              {/* Administrator only. A reseller must already name one of its own
                  customers, which the server verifies, so the field would offer
                  it nothing it is allowed to choose. */}
              {isAdmin && (
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">
                    {t('createModal.owner')}
                    {modalLoading && createResellers.length === 0 && <span className="ml-2 text-[11px] text-slate-400 dark:text-slate-500">{t('createModal.loading')}</span>}
                  </label>
                  <select
                    value={formOwnerUserID}
                    onChange={e => {
                      setFormOwnerUserID(e.target.value === '' ? '' : Number(e.target.value))
                      // The customer list below belongs to the previous owner, so
                      // keeping the choice would send a customer the new owner
                      // does not have.
                      setFormCustomerID('')
                    }}
                    disabled={creating}
                    className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 outline-none bg-white dark:bg-slate-800"
                  >
                    <option value="">{t('createModal.ownerAdmin')}</option>
                    {createResellers.map(reseller => (
                      <option key={reseller.id} value={reseller.id}>{reseller.full_name || reseller.username}</option>
                    ))}
                  </select>
                  <select
                    value={formCustomerID}
                    onChange={e => setFormCustomerID(e.target.value === '' ? '' : Number(e.target.value))}
                    disabled={creating}
                    className="mt-2 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm focus:border-brand-500 outline-none bg-white dark:bg-slate-800"
                  >
                    <option value="">{t('createModal.customerNew')}</option>
                    {ownerCustomerChoices.map(customer => (
                      <option key={customer.id} value={customer.id}>{customer.name}</option>
                    ))}
                  </select>
                  <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">{t('createModal.ownerHint')}</div>
                </div>
              )}
            </div>

            <div className="mt-4">
              <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300 cursor-pointer">
                <input type="checkbox" checked={formIssueSSL} onChange={e => setFormIssueSSL(e.target.checked)} disabled={creating} className="rounded" />
                {t('createModal.issueSsl')}
              </label>
              {formIssueSSL && (
                <p className="mt-1.5 text-[11px] text-amber-600 dark:text-amber-400">
                  {t('createModal.sslWarning')}
                </p>
              )}
              <label className="block mt-3">
                <span className="text-sm text-slate-600 dark:text-slate-300">{t('createModal.wwwRedirect')}</span>
                <select value={formWWWRedirect} onChange={e => setFormWWWRedirect(e.target.value as 'off' | 'to_www' | 'to_apex')} disabled={creating}
                  className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
                  <option value="off">{t('createModal.wwwRedirectOff')}</option>
                  <option value="to_www">{t('createModal.wwwRedirectToWww')}</option>
                  <option value="to_apex">{t('createModal.wwwRedirectToApex')}</option>
                </select>
                {formWWWRedirect === 'to_www' && (
                  <span className="mt-1.5 block text-[11px] text-amber-600 dark:text-amber-400">{t('createModal.wwwRedirectWarning')}</span>
                )}
              </label>
            </div>

            {/* Named stages, no percentage: the server reports no progress for
                any of these calls, so a bar would be showing an invented
                number. */}
            {creating && (
              <div className="mt-4 flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                <svg className="animate-spin w-3 h-3 shrink-0" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.3"/>
                  <path d="M22 12a10 10 0 0 1-10 10" stroke="currentColor" strokeWidth="3"/>
                </svg>
                {t(`createModal.stages.${createStage}`)}
              </div>
            )}

            <div className="flex justify-end gap-2 mt-5">
              <button type="button" onClick={() => setCreateOpen(false)} disabled={creating}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('createModal.cancel')}</button>
              <button type="submit" disabled={creating || !formDomainName.trim()}
                className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded font-medium inline-flex items-center gap-2">
                {creating && (
                  <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.3"/>
                    <path d="M22 12a10 10 0 0 1-10 10" stroke="currentColor" strokeWidth="3"/>
                  </svg>
                )}
                {creating ? t('createModal.creating') : t('createModal.create')}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Creation result modal with FTP and database passwords */}
      {creationResult && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setCreationResult(null)}>
          <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-lg p-5 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-emerald-700 dark:text-emerald-300 mb-1">{t('resultModal.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-4">
              <span className="font-mono text-slate-700 dark:text-slate-300">{creationResult.domain_name}</span>{t('resultModal.readyPre')}<strong>{t('resultModal.readyBold')}</strong>{t('resultModal.readyPost')}
            </p>

            {/* The domain was created, so this is not an error. It is shown
                because the reseller the operator picked was NOT applied, and
                leaving that silent would report a placement that never
                happened. */}
            {creationResult.warning === 'owner_not_applied' && (
              <div className="mb-4 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-300">
                {t('resultModal.ownerNotApplied')}
              </div>
            )}

            <div className="space-y-3">
              <div className="border border-slate-200 dark:border-slate-700 rounded-md p-3 bg-slate-50 dark:bg-slate-900">
                <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold mb-2">{t('resultModal.ftp')}</div>
                <CopyRow label={t('resultModal.host')} value={creationResult.ftp_host || '-'} copy={copyOrOffer} />
                <CopyRow label={t('resultModal.username')} value={creationResult.ftp_user} copy={copyOrOffer} />
                <CopyRow label={t('resultModal.password')} value={creationResult.created_passwords.ftp} copy={copyOrOffer} password />
              </div>

              {/* A static site was given no database, so there is nothing to show.
                  Rendering the block with empty rows would read as a failure. */}
              {creationResult.site_type !== 'static' && (
                <div className="border border-slate-200 dark:border-slate-700 rounded-md p-3 bg-slate-50 dark:bg-slate-900">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold mb-2">{t('resultModal.mysql')}</div>
                  <CopyRow label={t('resultModal.host')} value={creationResult.db_host || 'localhost'} copy={copyOrOffer} />
                  <CopyRow label={t('resultModal.database')} value={creationResult.db_name} copy={copyOrOffer} />
                  <CopyRow label={t('resultModal.username')} value={creationResult.db_user} copy={copyOrOffer} />
                  <CopyRow label={t('resultModal.password')} value={creationResult.created_passwords.db} copy={copyOrOffer} password />
                </div>
              )}

              {/* The certificate is still being issued when this modal opens, and
                  it may end on the self-signed fail-safe. Neither outcome can be
                  reported here, so point at the SSL page, which polls the
                  progress endpoint and shows the steps and the fallback. */}
              {sslQueued && (
                <div className="border border-amber-200 dark:border-amber-800 rounded-md p-3 bg-amber-50 dark:bg-amber-900/20">
                  <div className="text-[10px] uppercase tracking-wider text-amber-700 dark:text-amber-300 font-semibold mb-2">{t('resultModal.ssl')}</div>
                  <p className="text-[11px] text-amber-800 dark:text-amber-300 mb-2">{t('resultModal.sslNote')}</p>
                  <Link
                    to={`/subscriptions/${creationResult.id}/ssl`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white text-sm rounded font-medium"
                  >
                    {t('resultModal.sslAction')}
                  </Link>
                </div>
              )}

              {/* WordPress needs a site title, an administrator name and an email
                  address, so the install cannot run from here. Point at the screen
                  that asks for them instead of leaving it to be found. */}
              {creationResult.site_type === 'wordpress' && (
                <div className="border border-sky-200 dark:border-sky-800 rounded-md p-3 bg-sky-50 dark:bg-sky-900/20">
                  <div className="text-[10px] uppercase tracking-wider text-sky-700 dark:text-sky-300 font-semibold mb-2">{t('resultModal.wordpress')}</div>
                  <p className="text-[11px] text-sky-800 dark:text-sky-300 mb-2">{t('resultModal.wordpressNote')}</p>
                  <Link
                    to={`/subscriptions/${creationResult.id}/wordpress`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white text-sm rounded font-medium"
                  >
                    {t('resultModal.wordpressAction')}
                  </Link>
                </div>
              )}

              {creationResult.nameservers && (
                <div className="border border-emerald-200 dark:border-emerald-800 rounded-md p-3 bg-emerald-50 dark:bg-emerald-900/20">
                  <div className="text-[10px] uppercase tracking-wider text-emerald-700 dark:text-emerald-300 font-semibold mb-2">{t('resultModal.nameservers')}</div>
                  <CopyRow label="NS1" value={creationResult.nameservers.ns1} copy={copyOrOffer} />
                  <CopyRow label="NS2" value={creationResult.nameservers.ns2} copy={copyOrOffer} />
                  <p className="text-[11px] text-emerald-800 dark:text-emerald-300 mt-2">{t('resultModal.nameserversNote')}</p>
                </div>
              )}

              <div className="text-[11px] text-slate-500 dark:text-slate-500 italic">
                {t('resultModal.systemUser')}<span className="font-mono">{creationResult.system_user}</span>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-5">
              <button onClick={async () => {
                  if (await copyOrOffer(resultText(creationResult))) {
                    setResultCopied(true)
                    setTimeout(() => setResultCopied(false), 1500)
                  }
                }}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 text-sm rounded">
                {resultCopied ? t('resultModal.copied') : t('resultModal.copyAll')}
              </button>
              <button onClick={() => downloadResultText(creationResult)}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 text-sm rounded">
                {t('resultModal.saveTxt')}
              </button>
              <button onClick={() => setCreationResult(null)}
                className="px-4 py-1.5 bg-slate-700 hover:bg-slate-800 text-white text-sm rounded">{t('resultModal.ok')}</button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk deletion confirmation */}
      {/* Subdomain bulk delete confirmation. No typed name is demanded here: unlike a
          domain this removes one document root and its vhost, not a whole tenant. */}
      {subDeleteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md bg-white dark:bg-slate-900 rounded-xl shadow-xl p-5">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('subDeleteConfirm.title')}</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">
              {t('subDeleteConfirm.message', { count: selectedSubs.size })}
            </p>
            <ul className="mb-4 max-h-40 overflow-y-auto text-sm text-slate-700 dark:text-slate-300 space-y-0.5">
              {subdomains.filter(sub => selectedSubs.has(sub.id)).slice(0, 8).map(sub => (
                <li key={sub.id} className="font-mono text-xs">{sub.fqdn}</li>
              ))}
              {selectedSubs.size > 8 && (
                <li className="text-slate-400 dark:text-slate-500 italic">{t('deleteConfirm.moreItems', { count: selectedSubs.size - 8 })}</li>
              )}
            </ul>
            <div className="flex justify-end gap-2">
              <button onClick={() => setSubDeleteOpen(false)} disabled={processing}
                className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300">
                {t('subDeleteConfirm.cancel')}
              </button>
              <button onClick={bulkDeleteSubdomains} disabled={processing}
                className="px-3 py-1.5 text-sm rounded bg-red-600 hover:bg-red-700 text-white font-medium disabled:opacity-50">
                {processing ? t('subDeleteConfirm.working') : t('subDeleteConfirm.confirm')}
              </button>
            </div>
          </div>
        </div>
      )}

      {ownerOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setOwnerOpen(false)}>
          <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('owner.title')}</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">{t('owner.description', { count: selected.size })}</p>
            <select value={ownerTarget} onChange={e => setOwnerTarget(e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm mb-2">
              <option value="">{isAdmin ? t('owner.none') : t('owner.choose')}</option>
              {ownerCustomers.map(customer => (
                <option key={customer.id} value={customer.id}>{customer.name}</option>
              ))}
            </select>
            {/* Leaving the picker empty is a real action, not a cancel: it takes
                the domain out of every customer's hands and back to admin. */}
            {isAdmin && <p className="text-xs text-amber-700 dark:text-amber-400 mb-4">{t('owner.noneWarning')}</p>}
            <div className="flex justify-end gap-2">
              <button onClick={() => setOwnerOpen(false)}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('owner.cancel')}</button>
              <button onClick={changeOwner} disabled={processing || (!isAdmin && ownerTarget === '')}
                className="px-3 py-1.5 bg-sky-600 hover:bg-sky-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded font-medium">
                {t('owner.confirm')}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteConfirmationOpen && (() => {
        const selectedId = selected.size === 1 ? Array.from(selected)[0] : undefined
        const selectedDomain = selectedId !== undefined ? items.find(x => x.id === selectedId)?.domain_name : undefined
        const expectedConfirmationText = selectedDomain || 'DELETE'
        const deletionConfirmed = deleteConfirmationText === expectedConfirmationText
        return (
          <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setDeleteConfirmationOpen(false)}>
            <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
              <h3 className="text-base font-semibold text-red-700 dark:text-red-300 mb-2">{t('deleteConfirm.title')}</h3>
              <p className="text-sm text-slate-700 dark:text-slate-300 mb-3">
                <span className="font-semibold">{selected.size}</span>{t('deleteConfirm.messageMid')}<strong>{t('deleteConfirm.messageBold')}</strong>{t('deleteConfirm.messagePost')}
              </p>
              <ul className="text-xs font-mono text-slate-500 dark:text-slate-500 bg-slate-50 dark:bg-slate-900 rounded p-2 max-h-40 overflow-auto mb-4">
                {Array.from(selected).slice(0, 8).map(id => {
                  const d = items.find(x => x.id === id)
                  return <li key={id} className="truncate">{d?.domain_name || '?'}</li>
                })}
                {selected.size > 8 && <li className="text-slate-400 dark:text-slate-500 italic">{t('deleteConfirm.moreItems', { count: selected.size - 8 })}</li>}
              </ul>
              <label className="block text-xs text-slate-500 dark:text-slate-500 mb-1.5">
                {t('deleteConfirm.typeLabel')}<span className="font-mono font-semibold text-red-700 dark:text-red-300">{expectedConfirmationText}</span>{t('deleteConfirm.typeSuffix')}
              </label>
              <input
                type="text"
                autoFocus
                value={deleteConfirmationText}
                onChange={e => setDeleteConfirmationText(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && deletionConfirmed && !processing) bulkDelete() }}
                placeholder={expectedConfirmationText}
                autoComplete="off"
                spellCheck={false}
                className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 mb-4 focus:outline-none focus:ring-2 focus:ring-red-500"
              />
              <div className="flex justify-end gap-2">
                <button onClick={() => setDeleteConfirmationOpen(false)}
                  className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('deleteConfirm.cancel')}</button>
                <button onClick={bulkDelete} disabled={processing || !deletionConfirmed}
                  className="px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded font-medium">
                  {t('deleteConfirm.confirm')}
                </button>
              </div>
            </div>
          </div>
        )
      })()}
    </div>
  )
}

/**
 * The certificate pill drawn beside a name in the domain table.
 *
 * Shared between the domain row and the subdomain row nested under it because
 * they are the same pill in the same table, and two copies would let a
 * correction reach one and miss the other. It is local to this page rather than
 * a component of its own: the other screens that report SSL draw a lock icon, a
 * tool card and a table cell instead, so they share the decision in lib/ssl.ts
 * and nothing else.
 *
 * Amber, not green, for the self-signed fail-safe: it encrypts and still leaves
 * the visitor on a full-page browser warning, so the site is effectively shut.
 */
function SslPill({ enabled, source, trustedTitle, selfSignedTitle }: {
  enabled?: boolean; source?: string; trustedTitle: string; selfSignedTitle: string
}) {
  const state = sslState(enabled, source)
  if (state === 'none') return null
  const trusted = state === 'trusted'
  return (
    <span
      title={trusted ? trustedTitle : selfSignedTitle}
      className={`ml-1.5 text-[10px] font-semibold px-1.5 py-0.5 rounded ${trusted
        ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300'
        : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300'}`}
    >
      SSL
    </span>
  )
}

function CopyRow({ label, value, copy, password }: { label: string; value: string; copy: (text: string) => Promise<boolean>; password?: boolean }) {
  const { t } = useTranslation('DomainsPage')
  const [copied, setCopied] = useState(false)
  const [visible, setVisible] = useState(!password)
  async function handleClick() {
    const ok = await copy(value)
    if (ok) { setCopied(true); setTimeout(() => setCopied(false), 1500) }
  }
  return (
    <div className="flex items-center gap-2 text-xs py-1">
      <span className="w-24 text-slate-500 dark:text-slate-500 shrink-0">{label}</span>
      <code
        onClick={handleClick}
        className={`flex-1 font-mono px-2 py-1 rounded border cursor-pointer select-all transition ${
          copied ? 'border-emerald-300 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300' : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:border-brand-400 text-slate-800 dark:text-slate-200'
        }`}
        title={t('copyRow.clickToCopy')}
      >
        {password && !visible ? t('copyRow.hidden') : value}
      </code>
      {password && (
        <button type="button" onClick={() => setVisible(s => !s)}
          className="text-[10px] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800">
          {visible ? t('copyRow.hide') : t('copyRow.show')}
        </button>
      )}
      {copied && <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">{t('copyRow.copied')}</span>}
    </div>
  )
}