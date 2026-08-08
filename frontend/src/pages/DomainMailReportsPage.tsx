import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'

type Domain = { id: number; domain_name: string }

type Status = {
  report_address: string
  mailbox_local: string
  mailbox_exists: boolean
  last_scan_at: string
  last_error: string
  dmarc_report_ct: number
  tlsrpt_ct: number
}

type Source = {
  source_ip: string
  messages: number
  dkim_pass: number
  spf_pass: number
  quarantined: number
  rejected: number
  header_froms: string
  reporter: string
}

type TLSBucket = { result_type: string; receiving_mx: string; session_count: number }
type TLSReport = { org_name: string; date_begin: string; success_count: number; failure_count: number }
type TLSSummary = {
  success_count: number
  failure_count: number
  failures: TLSBucket[]
  reports: TLSReport[]
}

type MTASTS = {
  mode: string
  policy_id?: string
  changed_at?: string
  mx_hosts: string[]
  dns_ready: boolean
  cert_ready: boolean
  enforce_blocked: boolean
  enforce_reason?: string
}

type Tab = 'dmarc' | 'tlsrpt' | 'mtasts'

// The server sends a stable reason CODE, never a sentence, so the lock can be
// explained in the reader's own language. The table is explicit rather than
// derived from the code, because a code added later would otherwise become a
// translation key that does not exist and render as its own name everywhere.
const ENFORCE_REASONS: Record<string, string> = {
  not_testing: 'mtasts.reasons.notTesting',
  soak_incomplete: 'mtasts.reasons.soakIncomplete',
  mx_certificate_missing: 'mtasts.reasons.mxCertificateMissing',
}

const WINDOWS = [7, 30, 90]

function percent(part: number, whole: number): string {
  if (whole <= 0) return '0%'
  return `${Math.round((part / whole) * 100)}%`
}

export default function DomainMailReportsPage() {
  const { t } = useTranslation('DomainMailReportsPage')
  const { notify, confirm } = useDialog()
  const { id } = useParams()

  const [domain, setDomain] = useState<Domain | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [sources, setSources] = useState<Source[]>([])
  const [tls, setTLS] = useState<TLSSummary | null>(null)
  const [mtasts, setMTASTS] = useState<MTASTS | null>(null)
  const [tab, setTab] = useState<Tab>('dmarc')
  const [days, setDays] = useState(30)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchAll
  // settles only through promise callbacks, and reload() adds the spinner for
  // the refreshes that follow a write.
  const fetchAll = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<Domain>(`/domains/${id}`),
      api.get<Status>(`/domains/${id}/mail-reports`),
      api.get<{ sources: Source[] }>(`/domains/${id}/mail-reports/dmarc?days=${days}`),
      api.get<{ summary: TLSSummary }>(`/domains/${id}/mail-reports/tlsrpt?days=${days}`),
      api.get<MTASTS>(`/domains/${id}/mail-mtasts`),
    ])
      .then(([domainResponse, statusResponse, dmarcResponse, tlsResponse, mtastsResponse]) => {
        setDomain(domainResponse.data)
        setStatus(statusResponse.data)
        setSources(dmarcResponse.data.sources || [])
        setTLS(tlsResponse.data.summary)
        setMTASTS(mtastsResponse.data)
        setError(null)
      })
      .catch(cause => setError(apiError(cause, t('errors.loadFailed'))))
      .finally(() => setLoading(false))
  }, [id, days, t])

  const reload = useCallback(() => { setLoading(true); fetchAll() }, [fetchAll])

  useEffect(() => { fetchAll() }, [fetchAll])

  async function setMode(mode: 'testing' | 'enforce') {
    if (mode === 'enforce') {
      const agreed = await confirm({
        title: t('mtasts.confirmEnforce.title'),
        message: t('mtasts.confirmEnforce.message'),
        confirmLabel: t('mtasts.confirmEnforce.confirm'),
        dangerous: true,
      })
      if (!agreed) return
    }
    setIsSaving(true)
    try {
      const response = await api.post<MTASTS>(`/domains/${id}/mail-mtasts`, { mode })
      setMTASTS(response.data)
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.modeFailed')), tone: 'error' })
    } finally {
      setIsSaving(false)
    }
  }

  async function withdraw() {
    const agreed = await confirm({
      title: t('mtasts.confirmWithdraw.title'),
      message: t('mtasts.confirmWithdraw.message'),
      confirmLabel: t('mtasts.confirmWithdraw.confirm'),
      dangerous: true,
    })
    if (!agreed) return
    setIsSaving(true)
    try {
      const response = await api.delete<MTASTS>(`/domains/${id}/mail-mtasts`)
      setMTASTS(response.data)
    } catch (cause) {
      await notify({ message: apiError(cause, t('errors.withdrawFailed')), tone: 'error' })
    } finally {
      setIsSaving(false)
    }
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: 'dmarc', label: t('tabs.dmarc') },
    { key: 'tlsrpt', label: t('tabs.tlsrpt') },
    { key: 'mtasts', label: t('tabs.mtasts') },
  ]

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.email'), href: `/subscriptions/${id}/mail` },
        { label: t('breadcrumb.reports') },
      ]} />

      <h1 className="mt-4 text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('subtitle')}</p>

      {error && <div className="mt-4 rounded-lg bg-red-50 dark:bg-red-900/20 px-4 py-3 text-sm text-red-700 dark:text-red-300">{error}</div>}

      {/* The mailbox is what the whole screen depends on: the _dmarc record has
          always asked the world to send reports to it, so its absence is the
          most likely reason the tables below are empty. It is stated as an
          instruction rather than left as a blank page. */}
      {status && !status.mailbox_exists && (
        <div className="mt-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
          <p className="font-medium">{t('mailbox.missingTitle')}</p>
          <p className="mt-1">{t('mailbox.missingBody', { address: status.report_address })}</p>
          <a className="mt-2 inline-block font-medium underline" href={`/subscriptions/${id}/mail`}>
            {t('mailbox.missingAction')}
          </a>
        </div>
      )}
      {status?.last_error && (
        <div className="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
          {t('mailbox.lastError', { reason: status.last_error })}
        </div>
      )}

      {loading ? (
        <p className="mt-6 text-sm text-slate-500 dark:text-slate-400">{t('loading')}</p>
      ) : (
        <>
          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex gap-1 rounded-xl bg-slate-100 p-1 dark:bg-slate-800">
              {tabs.map(entry => (
                <button key={entry.key} type="button" onClick={() => setTab(entry.key)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${tab === entry.key ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
                  {entry.label}
                </button>
              ))}
            </div>
            {tab !== 'mtasts' && (
              <div className="inline-flex gap-1 rounded-xl bg-slate-100 p-1 dark:bg-slate-800">
                {WINDOWS.map(window => (
                  <button key={window} type="button" onClick={() => setDays(window)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${days === window ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
                    {t('window.days', { days: window })}
                  </button>
                ))}
              </div>
            )}
          </div>

          {status && (
            <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
              {status.last_scan_at
                ? t('mailbox.lastScan', { at: status.last_scan_at, address: status.report_address })
                : t('mailbox.neverScanned', { address: status.report_address })}
            </p>
          )}

          {tab === 'dmarc' && (
            <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <h3 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('dmarc.title')}</h3>
              <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">{t('dmarc.help')}</p>
              {sources.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t('dmarc.empty')}</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                      <tr>
                        <th className="py-2 pr-4">{t('dmarc.columns.source')}</th>
                        <th className="py-2 pr-4">{t('dmarc.columns.messages')}</th>
                        <th className="py-2 pr-4">{t('dmarc.columns.dkim')}</th>
                        <th className="py-2 pr-4">{t('dmarc.columns.spf')}</th>
                        <th className="py-2 pr-4">{t('dmarc.columns.action')}</th>
                        <th className="py-2">{t('dmarc.columns.reporter')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                      {sources.map(source => (
                        <tr key={source.source_ip}>
                          <td className="py-2 pr-4 font-mono text-xs text-slate-900 dark:text-slate-100">
                            {source.source_ip}
                            {source.header_froms && (
                              <span className="block font-sans text-xs text-slate-500 dark:text-slate-400">{source.header_froms}</span>
                            )}
                          </td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{source.messages}</td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{percent(source.dkim_pass, source.messages)}</td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{percent(source.spf_pass, source.messages)}</td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">
                            {source.quarantined + source.rejected === 0
                              ? t('dmarc.delivered')
                              : t('dmarc.acted', { quarantined: source.quarantined, rejected: source.rejected })}
                          </td>
                          <td className="py-2 text-xs text-slate-500 dark:text-slate-400">{source.reporter}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {tab === 'tlsrpt' && tls && (
            <div className="mt-5 space-y-5">
              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('tlsrpt.title')}</h3>
                <p className="text-sm text-slate-700 dark:text-slate-300">
                  {t('tlsrpt.sessions', { success: tls.success_count, failure: tls.failure_count })}
                </p>
                {tls.failures.length === 0 ? (
                  <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">{t('tlsrpt.noFailures')}</p>
                ) : (
                  <table className="mt-4 w-full text-left text-sm">
                    <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                      <tr>
                        <th className="py-2 pr-4">{t('tlsrpt.columns.result')}</th>
                        <th className="py-2 pr-4">{t('tlsrpt.columns.mx')}</th>
                        <th className="py-2">{t('tlsrpt.columns.sessions')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                      {tls.failures.map(bucket => (
                        <tr key={`${bucket.result_type}-${bucket.receiving_mx}`}>
                          <td className="py-2 pr-4 font-mono text-xs text-slate-900 dark:text-slate-100">{bucket.result_type}</td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{bucket.receiving_mx}</td>
                          <td className="py-2 text-slate-700 dark:text-slate-300">{bucket.session_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {tls.reports.length > 0 && (
                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                  <h3 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('tlsrpt.reportsTitle')}</h3>
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                      <tr>
                        <th className="py-2 pr-4">{t('tlsrpt.columns.reporter')}</th>
                        <th className="py-2 pr-4">{t('tlsrpt.columns.period')}</th>
                        <th className="py-2">{t('tlsrpt.columns.sessions')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                      {tls.reports.map(report => (
                        <tr key={`${report.org_name}-${report.date_begin}`}>
                          <td className="py-2 pr-4 text-slate-900 dark:text-slate-100">{report.org_name}</td>
                          <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{report.date_begin}</td>
                          <td className="py-2 text-slate-700 dark:text-slate-300">
                            {t('tlsrpt.sessions', { success: report.success_count, failure: report.failure_count })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {tab === 'mtasts' && mtasts && (
            <div className="mt-5 space-y-5">
              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{t('mtasts.title')}</h3>
                <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">{t('mtasts.help')}</p>

                <p className="text-sm text-slate-700 dark:text-slate-300">
                  {t(`mtasts.modes.${mtasts.mode}`, { defaultValue: mtasts.mode })}
                </p>

                {/* The sequence waits on the world, so the screen names the step
                    it is on instead of showing a spinner that never resolves. */}
                {(mtasts.mode === 'pending_dns' || mtasts.mode === 'pending_cert') && (
                  <ol className="mt-4 space-y-2 text-sm">
                    <li className={mtasts.dns_ready ? 'text-emerald-700 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}>
                      {mtasts.dns_ready ? t('mtasts.steps.dnsDone') : t('mtasts.steps.dnsWaiting')}
                    </li>
                    <li className={mtasts.cert_ready ? 'text-emerald-700 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}>
                      {mtasts.cert_ready ? t('mtasts.steps.certDone') : t('mtasts.steps.certWaiting')}
                    </li>
                  </ol>
                )}

                {mtasts.mx_hosts.length > 0 && (
                  <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
                    {t('mtasts.mxHosts', { hosts: mtasts.mx_hosts.join(', ') })}
                  </p>
                )}
                {mtasts.changed_at && (
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {t('mtasts.changedAt', { at: mtasts.changed_at })}
                  </p>
                )}

                <div className="mt-5 flex flex-wrap gap-2">
                  {mtasts.mode === 'off' && (
                    <button type="button" disabled={isSaving} onClick={() => setMode('testing')}
                      className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
                      {t('mtasts.actions.enable')}
                    </button>
                  )}
                  {mtasts.mode === 'testing' && (
                    <button type="button" disabled={isSaving || mtasts.enforce_blocked} onClick={() => setMode('enforce')}
                      className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
                      {t('mtasts.actions.enforce')}
                    </button>
                  )}
                  {mtasts.mode !== 'off' && mtasts.mode !== 'withdrawing' && (
                    <button type="button" disabled={isSaving} onClick={withdraw}
                      className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700">
                      {t('mtasts.actions.withdraw')}
                    </button>
                  )}
                  <button type="button" onClick={reload}
                    className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700">
                    {t('mtasts.actions.refresh')}
                  </button>
                </div>

                {/* The lock is explained rather than left as a greyed-out
                    button: enforce is the one control here that can stop mail
                    being delivered, so the reason has to be readable. */}
                {mtasts.mode === 'testing' && mtasts.enforce_blocked && (
                  <p className="mt-3 text-xs text-amber-700 dark:text-amber-300">
                    {t(ENFORCE_REASONS[mtasts.enforce_reason || ''] || 'mtasts.reasons.unknown')}
                  </p>
                )}
                {mtasts.mode === 'withdrawing' && (
                  <p className="mt-3 text-xs text-amber-700 dark:text-amber-300">{t('mtasts.withdrawNotice')}</p>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
