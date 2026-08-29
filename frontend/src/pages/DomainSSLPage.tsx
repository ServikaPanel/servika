import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { sslState, SSL_SOURCE_LETSENCRYPT, SSL_SOURCE_SELF_SIGNED, SSL_SOURCE_IMPORTED } from '@/lib/ssl'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'

type Domain = { id: number; domain_name: string; system_user: string; ipv4: string; ssl: boolean; ssl_expiry?: string }
type SSLStatus = {
  active: boolean
  source: string
  expires_at?: string
  cert_path?: string
  key_path?: string
}
type SSLStep = { name: string; state: string; reason?: string; seconds: number }
type SSLProgress = {
  state: string
  reason?: string
  steps: SSLStep[]
  result?: Record<string, unknown>
}

// Names the certificate's origin. An unrecognised source is reported as unknown
// rather than folded into self-signed: a row written before the column existed
// carries an empty value, and calling that self-signed states a defect that was
// never observed.
function sourceLabel(source: string, t: (key: string) => string) {
  switch (source) {
    case SSL_SOURCE_LETSENCRYPT: return t('status.sourceLetsencrypt')
    case SSL_SOURCE_SELF_SIGNED: return t('status.sourceSelfSigned')
    case SSL_SOURCE_IMPORTED: return t('status.sourceImported')
    default: return t('status.sourceUnknown')
  }
}

export default function DomainSSLPage() {
  const { t } = useTranslation('DomainSSLPage')
  const { confirm } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [status, setStatus] = useState<SSLStatus | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [warning, setWarning] = useState<string | null>(null)
  // Ordering the mail certificate as well is the default: a mailbox owner who
  // connects to mail.<domain> otherwise gets a name that does not match, and
  // nothing on this page would have told them why.
  const [alsoSecureMail, setAlsoSecureMail] = useState(true)
  const [mailNote, setMailNote] = useState<string | null>(null)
  // The installation runs on the server, not on this request, so the page shows
  // where it got to and survives being closed and reopened.
  const [steps, setSteps] = useState<SSLStep[]>([])
  const [jobState, setJobState] = useState('idle')
  const [pollToken, setPollToken] = useState(0)

  function load() {
    if (!id) return
    api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    api.get<SSLStatus>(`/domains/${id}/ssl`).then(r => setStatus(r.data)).catch(e => setError(apiError(e)))
  }
  useEffect(load, [id, report])

  // applyResult renders the outcome the installation recorded. It reads the
  // same fields the synchronous response used to carry, so what the customer is
  // told did not change when the work moved off the request.
  const applyResult = useCallback((progress: SSLProgress) => {
    const result = (progress.result ?? {}) as Record<string, string | undefined> &
      { web_ssl_skipped?: Record<string, string>; mail_ssl_skipped?: Record<string, string>; mail_ssl?: { hosts?: string[] } }

    if (progress.state === 'failed') {
      setError(t(`reasons.${progress.reason}`, { defaultValue: t('errors.installFailed') }))
      return
    }

    // A name left out of the certificate is not a failure, so it is reported
    // whether the issuance succeeded or fell back. Without it the only symptom
    // is a mail client that keeps asking for a password.
    const webSkipped = Object.entries(result.web_ssl_skipped ?? {})
      .map(([host, code]) => `${host} (${t(`reasons.${code}`, { defaultValue: code })})`)
      .join(', ')
    const skippedNote = webSkipped ? ` ${t('warning.namesSkipped', { skipped: webSkipped })}` : ''

    // result.type is what was ACTUALLY installed, which is not always what was
    // asked for: a Let's Encrypt request that fails falls back to a self-signed
    // certificate so port 443 keeps serving. Reporting the requested type here
    // is what let the panel say "Let's Encrypt installed" while the browser said
    // the site was not secure.
    const installed = result.type ?? result.requested_type ?? ''
    if (result.warning) {
      const reason = result.reason
        ? t(`reasons.${result.reason}`, { defaultValue: result.reason })
        : ''
      const fallback = t('warning.letsencryptFallback')
      setWarning((reason ? `${fallback} ${reason}` : fallback) + skippedNote)
    } else {
      setSuccess(t('success.installed', { type: installed, expires: result.expires_at }))
      if (skippedNote) setWarning(skippedNote.trim())
    }

    // The mail certificate is a separate order, so it is reported separately.
    // The backend returns reason CODES, never sentences: the API is English and
    // this interface ships twelve languages.
    if (result.mail_ssl_error) {
      setMailNote(t(`mailSSL.errors.${result.mail_ssl_error}`, { defaultValue: t('mailSSL.errors.generic') }))
    } else if (result.mail_ssl) {
      const skipped = Object.entries(result.mail_ssl_skipped ?? {})
      setMailNote(skipped.length === 0
        ? t('mailSSL.secured', { hosts: (result.mail_ssl.hosts ?? []).join(', ') })
        : t('mailSSL.securedPartly', {
            hosts: (result.mail_ssl.hosts ?? []).join(', '),
            skipped: skipped.map(([host, code]) =>
              `${host} (${t(`mailSSL.reasons.${code}`, { defaultValue: code })})`).join(', '),
          }))
    }
  }, [t])

  // Polling replaces waiting on the request. It also runs on mount, so opening
  // the page while an installation is under way shows it rather than an idle
  // form. The banner is only raised for a finish this page actually watched: an
  // installation that ended before the page opened is history, not news.
  useEffect(() => {
    if (!id) return
    let cancelled = false
    let timer: number | undefined
    let watched = false

    async function tick() {
      try {
        const { data } = await api.get<SSLProgress>(`/domains/${id}/ssl/progress`)
        if (cancelled) return
        setSteps(data.steps ?? [])
        setJobState(data.state)
        if (data.state === 'running') {
          watched = true
          setIsProcessing(true)
          timer = window.setTimeout(tick, 1500)
          return
        }
        setIsProcessing(false)
        if (watched && data.state !== 'idle') {
          applyResult(data)
          load()
        }
      } catch {
        // A failed poll is not a failed installation. Stop polling and let the
        // status card below report what the server actually holds.
        if (!cancelled) setIsProcessing(false)
      }
    }
    void tick()
    return () => { cancelled = true; if (timer) window.clearTimeout(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, pollToken, applyResult])

  async function issue(type: 'self-signed' | 'letsencrypt') {
    if (type === 'letsencrypt' && !(await confirm({ message: t('confirm.letsencrypt') }))) return
    setIsProcessing(true); setError(null); setSuccess(null); setWarning(null); setMailNote(null)
    setSteps([])
    try {
      const body: { type: string; mail_ssl?: boolean } = { type }
      if (type === 'letsencrypt' && alsoSecureMail) body.mail_ssl = true
      // The server answers as soon as the work is under way. Holding the request
      // meant the browser gave up before the installation did, and closing the
      // tab cancelled it while the certificate was already half in place.
      await api.post(`/domains/${id}/ssl/issue`, body)
      setPollToken(token => token + 1)
    } catch (e) {
      setIsProcessing(false)
      setError(apiError(e, t('errors.installFailed')))
    }
  }

  async function disable() {
    if (!(await confirm({ message: t('confirm.disable'), dangerous: true }))) return
    setIsProcessing(true); setError(null); setSuccess(null); setWarning(null)
    try {
      await api.delete(`/domains/${id}/ssl`)
      setSuccess(t('success.removed'))
      load()
    } catch (e) {
      setError(apiError(e, t('errors.removeFailed')))
    } finally {
      setIsProcessing(false)
    }
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.sslCertificates') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && (
        <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">
          <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
          {' · '}
          {t('ipLabel')} <span className="font-mono">{domain.ipv4}</span>
        </p>
      )}

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}
      {warning && <div className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-sm text-amber-800 dark:text-amber-300">{warning}</div>}
      {jobState === 'running' && (
        <div className="mb-3 px-3 py-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md text-sm text-blue-700 dark:text-blue-300">
          {t('status.issuingNotice')}
        </div>
      )}

      {/* What the installation is doing. It runs on the server, so this survives
          the page being closed and reopened. */}
      {steps.length > 0 && (
        <div className="mb-5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('steps.title')}</h2>
          <ol className="space-y-2">
            {steps.map((step, index) => (
              <li key={`${step.name}-${index}`} className="flex items-start gap-2.5 text-sm">
                <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${
                  step.state === 'done' ? 'bg-emerald-500'
                  : step.state === 'warning' ? 'bg-amber-400'
                  : step.state === 'failed' ? 'bg-red-500'
                  : 'bg-blue-500 animate-pulse'
                }`}></span>
                <div className="min-w-0">
                  <div className="text-slate-800 dark:text-slate-200">
                    {t(`steps.names.${step.name}`, { defaultValue: step.name })}
                    <span className="ml-2 text-xs text-slate-400 dark:text-slate-500">
                      {t(`steps.states.${step.state}`, { defaultValue: step.state })}
                      {step.seconds >= 1 ? ` · ${Math.round(step.seconds)}s` : ''}
                    </span>
                  </div>
                  {step.reason && (
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      {t(`reasons.${step.reason}`, {
                        defaultValue: t(`mailSSL.errors.${step.reason}`, { defaultValue: step.reason }),
                      })}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
      {mailNote && <div className="mb-3 px-3 py-2 bg-sky-50 dark:bg-sky-900/20 border border-sky-200 dark:border-sky-800 rounded-md text-sm text-sky-800 dark:text-sky-300">{mailNote}</div>}

      {/* Status card */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 mb-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('status.title')}</h2>
          {status && (
            // Only a real CA is trusted by a browser. A self-signed certificate
            // encrypts the connection and still shows the visitor a warning
            // page, so a green "protected" badge would report the fail-safe as
            // the outcome the customer asked for. The test is which SOURCE it
            // came from, not whether it is Let's Encrypt: a certificate carried
            // over from a cPanel migration is as real as one ordered here, and
            // calling it self-signed was the same false report in reverse.
            sslState(status.active, status.source) === 'trusted' ? (
              <span className="text-xs px-2 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 rounded uppercase font-semibold tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                {t('status.protected')}
              </span>
            ) : status.active ? (
              <span className="text-xs px-2 py-1 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 rounded uppercase font-semibold tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                {t('status.selfSignedBadge')}
              </span>
            ) : (
              <span className="text-xs px-2 py-1 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 rounded uppercase font-semibold tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                {t('status.unprotected')}
              </span>
            )
          )}
        </div>
        {!status ? (
          <div className="text-sm text-slate-400 dark:text-slate-500">{t('status.loading')}</div>
        ) : status.active ? (
          <div className="space-y-2 text-sm">
            <DetailRow label={t('status.sourceLabel')} value={sourceLabel(status.source, t)} />
            {status.expires_at && <DetailRow label={t('status.expiryLabel')} value={new Date(status.expires_at).toLocaleDateString('en-US', { dateStyle: 'long' })} />}
            <button
              onClick={disable}
              disabled={isProcessing}
              className="mt-4 px-4 py-2 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 disabled:opacity-50 rounded-md text-sm font-medium transition"
            >
              {t('status.remove')}
            </button>
          </div>
        ) : (
          <div className="text-sm text-slate-600 dark:text-slate-400 dark:text-slate-500">
            {t('status.noCert')}
          </div>
        )}
      </div>

      {/* Action cards */}
      {status && !status.active && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-9 h-9 rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 flex items-center justify-center">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
              </div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('selfSigned.title')}</h3>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-500 mb-4">
              {t('selfSigned.description')}
            </p>
            <ul className="text-xs text-slate-500 dark:text-slate-500 mb-4 space-y-1">
              <li>{t('selfSigned.bullet1')}</li>
              <li>{t('selfSigned.bullet2')}</li>
              <li>{t('selfSigned.bullet3')}</li>
            </ul>
            <button
              onClick={() => issue('self-signed')}
              disabled={isProcessing}
              className="w-full px-4 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md transition"
            >
              {isProcessing ? t('selfSigned.installing') : t('selfSigned.install')}
            </button>
          </div>

          <div className="bg-white dark:bg-slate-800 border border-emerald-200 dark:border-emerald-800 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-9 h-9 rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 flex items-center justify-center">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
              </div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('letsencrypt.title')}</h3>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-500 mb-4">
              {t('letsencrypt.description')}
            </p>
            <ul className="text-xs text-slate-500 dark:text-slate-500 mb-4 space-y-1">
              <li>{t('letsencrypt.bullet1')}</li>
              <li>{t('letsencrypt.bullet2')}</li>
              <li>{t('letsencrypt.bullet3')}</li>
            </ul>
            <label className="flex items-start gap-2 mb-4 p-2.5 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 cursor-pointer">
              <input
                type="checkbox"
                checked={alsoSecureMail}
                onChange={e => setAlsoSecureMail(e.target.checked)}
                className="mt-0.5 cursor-pointer"
              />
              <span className="text-xs text-slate-700 dark:text-slate-300">
                <b>{t('mailSSL.option')}</b>
                <span className="block text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  {t('mailSSL.optionHint', { domain: domain?.domain_name ?? '' })}
                </span>
              </span>
            </label>
            <button
              onClick={() => issue('letsencrypt')}
              disabled={isProcessing}
              className="w-full px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:bg-emerald-300 text-white text-sm font-medium rounded-md transition"
            >
              {isProcessing ? t('letsencrypt.installing') : t('letsencrypt.install')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-slate-500 dark:text-slate-500">{label}</span>
      <span className={`text-slate-800 dark:text-slate-200 text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  )
}