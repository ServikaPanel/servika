import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useCopyOrOffer } from '@/lib/useCopyOrOffer'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'



type Domain = {
  id: number; domain_name: string; ipv4: string
  ftp_host: string; ftp_user: string
  db_host: string; db_user: string; db_name: string
  system_user: string; web_root: string
}

// The shared nameserver pair the domain is pointed at. The customer enters
// these at their registrar instead of maintaining A records by hand.
type Nameservers = { ns1: string; ns2: string; source?: string }

export default function DomainConnectionPage() {
  const { t } = useTranslation('DomainConnectionPage')
  const copyOrOffer = useCopyOrOffer()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copiedValue, setCopiedValue] = useState<string | null>(null)
  const [passwordModal, setPasswordModal] = useState<{ type: 'ftp' | 'db' } | null>(null)
  const [nameservers, setNameservers] = useState<Nameservers | null>(null)

  useEffect(() => {
    if (!id) return
    api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(e => setError(apiError(e)))
    // The pair comes from its own endpoint, where the panel-wide setting and a
    // reseller override are resolved.
    api.get<Nameservers>(`/domains/${id}/nameservers`).then(r => setNameservers(r.data)).catch(() => { /* the card stays hidden */ })
  }, [id])

  async function copy(value: string) {
    if (!(await copyOrOffer(value))) return
    setCopiedValue(value)
    setTimeout(() => setCopiedValue(null), 1800)
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.connectionDetails') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && (
        <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
          <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
          {' · '}<span className="text-xs text-slate-400 dark:text-slate-500">{t('subtitle')}</span>
        </p>
      )}
      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {domain && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <Card title={t('cards.ftp')} color="sky" icon="M3 16V8a2 2 0 012-2h6l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2z">
            <Row e={t('rows.host')} d={domain.ftp_host} onCopy={copy} copiedValue={copiedValue} />
            <Row e={t('rows.port')} d="21" onCopy={copy} copiedValue={copiedValue} />
            <Row e={t('rows.username')} d={domain.ftp_user} onCopy={copy} copiedValue={copiedValue} mono />
            <Password e={t('rows.password')} id={id!} type="ftp" onOpen={() => setPasswordModal({ type: 'ftp' })} />
            <Row e={t('rows.homeDirectory')} d={`/home/${domain.system_user}`} onCopy={copy} copiedValue={copiedValue} mono />
            <Link to={`/subscriptions/${id}/ftp`} className="block mt-2 text-sm text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{t('links.ftp')}</Link>
          </Card>

          <Card title={t('cards.mysql')} color="violet" icon="M4 7c0-1.657 3.582-3 8-3s8 1.343 8 3-3.582 3-8 3-8-1.343-8-3z">
            <Row e={t('rows.host')} d={domain.db_host} onCopy={copy} copiedValue={copiedValue} />
            <Row e={t('rows.port')} d="3306" onCopy={copy} copiedValue={copiedValue} />
            <Row e={t('rows.database')} d={domain.db_name} onCopy={copy} copiedValue={copiedValue} mono />
            <Row e={t('rows.username')} d={domain.db_user} onCopy={copy} copiedValue={copiedValue} mono />
            <Password e={t('rows.password')} id={id!} type="db" onOpen={() => setPasswordModal({ type: 'db' })} />
            <Link to={`/subscriptions/${id}/databases`} className="block mt-2 text-sm text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{t('links.database')}</Link>
          </Card>

          <Card title={t('cards.web')} color="amber" icon="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" wide>
            <Row e={t('rows.webRoot')} d={domain.web_root} onCopy={copy} copiedValue={copiedValue} mono />
            <Row e={t('rows.ipv4')} d={domain.ipv4} onCopy={copy} copiedValue={copiedValue} mono />
            <Row e={t('rows.systemUser')} d={domain.system_user} onCopy={copy} copiedValue={copiedValue} mono />
            <Row e={t('rows.httpUrl')} d={`http://${domain.domain_name}/`} onCopy={copy} copiedValue={copiedValue} />
            <Row e={t('rows.httpsUrl')} d={`https://${domain.domain_name}/`} onCopy={copy} copiedValue={copiedValue} />
          </Card>

          {nameservers && (
            <Card title={t('cards.nameservers')} color="emerald" icon="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" wide>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('nameservers.description')}</p>
              <Row e="NS1" d={nameservers.ns1} onCopy={copy} copiedValue={copiedValue} mono />
              <Row e="NS2" d={nameservers.ns2} onCopy={copy} copiedValue={copiedValue} mono />
              {nameservers.source === 'none' && (
                <p className="mt-2 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-300">
                  {t('nameservers.unconfigured')}
                </p>
              )}
            </Card>
          )}
        </div>
      )}

      {passwordModal && (
        <PasswordResetModal
          type={passwordModal.type}
          domainId={id!}
          ftpUser={domain?.ftp_user || ''}
          dbUser={domain?.db_user || ''}
          onClose={() => setPasswordModal(null)}
        />
      )}
    </div>
  )
}

function Card({ title, color, icon, children, wide }: { title: string; color: string; icon: string; children: React.ReactNode; wide?: boolean }) {
  const bg: Record<string, string> = {
    sky: 'bg-sky-100 text-sky-700',
    violet: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300',
    amber: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
    emerald: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
  }
  return (
    <div className={`bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 ${wide ? 'lg:col-span-2' : ''}`}>
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${bg[color]}`}>
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}>
            <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
          </svg>
        </div>
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
      </div>
      <dl className="space-y-2 text-sm">{children}</dl>
    </div>
  )
}

function Row({ e, d, mono, onCopy, copiedValue }: { e: string; d: string; mono?: boolean; onCopy?: (s: string) => void; copiedValue?: string | null }) {
  const { t } = useTranslation('DomainConnectionPage')
  const isCopyable = !!onCopy
  const copied = copiedValue === d
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
      <dt className="text-slate-500 dark:text-slate-500 text-xs uppercase tracking-wider">{e}</dt>
      <dd
        onClick={() => isCopyable && onCopy!(d)}
        className={`text-right flex items-center gap-2 group ${isCopyable ? 'cursor-pointer' : ''}`}
        title={isCopyable ? t('row.selectToCopy') : ''}
      >
        <span className={`${mono ? 'font-mono text-xs' : 'text-sm'} ${isCopyable ? 'text-slate-800 dark:text-slate-200 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 transition' : 'text-slate-800 dark:text-slate-200'}`}>
          {d}
        </span>
        {copied && (
          <span className="text-[10px] uppercase tracking-wider bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 rounded font-medium animate-pulse">
            {t('row.copied')}
          </span>
        )}
      </dd>
    </div>
  )
}

function Password({ e, onOpen }: { e: string; id: string; type: string; onOpen: () => void }) {
  const { t } = useTranslation('DomainConnectionPage')
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
      <dt className="text-slate-500 dark:text-slate-500 text-xs uppercase tracking-wider">{e}</dt>
      <dd className="text-right">
        <button
          onClick={onOpen}
          className="text-xs px-3 py-1 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded font-medium transition inline-flex items-center gap-1"
        >
          {t('password.button')}
        </button>
      </dd>
    </div>
  )
}

// Only the fields the reset flow reads; the endpoint returns more.
type DatabaseRow = { id: number; db_pass?: string; db_pass_plain?: string }

function PasswordResetModal({ type, domainId, ftpUser, dbUser, onClose }:
  { type: 'ftp' | 'db'; domainId: string; ftpUser: string; dbUser: string; onClose: () => void }) {
  const [newPassword, setNewPassword] = useState<string | null>(null)
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { t } = useTranslation('DomainConnectionPage')
  const [showCurrent, setShowCurrent] = useState(false)
  const [currentPassword, setCurrentPassword] = useState<string | null>(null)

  // Fetch the current password from the stored FTP value or the databases endpoint.
  useEffect(() => {
    if (!showCurrent) return
    if (type === 'ftp') {
      api.get<{ ftp_pass_plain: string }>(`/domains/${domainId}/ftp/password-show`)
        .then(r => setCurrentPassword(r.data.ftp_pass_plain || t('modal.notStored')))
        .catch(() => setCurrentPassword(t('modal.notAuthorized')))
    } else {
      api.get<DatabaseRow[]>(`/domains/${domainId}/databases`)
        .then(r => {
          const main = (r.data || [])[0]
          setCurrentPassword(main?.db_pass || main?.db_pass_plain || t('modal.notStored'))
        })
        .catch(() => setCurrentPassword(t('modal.notAuthorized')))
    }
  }, [showCurrent, type, domainId, t])

  async function create() {
    setProcessing(true); setError(null)
    try {
      if (type === 'ftp') {
        const r = await api.put<{ password: string }>(`/domains/${domainId}/ftp/password`, {})
        setNewPassword(r.data.password)
      } else {
        // Use the first database ID.
        const dbs = await api.get<DatabaseRow[]>(`/domains/${domainId}/databases`)
        const main = (dbs.data || [])[0]
        if (!main) throw new Error('no database')
        const r = await api.put<{ password: string }>(`/databases/${main.id}/password`, {})
        setNewPassword(r.data.password)
      }
    } catch (e) { setError(apiError(e, t('modal.errorGenerate'))) }
    finally { setProcessing(false) }
  }

  const user = type === 'ftp' ? ftpUser : dbUser
  const typeName = type === 'ftp' ? t('typeName.ftp') : t('typeName.db')

  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={ev => ev.stopPropagation()}>
        <div className="flex items-center gap-2 mb-3">
          <span><Icon d={ICON.key} className="h-6 w-6" /></span>
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{typeName} {t('modal.titleSuffix')}</h3>
        </div>
        <div className="text-xs text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-4 bg-slate-50 dark:bg-slate-900 px-3 py-2 rounded">
          <span className="text-slate-500 dark:text-slate-500">{t('modal.userLabel')}</span> <code className="font-mono text-slate-900 dark:text-slate-100">{user}</code>
        </div>

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-xs text-red-700 dark:text-red-300">{error}</div>}

        {/* Show the current password */}
        {!newPassword && (
          <div className="mb-4">
            {!showCurrent ? (
              <button onClick={() => setShowCurrent(true)}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded-md text-slate-700 dark:text-slate-300">
                {t('modal.showCurrent')}
              </button>
            ) : (
              <div className="px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded">
                <div className="text-[10px] uppercase tracking-wider text-amber-700 dark:text-amber-300 mb-1">{t('modal.currentPasswordLabel')}</div>
                <div className="flex items-center gap-2">
                  <code className="font-mono text-sm text-slate-900 dark:text-slate-100 flex-1 break-all">{currentPassword || '...'}</code>
                  {currentPassword && currentPassword.length > 5 && (
                    <CopyButton text={currentPassword} color="amber" />
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* New password */}
        {newPassword && (
          <div className="mb-4 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded">
            <div className="text-[10px] uppercase tracking-wider text-emerald-700 dark:text-emerald-300 mb-1">{t('modal.newPasswordGenerated')}</div>
            <div className="flex items-center gap-2">
              <code className="font-mono text-sm text-slate-900 dark:text-slate-100 flex-1 break-all">{newPassword}</code>
              <CopyButton text={newPassword} color="emerald" />
            </div>
            <p className="text-[11px] text-emerald-700 dark:text-emerald-300 mt-2">{t('modal.copyWarning')}</p>
          </div>
        )}

        <div className="flex gap-2 justify-end mt-4">
          <button onClick={onClose} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">
            {t('modal.close')}
          </button>
          <button onClick={create} disabled={processing}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded font-medium">
            {processing ? t('modal.generating') : (newPassword ? t('modal.generateAgain') : t('modal.generateNew'))}
          </button>
        </div>
      </div>
    </div>
  )
}

function CopyButton({ text, color }: { text: string; color: 'amber' | 'emerald' }) {
  const { t } = useTranslation('DomainConnectionPage')
  const copyOrOffer = useCopyOrOffer()
  const [k, setK] = useState(false)
  const bg: Record<string, string> = {
    amber: 'bg-amber-100 dark:bg-amber-900/30 hover:bg-amber-200 text-amber-800 dark:text-amber-200',
    emerald: 'bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 text-emerald-800 dark:text-emerald-200',
  }
  return (
    <button
      onClick={async () => {
        if (!(await copyOrOffer(text))) return
        setK(true)
        setTimeout(() => setK(false), 1500)
      }}
      className={`text-[10px] px-2 py-1 rounded font-medium transition ${bg[color]} ${k ? 'ring-2 ring-emerald-400' : ''}`}
    >
      {k ? t('copyButton.copied') : t('copyButton.copy')}
    </button>
  )
}