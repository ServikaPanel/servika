import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import { type DB, formatBytes } from '@/lib/database'
import Breadcrumb from '@/components/Breadcrumb'
import Modal from '@/components/Modal'
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

type Domain = { id: number; domain_name: string; system_user: string }

export default function DomainDatabasesPage() {
  const { t } = useTranslation('DomainDatabasesPage')
  const report = useReportError()
  const { id } = useParams()
  const navigate = useNavigate()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [databases, setDatabases] = useState<DB[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [addOpen, setAddOpen] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchDatabases
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchDatabases = useCallback(() => {
    if (!id) return
    api.get<DB[]>(`/domains/${id}/databases`)
      .then(r => setDatabases(r.data))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    fetchDatabases()
  }, [fetchDatabases])

  useEffect(() => {
    if (id) api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    fetchDatabases()
  }, [id, fetchDatabases, report])

  // Unique existing DB users for this domain (used for the existing-user selector).
  const existingUsers = useMemo(
    () => Array.from(new Set(databases.map(d => d.db_user))),
    [databases],
  )

  return (
    <div className="w-full px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.databases') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && <p className="text-sm text-slate-500 dark:text-slate-500 mb-5"><Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link></p>}

      <div className="flex flex-col gap-2 mb-4 sm:flex-row sm:items-center">
        <button onClick={() => setAddOpen(true)} className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-md">{t('actions.new')}</button>
        <button onClick={load} className="px-3 py-2 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-sm rounded-md">{t('actions.refresh')}</button>
        <span className="text-sm text-slate-500 dark:text-slate-500 sm:ml-auto">{t('count', { count: databases.length })}</span>
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      <div className={responsiveTableContainerClass}>
        {loading ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> :
         databases.length === 0 ? <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-500">{t('empty')}</div> :
        <table className={responsiveTableClass}>
          <thead className={responsiveTableHeadClass}>
            <tr>
              <th className="text-left px-4 py-2.5">{t('columns.database')}</th>
              <th className="text-left px-4 py-2.5">{t('columns.created')}</th>
              <th className="text-right px-4 py-2.5">{t('columns.size')}</th>
              <th className="text-right px-4 py-2.5"></th>
            </tr>
          </thead>
          <tbody className={responsiveTableBodyClass}>
            {databases.map(d => (
              <tr
                key={d.id}
                onClick={() => navigate(`/subscriptions/${id}/databases/${d.id}`)}
                className={`${responsiveTableRowClass} cursor-pointer`}
              >
                <td data-label={t('columns.database')} className={responsiveTableCodeCellClass}>
                  <span className="text-brand-700 dark:text-brand-300">{d.db_name}</span>
                </td>
                <td data-label={t('columns.created')} className={responsiveTableCellClass}>{d.created_at}</td>
                <td data-label={t('columns.size')} className={`${responsiveTableCellClass} text-right`}>
                  <span className="font-mono tabular-nums whitespace-nowrap text-slate-700 dark:text-slate-300">{formatBytes(d.size)}</span>
                </td>
                <td className={responsiveTableActionCellClass}>
                  <span className="inline-flex items-center gap-1 text-sm text-slate-500 dark:text-slate-400">
                    {t('row.manage')}
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>}
      </div>

      {addOpen && domain && (
        <NewDatabaseModal
          domainId={Number(id)}
          systemUser={domain.system_user}
          existingUsers={existingUsers}
          onClose={() => setAddOpen(false)}
          onDone={() => { setAddOpen(false); load() }}
        />
      )}
    </div>
  )
}

// generateStrongPassword builds a browser-side strong password (mixed letters+digits, passes the
// server-side strength check).
function generateStrongPassword(n = 20): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
  const buf = new Uint32Array(n)
  ;(window.crypto || (window as unknown as { msCrypto: Crypto }).msCrypto).getRandomValues(buf)
  let s = ''
  for (let i = 0; i < n; i++) s += alphabet[buf[i] % alphabet.length]
  return s
}

type NewDatabaseModalProps = {
  domainId: number
  systemUser: string
  existingUsers: string[]
  onClose: () => void
  onDone: () => void
}

const SUFFIX_RE = /^[a-z0-9_]{1,32}$/

function NewDatabaseModal({ domainId, systemUser, existingUsers, onClose, onDone }: NewDatabaseModalProps) {
  const { t } = useTranslation('DomainDatabasesPage')
  const prefix = systemUser + '_'
  const [auto, setAuto] = useState(true)
  const [dbSuffix, setDbSuffix] = useState('')
  const [userMode, setUserMode] = useState<'new' | 'existing'>('new')
  const [userSuffix, setUserSuffix] = useState('')
  const [existingUser, setExistingUser] = useState(existingUsers[0] || '')
  const [password, setPassword] = useState('')
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ db_name: string; db_user: string; db_pass: string } | null>(null)

  const dbNamePreview = prefix + (dbSuffix || '...')
  const userPreview = prefix + (userSuffix || '...')
  const passwordStrengthIssue =
    password !== '' && (password.length < 12 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password))

  function localValidate(): string | null {
    if (auto) return null
    if (!SUFFIX_RE.test(dbSuffix)) return t('newModal.errors.dbSuffix')
    if ((prefix + dbSuffix).length > 64) return t('newModal.errors.dbNameTooLong')
    if (userMode === 'new') {
      if (!SUFFIX_RE.test(userSuffix)) return t('newModal.errors.userSuffix')
      if ((prefix + userSuffix).length > 64) return t('newModal.errors.userNameTooLong')
      if (password !== '' && passwordStrengthIssue) return t('newModal.errors.passwordStrength')
    } else {
      if (!existingUser) return t('newModal.errors.selectExisting')
    }
    return null
  }

  async function create() {
    const v = localValidate()
    if (v) { setError(v); return }
    setProcessing(true); setError(null)
    try {
      const body: Record<string, unknown> = auto
        ? { auto: true }
        : {
            db_suffix: dbSuffix,
            user_mode: userMode,
            ...(userMode === 'new'
              ? { user_suffix: userSuffix, password }
              : { existing_user: existingUser }),
          }
      const { data } = await api.post(`/domains/${domainId}/databases`, body)
      setResult({ db_name: data.db_name, db_user: data.db_user, db_pass: data.db_pass })
    } catch (e) {
      setError(apiError(e, t('newModal.errors.createFailed')))
    } finally {
      setProcessing(false)
    }
  }

  const inputCls = 'w-full px-3 py-2 border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 rounded-md text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-50'

  return (
    <Modal open={true} title={t('newModal.title')} onClose={result ? onDone : onClose} width="lg">
      {result ? (
        <div className="space-y-4">
          <div className="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md p-4 space-y-3">
            <p className="text-sm text-emerald-800 dark:text-emerald-200 font-medium">{t('newModal.created')}</p>
            <p className="text-xs text-emerald-700 dark:text-emerald-300">{t('newModal.saveHint')}</p>
            <ResultRow label={t('newModal.labelDatabase')} value={result.db_name} />
            <ResultRow label={t('newModal.labelUser')} value={result.db_user} />
            <ResultRow label={t('newModal.labelPassword')} value={result.db_pass} />
          </div>
          <div className="flex justify-end">
            <button onClick={onDone} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded-md">{t('newModal.done')}</button>
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <label className="flex items-center gap-3 cursor-pointer select-none">
            <input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} className="h-4 w-4 accent-brand-600" />
            <span className="text-sm text-slate-700 dark:text-slate-300">
              <strong className="font-medium">{t('newModal.autoPre')}</strong>{t('newModal.autoPost')}
            </span>
          </label>

          {!auto && (
            <div className="space-y-5 pt-1">
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('newModal.dbNameLabel')}</label>
                <div className="flex items-stretch">
                  <span className="inline-flex items-center px-3 rounded-l-md border border-r-0 border-slate-300 dark:border-slate-600 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 text-sm font-mono select-none">{prefix}</span>
                  <input value={dbSuffix} onChange={e => setDbSuffix(e.target.value.toLowerCase())} placeholder={t('newModal.dbSuffixPlaceholder')} className={inputCls + ' rounded-l-none'} />
                </div>
                <p className="mt-1 text-xs text-slate-400 dark:text-slate-500 font-mono">{dbNamePreview}</p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">{t('newModal.dbUserLabel')}</label>
                <div className="flex gap-4 mb-2">
                  <label className="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input type="radio" name="userMode" checked={userMode === 'new'} onChange={() => setUserMode('new')} className="accent-brand-600" />
                    {t('newModal.newUser')}
                  </label>
                  <label className={'flex items-center gap-1.5 text-sm cursor-pointer ' + (existingUsers.length ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-600 cursor-not-allowed')}>
                    <input type="radio" name="userMode" disabled={!existingUsers.length} checked={userMode === 'existing'} onChange={() => setUserMode('existing')} className="accent-brand-600" />
                    {t('newModal.selectExistingUser')}
                  </label>
                </div>

                {userMode === 'new' ? (
                  <>
                    <div className="flex items-stretch">
                      <span className="inline-flex items-center px-3 rounded-l-md border border-r-0 border-slate-300 dark:border-slate-600 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 text-sm font-mono select-none">{prefix}</span>
                      <input value={userSuffix} onChange={e => setUserSuffix(e.target.value.toLowerCase())} placeholder={t('newModal.userSuffixPlaceholder')} className={inputCls + ' rounded-l-none'} />
                    </div>
                    <p className="mt-1 text-xs text-slate-400 dark:text-slate-500 font-mono">{userPreview}</p>
                  </>
                ) : (
                  <select value={existingUser} onChange={e => setExistingUser(e.target.value)} className={inputCls}>
                    {existingUsers.map(u => <option key={u} value={u}>{u}</option>)}
                  </select>
                )}
              </div>

              {userMode === 'new' && (
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('newModal.passwordLabel')} <span className="text-slate-400 dark:text-slate-500">{t('newModal.passwordOptional')}</span></label>
                  <div className="flex gap-2">
                    <input type="text" value={password} onChange={e => setPassword(e.target.value)} placeholder={t('newModal.passwordPlaceholder')} className={inputCls} />
                    <button type="button" onClick={() => setPassword(generateStrongPassword())} className="whitespace-nowrap px-3 py-2 bg-white dark:bg-slate-800 border border-brand-600 text-brand-700 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-900/30 text-sm rounded-md">{t('newModal.generate')}</button>
                  </div>
                  {passwordStrengthIssue && <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">{t('newModal.passwordStrength')}</p>}
                </div>
              )}
            </div>
          )}

          {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-300">{error}</div>}

          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} disabled={processing} className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md text-sm">{t('newModal.cancel')}</button>
            <button onClick={create} disabled={processing} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">{processing ? t('newModal.creating') : t('newModal.create')}</button>
          </div>
        </div>
      )}
    </Modal>
  )
}

function ResultRow({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation('DomainDatabasesPage')
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center gap-2">
      <span className="w-24 shrink-0 text-xs text-emerald-700 dark:text-emerald-300">{label}</span>
      <code className="flex-1 bg-white dark:bg-slate-800 px-3 py-1.5 font-mono text-sm text-slate-900 dark:text-slate-100 rounded border border-emerald-200 dark:border-emerald-800 break-all">{value}</code>
      <button onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }} className="px-2.5 py-1.5 bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 text-emerald-800 dark:text-emerald-200 text-xs rounded">{copied ? t('resultRow.copied') : t('resultRow.copy')}</button>
    </div>
  )
}
