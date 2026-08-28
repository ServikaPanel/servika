import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import Modal from '@/components/Modal'
import ConfirmDialog from '@/components/ConfirmDialog'
import DBPasswordResetModal from '@/components/DBPasswordResetModal'
import DBRemoteAccess from '@/components/DBRemoteAccess'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import { type DB, formatBytes } from '@/lib/database'

type Domain = { id: number; domain_name: string }

// One database's own page. The list stays three columns for readability, so the
// full connection detail and every action live here. There is no single-database
// GET endpoint, so this reads the same /databases list and picks the row.
export default function DomainDatabaseDetailPage() {
  const { t } = useTranslation('DomainDatabasesPage')
  const { id, dbid } = useParams()
  const navigate = useNavigate()
  const report = useReportError()
  const { confirm, notify } = useDialog()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [db, setDb] = useState<DB | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [passwordShown, setPasswordShown] = useState(false)
  const [copied, setCopied] = useState(false)
  const [optimizing, setOptimizing] = useState(false)
  const [pwResetOpen, setPwResetOpen] = useState(false)
  const [remoteOpen, setRemoteOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchDatabase
  // settles only through promise callbacks.
  const fetchDatabase = useCallback(() => {
    if (!id || !dbid) return
    api.get<DB[]>(`/domains/${id}/databases`)
      .then(r => {
        const found = r.data.find(x => String(x.id) === String(dbid))
        setDb(found ?? null)
        if (!found) setError(t('detail.notFound'))
      })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id, dbid, t])

  useEffect(() => {
    if (id) api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    fetchDatabase()
  }, [id, fetchDatabase, report])

  async function openPma() {
    if (!db) return
    try {
      const { data } = await api.post<{ token: string }>(`/databases/${db.id}/pma-token`)
      // Deliver the one-time token in a POST body (never a URL) so it cannot leak
      // through browser history, proxy logs, or Referer headers.
      const form = document.createElement('form')
      form.method = 'POST'
      form.action = '/pma-signon.php'
      form.target = '_blank'
      const input = document.createElement('input')
      input.type = 'hidden'
      input.name = 't'
      input.value = data.token
      form.appendChild(input)
      document.body.appendChild(form)
      form.submit()
      form.remove()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.pmaToken')), tone: 'error' })
    }
  }

  async function optimize() {
    if (!db || optimizing) return
    if (!(await confirm({ message: t('detail.optimizeConfirm', { name: db.db_name }), confirmLabel: t('detail.optimizeConfirmButton') }))) return
    setOptimizing(true)
    try {
      const { data } = await api.post<{ before_bytes: number; after_bytes: number; reclaimed_bytes: number }>(`/databases/${db.id}/optimize`)
      const reclaimed = Number(data?.reclaimed_bytes || 0)
      await notify({
        message: reclaimed > 0
          ? t('detail.optimizeReclaimed', { reclaimed: formatBytes(reclaimed), before: formatBytes(Number(data?.before_bytes || 0)), after: formatBytes(Number(data?.after_bytes || 0)) })
          : t('detail.optimizeTidy', { name: db.db_name }),
        tone: 'info',
      })
      fetchDatabase()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.optimizeFailed')), tone: 'error' })
    } finally {
      setOptimizing(false)
    }
  }

  async function remove() {
    if (!db) return
    try {
      await api.delete(`/databases/${db.id}`)
      setDeleteOpen(false)
      navigate(`/subscriptions/${id}/databases`)
    } catch (e) {
      await notify({ message: apiError(e, t('errors.deleteFailed')), tone: 'error' })
    }
  }

  function copyPassword() {
    if (!db) return
    navigator.clipboard.writeText(db.db_pass)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="w-full px-4 py-4 sm:px-6 sm:py-5 max-w-[900px]">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.databases'), href: `/subscriptions/${id}/databases` },
        { label: db?.db_name || '...' },
      ]} />

      <div className="flex items-center gap-3 mb-5">
        <Link to={`/subscriptions/${id}/databases`} className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300" title={t('detail.back')}>
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" /></svg>
        </Link>
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 font-mono truncate">{db?.db_name || t('title')}</h1>
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {loading ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> : db && (
        <div className="space-y-4">
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-4">{t('detail.connectionInfo')}</h2>
            <dl className="space-y-3">
              <DetailRow label={t('columns.database')} value={db.db_name} mono />
              <DetailRow label={t('columns.username')} value={db.db_user} mono />
              <DetailRow label={t('columns.host')} value={`${db.db_host}:3306`} mono />
              <div className="flex items-start justify-between gap-3 py-1.5">
                <dt className="text-sm text-slate-500 dark:text-slate-400 pt-1">{t('columns.password')}</dt>
                <dd className="flex flex-wrap items-center gap-2 justify-end">
                  <code className="font-mono text-sm bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded text-slate-800 dark:text-slate-200 break-all">
                    {passwordShown ? db.db_pass : '••••••••••••'}
                  </code>
                  <button onClick={() => setPasswordShown(!passwordShown)} className="text-xs px-2 py-1 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded text-slate-600 dark:text-slate-300">{passwordShown ? t('password.hide') : t('password.show')}</button>
                  {passwordShown && <button onClick={copyPassword} className="text-xs px-2 py-1 bg-slate-100 dark:bg-slate-700 hover:bg-brand-100 dark:hover:bg-brand-900/40 rounded text-slate-600 dark:text-slate-300">{copied ? t('resultRow.copied') : t('password.copy')}</button>}
                </dd>
              </div>
              <DetailRow label={t('columns.size')} value={formatBytes(db.size)} mono />
              <DetailRow label={t('columns.created')} value={db.created_at} />
            </dl>
          </div>

          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-4">{t('detail.operations')}</h2>
            <div className="flex flex-wrap gap-2">
              <button onClick={openPma} className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/40 rounded-md"><Icon d={ICON.lockOpen} className="h-4 w-4" />{t('row.pma')}</button>
              <button onClick={() => setPwResetOpen(true)} className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300 hover:bg-brand-100 dark:hover:bg-brand-900/40 rounded-md"><Icon d={ICON.key} className="h-4 w-4" />{t('row.resetPassword')}</button>
              <button onClick={() => setRemoteOpen(true)} className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-md"><Icon d={ICON.globe} className="h-4 w-4" />{t('row.remoteAccess')}</button>
              <button onClick={optimize} disabled={optimizing} className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 rounded-md disabled:opacity-50"><Icon d={ICON.bolt} className={`h-4 w-4 ${optimizing ? 'animate-pulse' : ''}`} />{optimizing ? t('row.optimizing') : t('row.optimize')}</button>
              <button onClick={() => setDeleteOpen(true)} className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-md ml-auto"><Icon d={ICON.trash} className="h-4 w-4" />{t('row.delete')}</button>
            </div>
          </div>
        </div>
      )}

      {pwResetOpen && db && (
        <DBPasswordResetModal db={db} onClose={() => setPwResetOpen(false)} onDone={() => { setPwResetOpen(false); fetchDatabase() }} />
      )}

      {/* Keyed by the database USER, not the row: one user can own several
          databases and a remote account is granted all of them at once. */}
      <Modal open={remoteOpen} title={t('remote.title', { user: db?.db_user })} width="lg" onClose={() => setRemoteOpen(false)}>
        {remoteOpen && db && <DBRemoteAccess domainId={Number(id)} dbUser={db.db_user} />}
      </Modal>

      <ConfirmDialog
        open={deleteOpen}
        title={t('delete.title')}
        message={t('delete.message', { name: db?.db_name })}
        dangerous
        confirmText={t('delete.confirm')}
        onConfirm={remove}
        onCancel={() => setDeleteOpen(false)}
      />
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5">
      <dt className="text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className={`text-sm text-slate-800 dark:text-slate-200 text-right break-all ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  )
}
