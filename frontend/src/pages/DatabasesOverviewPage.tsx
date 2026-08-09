// Server-wide database overview. Sizes come from the root mysql client because
// the panel DSN cannot see other schemas (see internal/overview.dbSizes); 0
// means "size unavailable" and renders as "—".
//
// The row actions call the same /databases/:id endpoints the domain-scoped page
// uses, so nothing about authorization or validation is decided twice. Their
// guards differ from this list's, though: the list is ResellerOrAbove while the
// password and delete endpoints are AdminOnly, so a reseller is only offered
// what it can actually reach.
import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useAuth } from '@/store/auth'
import OverviewList, { type Column, type Badge } from '@/components/OverviewList'
import ConfirmDialog from '@/components/ConfirmDialog'
import DBPasswordResetModal from '@/components/DBPasswordResetModal'
import SlowQuerySettings from '@/components/SlowQuerySettings'
import SlowQueryTable from '@/components/SlowQueryTable'
import DBRemoteAccess from '@/components/DBRemoteAccess'
import DBRemoteServerSwitch from '@/components/DBRemoteServerSwitch'

type Row = {
  id: number
  domain_id: number
  domain_name: string
  db_name: string
  db_user: string
  db_host: string
  db_pass: string
  size_kb: number
  created_at: string
}

function humanSize(kb: number): string {
  if (kb <= 0) return '—'
  if (kb < 1024) return `${kb} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb.toFixed(1)} MB`
  return `${(mb / 1024).toFixed(2)} GB`
}

export default function DatabasesOverviewPage() {
  const { t } = useTranslation('DatabasesOverviewPage')
  const { notify } = useDialog()
  const isAdmin = useAuth((s) => s.username?.role) === 'admin'
  const [passwordVisibility, setPasswordVisibility] = useState<Record<number, boolean>>({})
  const [copiedValue, setCopiedValue] = useState<number | null>(null)
  const [rowToDelete, setRowToDelete] = useState<Row | null>(null)
  const [pwResetFor, setPwResetFor] = useState<Row | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const [tab, setTab] = useState<'databases' | 'slow' | 'remote'>('databases')
  // Bumped when the threshold changes, so the table below reloads under the new
  // setting rather than keeping rows the operator just stopped collecting.
  const [slowKey, setSlowKey] = useState(0)
  // Bumped when the switch flips, so the list below reloads under the new state
  // rather than showing addresses that are no longer reachable.
  const [remoteKey, setRemoteKey] = useState(0)

  async function openPma(s: Row) {
    try {
      const { data } = await api.post<{ token: string }>(`/databases/${s.id}/pma-token`)
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

  async function remove() {
    if (!rowToDelete) return
    try {
      await api.delete(`/databases/${rowToDelete.id}`)
      setRowToDelete(null)
      setRefreshKey((n) => n + 1)
    } catch (e) {
      await notify({ message: apiError(e, t('errors.deleteFailed')), tone: 'error' })
    }
  }

  function copy(s: Row) {
    navigator.clipboard.writeText(s.db_pass)
    setCopiedValue(s.id)
    setTimeout(() => setCopiedValue(null), 1500)
  }

  const columns: Column<Row>[] = [
    {
      title: t('column.domain'),
      cell: (s) => (
        <Link to={`/subscriptions/${s.domain_id}/databases`} className="font-medium text-slate-900 dark:text-slate-100 hover:text-brand-600 dark:hover:text-brand-400 transition">
          {s.domain_name}
        </Link>
      ),
    },
    { title: t('column.database'), cell: (s) => <span className="font-mono text-xs">{s.db_name}</span> },
    { title: t('column.user'), cell: (s) => <span className="font-mono text-xs">{s.db_user}</span> },
    {
      title: t('column.password'),
      cell: (s) => (
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPasswordVisibility({ ...passwordVisibility, [s.id]: !passwordVisibility[s.id] })}
            className="font-mono text-xs px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded"
            title={passwordVisibility[s.id] ? t('password.hide') : t('password.show')}
          >
            {passwordVisibility[s.id] ? (s.db_pass || t('password.unreadable')) : '••••••••'}
          </button>
          {passwordVisibility[s.id] && s.db_pass && (
            <button onClick={() => copy(s)} className="text-xs px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 hover:bg-brand-100 dark:hover:bg-brand-900/30 hover:text-brand-700 dark:text-brand-300 rounded" title={t('password.copy')}>
              {copiedValue === s.id ? '✓' : '⧉'}
            </button>
          )}
        </div>
      ),
    },
    { title: t('column.size'), cell: (s) => humanSize(s.size_kb) },
    { title: t('column.created'), cell: (s) => (s.created_at || <span className="text-slate-400">—</span>) },
    {
      title: t('column.actions'),
      className: 'text-right',
      cell: (s) => (
        <div className="flex flex-wrap items-center gap-1 lg:justify-end">
          <button onClick={() => openPma(s)} className="text-sm text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 px-2 py-1 rounded" title={t('row.pmaTitle')}>{t('row.pma')}</button>
          {isAdmin && (
            <>
              <button onClick={() => setPwResetFor(s)} className="text-sm text-brand-600 dark:text-brand-400 hover:bg-brand-50 dark:hover:bg-brand-900/30 px-2 py-1 rounded">{t('row.resetPassword')}</button>
              <button onClick={() => setRowToDelete(s)} className="text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 px-2 py-1 rounded">{t('row.delete')}</button>
            </>
          )}
        </div>
      ),
    },
  ]

  // The slow query tab is shown only to an admin, because its endpoint is
  // AdminOnly while this page is ResellerOrAbove: offering it to a reseller
  // would be a tab that answers 403 on every click.
  const tabs = isAdmin
    ? (
      <div className="mb-4 inline-flex rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800">
        {(['databases', 'slow', 'remote'] as const).map(key => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === key
                ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            {t(`tabs.${key}`)}
          </button>
        ))}
      </div>
      )
    : undefined

  return (
    <>
      <OverviewList<Row>
        title={t('title')}
        icon="🗄️"
        description={t('description')}
        endpoint="/overview/databases"
        columns={columns}
        searchField={(s) => `${s.domain_name} ${s.db_name} ${s.db_user}`}
        rowKey={(s) => s.id}
        emptyMessage={t('emptyMessage')}
        refreshKey={refreshKey}
        headerExtra={tabs}
        body={tab === 'slow' ? (
          <>
            <SlowQuerySettings onChange={() => setSlowKey((n) => n + 1)} />
            <SlowQueryTable key={slowKey} endpoint="/admin/slow-queries" showDomain />
          </>
        ) : tab === 'remote' ? (
          <>
            <DBRemoteServerSwitch onChange={() => setRemoteKey((n) => n + 1)} />
            <DBRemoteAccess key={remoteKey} showDomain />
          </>
        ) : undefined}
        summary={(list): Badge[] => {
          const totalKB = list.reduce((n, s) => n + Math.max(0, s.size_kb), 0)
          return [
            { label: t('summary.databases'), value: list.length },
            { label: t('summary.totalSize'), value: humanSize(totalKB) },
          ]
        }}
      />

      {pwResetFor && (
        <DBPasswordResetModal
          db={{ id: pwResetFor.id, db_name: pwResetFor.db_name, db_user: pwResetFor.db_user }}
          onClose={() => setPwResetFor(null)}
          onDone={() => { setPwResetFor(null); setRefreshKey((n) => n + 1) }}
        />
      )}

      <ConfirmDialog
        open={!!rowToDelete}
        title={t('delete.title')}
        message={t('delete.message', { name: rowToDelete?.db_name })}
        dangerous
        confirmText={t('delete.confirm')}
        onConfirm={remove}
        onCancel={() => setRowToDelete(null)}
      />
    </>
  )
}
