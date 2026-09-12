import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import { safeHref } from '@/lib/safeUrl'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type CatalogEntry = {
  code: string
  name: string
  version: string
  needs_database: boolean
}

type InstallRow = {
  id: number
  code: string
  name: string
  version: string
  subdirectory: string
  site_url: string
  db_name: string
  state: string
  last_error: string
  created_at: string
}

const INPUT_CLASS = 'w-full px-2.5 py-1.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

// InstallCard picks the application, where it goes and its database suffix.
function InstallCard({ catalog, selected, code, subdirectory, dbSuffix, starting, loading, onCode, onSubdirectory, onDbSuffix, onSubmit }: {
  catalog: CatalogEntry[]
  selected: CatalogEntry | null
  code: string
  subdirectory: string
  dbSuffix: string
  starting: boolean
  loading: boolean
  onCode: (value: string) => void
  onSubdirectory: (value: string) => void
  onDbSuffix: (value: string) => void
  onSubmit: () => void
}) {
  const { t } = useTranslation('AppInstaller')
  return (
    <div className="mb-5 rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/40">
      <h2 className="mb-3 text-sm font-semibold text-slate-800 dark:text-slate-200">{t('install.title')}</h2>

      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="app-code">
            {t('install.application')}
          </label>
          <select id="app-code" value={code} onChange={event => onCode(event.target.value)} className={INPUT_CLASS}>
            <option value="">{t('install.choose')}</option>
            {catalog.map(entry => (
              <option key={entry.code} value={entry.code}>{entry.name} {entry.version}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="app-subdirectory">
            {t('install.subdirectory')}
          </label>
          <input
            id="app-subdirectory"
            type="text"
            value={subdirectory}
            onChange={event => onSubdirectory(event.target.value)}
            placeholder={t('install.subdirectoryPlaceholder')}
            className={`${INPUT_CLASS} font-mono`}
          />
        </div>
        {selected?.needs_database && (
          <div>
            <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="app-db">
              {t('install.database')}
            </label>
            <input
              id="app-db"
              type="text"
              value={dbSuffix}
              onChange={event => onDbSuffix(event.target.value)}
              placeholder={selected.code}
              className={`${INPUT_CLASS} font-mono`}
            />
          </div>
        )}
      </div>

      <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">{t('install.subdirectoryHint')}</p>

      <button
        type="button"
        onClick={onSubmit}
        disabled={starting || !code || loading}
        className="mt-4 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
      >
        {starting ? t('install.starting') : t('install.submit')}
      </button>

      {/* The panel deliberately stops at the files and the database: the
          application's own wizard creates the administrator account, so no
          password of the customer's passes through the panel. */}
      <p className="mt-3 text-xs text-slate-500 dark:text-slate-500">{t('install.wizardNote')}</p>
    </div>
  )
}

// stateClass tones the badge by how the installation ended.
function stateClass(state: string): string {
  if (state === 'installed') return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
  if (state === 'failed') return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
  return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
}

// InstallRowView is one installation of the list.
function InstallRowView({ row, onForget }: { row: InstallRow; onForget: (row: InstallRow) => void }) {
  const { t } = useTranslation('AppInstaller')
  return (
    <tr className={responsiveTableRowClass}>
      <td className={responsiveTableCellClass} data-label={t('list.application')}>
        {row.name} <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{row.version}</span>
      </td>
      <td className={responsiveTableCellClass} data-label={t('list.location')}>
        {row.state === 'installed' && safeHref(row.site_url) ? (
          <a href={row.site_url} target="_blank" rel="noreferrer noopener"
            className="font-mono text-xs text-brand-600 hover:underline dark:text-brand-400">
            {row.site_url}
          </a>
        ) : (
          <span className="font-mono text-xs">{row.subdirectory || '/'}</span>
        )}
      </td>
      <td className={`${responsiveTableCellClass} font-mono text-xs`} data-label={t('list.database')}>
        {row.db_name || '-'}
      </td>
      <td className={responsiveTableCellClass} data-label={t('list.state')}>
        <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${stateClass(row.state)}`}>
          {t(`state.${row.state}`, { defaultValue: row.state })}
        </span>
        {row.state === 'failed' && row.last_error && (
          <div className="mt-1 text-[11px] text-red-700 dark:text-red-300">
            {t(`reasons.${row.last_error.split(':')[0]}`, { defaultValue: row.last_error })}
          </div>
        )}
      </td>
      <td className={responsiveTableCellClass} data-label={t('list.installed')}>{row.created_at}</td>
      <td className={responsiveTableActionCellClass} data-label={t('list.actions')}>
        <button
          type="button"
          onClick={() => onForget(row)}
          disabled={row.state === 'installing'}
          className="rounded-lg border border-slate-300 px-2.5 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800"
        >
          {t('list.forget')}
        </button>
      </td>
    </tr>
  )
}

// InstallsTable lists what this domain has installed.
function InstallsTable({ rows, loading, listFailed, onForget }: {
  rows: InstallRow[]
  loading: boolean
  listFailed: boolean
  onForget: (row: InstallRow) => void
}) {
  const { t } = useTranslation('AppInstaller')
  return (
    <div className={responsiveTableContainerClass}>
      <table className={responsiveTableClass}>
        <thead className={responsiveTableHeadClass}>
          <tr>
            <th className="px-3 py-2 text-left">{t('list.application')}</th>
            <th className="px-3 py-2 text-left">{t('list.location')}</th>
            <th className="px-3 py-2 text-left">{t('list.database')}</th>
            <th className="px-3 py-2 text-left">{t('list.state')}</th>
            <th className="px-3 py-2 text-left">{t('list.installed')}</th>
            <th className="px-3 py-2 text-right">{t('list.actions')}</th>
          </tr>
        </thead>
        <tbody className={responsiveTableBodyClass}>
          {loading && (
            <tr className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} colSpan={6}>{t('list.loading')}</td>
            </tr>
          )}
          {!loading && rows.length === 0 && (
            <tr className={responsiveTableRowClass}>
              {/* A list that could not be read says so. "No applications
                  installed" is a fact the screen must not invent. */}
              <td className={responsiveTableCellClass} colSpan={6}>{listFailed ? t('list.unavailable') : t('list.empty')}</td>
            </tr>
          )}
          {!loading && rows.map(row => (
            <InstallRowView key={row.id} row={row} onForget={onForget} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Installs a catalogued application into this domain's document root. */
export default function DomainAppInstallerPage() {
  const { t } = useTranslation('AppInstaller')
  const { confirm } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [catalog, setCatalog] = useState<CatalogEntry[]>([])
  const [installs, setInstalls] = useState<InstallRow[]>([])
  const [listFailed, setListFailed] = useState(false)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [subdirectory, setSubdirectory] = useState('')
  const [dbSuffix, setDbSuffix] = useState('')
  const poll = useRef<ReturnType<typeof setInterval> | null>(null)

  const selected = catalog.find(entry => entry.code === code) || null

  // Writes only from the promise callbacks, so the mount effect never sets
  // state synchronously.
  const load = useCallback(() => {
    if (!id) return
    api.get<CatalogEntry[]>(`/domains/${id}/app-installer`)
      .then(response => setCatalog(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.catalog'))))
      .finally(() => setLoading(false))
    api.get<InstallRow[]>(`/domains/${id}/app-installer/installs`)
      .then(response => { setInstalls(response.data || []); setListFailed(false) })
      // The rows are NOT cleared. `busy` below is derived from them and gates
      // the poll, so emptying the list on a failed read both hid the running
      // installation and cancelled the polling that would have recovered it.
      // Keeping the previous rows keeps the poll alive across a transient error.
      .catch(cause => { setListFailed(true); report('appInstalls')(cause) })
  }, [id, t, report])

  useEffect(() => { load() }, [load])

  // One effect owns the polling. An installation runs detached and takes
  // minutes, so the row is the only thing that says how it went.
  const busy = installs.some(row => row.state === 'installing')
  useEffect(() => {
    if (!busy) {
      if (poll.current) {
        clearInterval(poll.current)
        poll.current = null
      }
      return
    }
    if (poll.current) return
    poll.current = setInterval(load, 8000)
    return () => {
      if (poll.current) {
        clearInterval(poll.current)
        poll.current = null
      }
    }
  }, [busy, load])

  async function install() {
    if (!id || !code) return
    setError(null)
    setStarting(true)
    try {
      await api.post(`/domains/${id}/app-installer/installs`, {
        code,
        subdirectory: subdirectory.trim(),
        db_suffix: dbSuffix.trim(),
      })
      setSubdirectory('')
      setDbSuffix('')
      load()
    } catch (cause) {
      const reason = apiError(cause, '')
      setError(reason.startsWith('app_')
        ? t(`reasons.${reason}`, { defaultValue: reason })
        : apiError(cause, t('errors.install')))
    } finally {
      setStarting(false)
    }
  }

  async function forget(row: InstallRow) {
    if (!id) return
    if (!(await confirm({
      title: t('forget.title'),
      message: t('forget.message', { name: row.name }),
      confirmLabel: t('forget.confirm'),
      dangerous: true,
    }))) return
    try {
      await api.delete(`/domains/${id}/app-installer/installs/${row.id}`)
      load()
    } catch (cause) {
      setError(apiError(cause, t('errors.forget')))
    }
  }

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.current') },
      ]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      <InstallCard
        catalog={catalog} selected={selected}
        code={code} subdirectory={subdirectory} dbSuffix={dbSuffix}
        starting={starting} loading={loading}
        onCode={setCode} onSubdirectory={setSubdirectory} onDbSuffix={setDbSuffix}
        onSubmit={install}
      />

      <InstallsTable rows={installs} loading={loading} listFailed={listFailed} onForget={forget} />

      <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('forgetNote')}</p>
    </div>
  )
}
