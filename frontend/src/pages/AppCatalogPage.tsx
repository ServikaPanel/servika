import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
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
  download_url: string
  sha256: string
  archive_name: string
  strip_components: number
  needs_database: boolean
  enabled: boolean
  updated_at: string
}

const EMPTY: CatalogEntry = {
  code: '', name: '', version: '', download_url: '', sha256: '',
  archive_name: '', strip_components: 0, needs_database: true, enabled: true,
  updated_at: '',
}

const INPUT_CLASS = 'w-full px-2.5 py-1.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

/** Edits the catalog the one-click installer offers. */
export default function AppCatalogPage() {
  const { t } = useTranslation('AppInstaller')
  const { confirm } = useDialog()
  const [entries, setEntries] = useState<CatalogEntry[]>([])
  const [draft, setDraft] = useState<CatalogEntry>(EMPTY)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const load = useCallback(() => {
    api.get<CatalogEntry[]>('/admin/app-catalog')
      .then(response => setEntries(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.catalog'))))
      .finally(() => setLoading(false))
  }, [t])

  useEffect(() => { load() }, [load])

  async function save() {
    setError(null)
    setMessage(null)
    setSaving(true)
    try {
      await api.put('/admin/app-catalog', draft)
      setMessage(t('catalog.saved', { code: draft.code }))
      setDraft(EMPTY)
      load()
    } catch (cause) {
      const reason = apiError(cause, '')
      setError(reason.startsWith('app_catalog_invalid_')
        ? t('catalog.invalidField', { field: reason.replace('app_catalog_invalid_', '') })
        : apiError(cause, t('errors.save')))
    } finally {
      setSaving(false)
    }
  }

  async function remove(entry: CatalogEntry) {
    if (!(await confirm({
      title: t('catalog.removeTitle'),
      message: t('catalog.removeMessage', { name: entry.name }),
      confirmLabel: t('catalog.removeConfirm'),
      dangerous: true,
    }))) return
    try {
      await api.delete(`/admin/app-catalog/${entry.code}`)
      load()
    } catch (cause) {
      setError(apiError(cause, t('errors.save')))
    }
  }

  function field(key: keyof CatalogEntry, label: string, mono = false) {
    return (
      <div>
        <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor={`catalog-${key}`}>{label}</label>
        <input
          id={`catalog-${key}`}
          type="text"
          value={String(draft[key] ?? '')}
          onChange={event => setDraft(current => ({ ...current, [key]: event.target.value }))}
          className={mono ? `${INPUT_CLASS} font-mono text-xs` : INPUT_CLASS}
        />
      </div>
    )
  }

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.tools'), href: '/tools-settings' },
        { label: t('catalog.title') },
      ]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('catalog.title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('catalog.subtitle')}</p>

      {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {message && <div className="mb-4 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{message}</div>}

      <div className="mb-5 rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/40">
        <h2 className="mb-3 text-sm font-semibold text-slate-800 dark:text-slate-200">{t('catalog.editTitle')}</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {field('code', t('catalog.code'), true)}
          {field('name', t('catalog.name'))}
          {field('version', t('catalog.version'), true)}
        </div>
        <div className="mt-3 grid gap-3">
          {field('download_url', t('catalog.url'), true)}
          {field('sha256', t('catalog.sha256'), true)}
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          {field('archive_name', t('catalog.archiveName'), true)}
          <div>
            <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="catalog-strip">
              {t('catalog.strip')}
            </label>
            <input
              id="catalog-strip"
              type="number"
              min={0}
              max={8}
              value={draft.strip_components}
              onChange={event => setDraft(current => ({ ...current, strip_components: Number(event.target.value) }))}
              className={INPUT_CLASS}
            />
          </div>
          <div className="flex flex-col justify-end gap-2 pb-1">
            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input type="checkbox" checked={draft.needs_database}
                onChange={event => setDraft(current => ({ ...current, needs_database: event.target.checked }))}
                className="h-4 w-4 rounded border-slate-300 dark:border-slate-600" />
              {t('catalog.needsDatabase')}
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input type="checkbox" checked={draft.enabled}
                onChange={event => setDraft(current => ({ ...current, enabled: event.target.checked }))}
                className="h-4 w-4 rounded border-slate-300 dark:border-slate-600" />
              {t('catalog.enabled')}
            </label>
          </div>
        </div>

        <p className="mt-3 text-xs text-slate-500 dark:text-slate-500">{t('catalog.pinNote')}</p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('catalog.stripNote')}</p>

        <button
          type="button"
          onClick={save}
          disabled={saving || !draft.code.trim()}
          className="mt-4 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {saving ? t('catalog.saving') : t('catalog.save')}
        </button>
      </div>

      <div className={responsiveTableContainerClass}>
        <table className={responsiveTableClass}>
          <thead className={responsiveTableHeadClass}>
            <tr>
              <th className="px-3 py-2 text-left">{t('catalog.name')}</th>
              <th className="px-3 py-2 text-left">{t('catalog.version')}</th>
              <th className="px-3 py-2 text-left">{t('catalog.sha256')}</th>
              <th className="px-3 py-2 text-left">{t('catalog.enabled')}</th>
              <th className="px-3 py-2 text-right">{t('list.actions')}</th>
            </tr>
          </thead>
          <tbody className={responsiveTableBodyClass}>
            {loading && (
              <tr className={responsiveTableRowClass}>
                <td className={responsiveTableCellClass} colSpan={5}>{t('list.loading')}</td>
              </tr>
            )}
            {!loading && entries.map(entry => (
              <tr key={entry.code} className={responsiveTableRowClass}>
                <td className={responsiveTableCellClass} data-label={t('catalog.name')}>
                  {entry.name} <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{entry.code}</span>
                </td>
                <td className={`${responsiveTableCellClass} font-mono text-xs`} data-label={t('catalog.version')}>{entry.version}</td>
                <td className={responsiveTableCellClass} data-label={t('catalog.sha256')}>
                  {entry.sha256
                    ? <span className="font-mono text-xs">{entry.sha256.slice(0, 12)}…</span>
                    : <span className="text-xs text-amber-700 dark:text-amber-300">{t('catalog.noPin')}</span>}
                </td>
                <td className={responsiveTableCellClass} data-label={t('catalog.enabled')}>
                  {entry.enabled ? t('catalog.yes') : t('catalog.no')}
                </td>
                <td className={responsiveTableActionCellClass} data-label={t('list.actions')}>
                  <button type="button" onClick={() => setDraft(entry)}
                    className="mr-2 rounded-lg border border-slate-300 px-2.5 py-1 text-xs text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800">
                    {t('catalog.edit')}
                  </button>
                  <button type="button" onClick={() => remove(entry)}
                    className="rounded-lg border border-red-300 px-2.5 py-1 text-xs text-red-700 hover:bg-red-50 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-900/20">
                    {t('catalog.remove')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
