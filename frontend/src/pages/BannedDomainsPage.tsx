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

type BannedDomain = {
  domain: string
  description: string
  match_subdomains: boolean
  created_by: string
  created_at: string
}

type WriteResult = {
  applied: number
  skipped: number
  rejected: string[]
}

const INPUT_CLASS = 'w-full px-2.5 py-1.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

/** Renders the server-wide list of hostnames no tenant may add. */
export default function BannedDomainsPage() {
  const { t } = useTranslation('BannedDomainsPage')
  const dialog = useDialog()
  const [rows, setRows] = useState<BannedDomain[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<WriteResult | null>(null)
  const [domains, setDomains] = useState('')
  const [description, setDescription] = useState('')
  const [matchSubdomains, setMatchSubdomains] = useState(true)
  const [filter, setFilter] = useState('')

  // Split so the mount effect never writes state synchronously; it settles
  // only through the promise callbacks.
  const fetchList = useCallback(() => {
    api.get<BannedDomain[]>('/admin/banned-domains')
      .then(response => setRows(response.data || []))
      .catch(cause => setError(apiError(cause, t('errors.loadFailed'))))
      .finally(() => setLoading(false))
  }, [t])

  const reload = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchList()
  }, [fetchList])

  useEffect(() => { fetchList() }, [fetchList])

  async function addDomains() {
    if (!domains.trim()) return
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      const response = await api.post<WriteResult>('/admin/banned-domains', {
        domains,
        description,
        match_subdomains: matchSubdomains,
      })
      setResult(response.data)
      setDomains('')
      setDescription('')
      reload()
    } catch (cause) {
      setError(apiError(cause, t('errors.saveFailed')))
    } finally {
      setSaving(false)
    }
  }

  async function removeDomain(domain: string) {
    const confirmed = await dialog.confirm({
      title: t('remove.title'),
      message: t('remove.message', { domain }),
      confirmLabel: t('remove.confirm'),
      dangerous: true,
    })
    if (!confirmed) return
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      await api.post('/admin/banned-domains/remove', { domains: domain })
      reload()
    } catch (cause) {
      setError(apiError(cause, t('errors.saveFailed')))
    } finally {
      setSaving(false)
    }
  }

  const needle = filter.trim().toLowerCase()
  const visible = needle
    ? rows.filter(row => row.domain.includes(needle) || row.description.toLowerCase().includes(needle))
    : rows

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.tools'), href: '/tools-settings' },
        { label: t('breadcrumb.current') },
      ]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      {result && (
        <div className="mb-4 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">
          <div>{t('result.applied')}: {result.applied}</div>
          {result.skipped > 0 && <div>{t('result.skipped')}: {result.skipped}</div>}
          {result.rejected.length > 0 && (
            <div className="mt-1 text-red-700 dark:text-red-300">
              {t('result.rejected')}:{' '}
              <span className="font-mono">{result.rejected.join(', ')}</span>
            </div>
          )}
        </div>
      )}

      <div className="mb-5 rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/40">
        <h2 className="mb-3 text-sm font-semibold text-slate-800 dark:text-slate-200">{t('add.title')}</h2>
        <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="banned-domains">
          {t('add.domainsLabel')}
        </label>
        <textarea
          id="banned-domains"
          rows={4}
          value={domains}
          onChange={event => setDomains(event.target.value)}
          placeholder={t('add.domainsPlaceholder')}
          className={`${INPUT_CLASS} font-mono`}
        />
        <p className="mt-1 mb-3 text-xs text-slate-500 dark:text-slate-500">{t('add.domainsHint')}</p>

        <label className="mb-1 block text-xs text-slate-500 dark:text-slate-400" htmlFor="banned-description">
          {t('add.descriptionLabel')}
        </label>
        <input
          id="banned-description"
          type="text"
          value={description}
          onChange={event => setDescription(event.target.value)}
          placeholder={t('add.descriptionPlaceholder')}
          className={INPUT_CLASS}
        />

        <label className="mt-3 flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
          <input
            type="checkbox"
            checked={matchSubdomains}
            onChange={event => setMatchSubdomains(event.target.checked)}
            className="h-4 w-4 rounded border-slate-300 dark:border-slate-600"
          />
          {t('add.matchSubdomains')}
        </label>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('add.matchSubdomainsHint')}</p>

        <button
          type="button"
          onClick={addDomains}
          disabled={saving || !domains.trim()}
          className="mt-4 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {saving ? t('add.saving') : t('add.submit')}
        </button>
      </div>

      <div className="mb-3 flex items-center justify-between gap-3">
        <input
          type="search"
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder={t('list.filterPlaceholder')}
          className={`${INPUT_CLASS} max-w-xs`}
        />
        <span className="text-xs text-slate-500 dark:text-slate-500">
          {t('list.count')}: {visible.length}
        </span>
      </div>

      <div className={responsiveTableContainerClass}>
        <table className={responsiveTableClass}>
          <thead className={responsiveTableHeadClass}>
            <tr>
              <th className="px-3 py-2 text-left">{t('list.domain')}</th>
              <th className="px-3 py-2 text-left">{t('list.scope')}</th>
              <th className="px-3 py-2 text-left">{t('list.description')}</th>
              <th className="px-3 py-2 text-left">{t('list.createdBy')}</th>
              <th className="px-3 py-2 text-left">{t('list.createdAt')}</th>
              <th className="px-3 py-2 text-right">{t('list.actions')}</th>
            </tr>
          </thead>
          <tbody className={responsiveTableBodyClass}>
            {loading && (
              <tr className={responsiveTableRowClass}>
                <td className={responsiveTableCellClass} colSpan={6}>{t('list.loading')}</td>
              </tr>
            )}
            {!loading && visible.length === 0 && (
              <tr className={responsiveTableRowClass}>
                <td className={responsiveTableCellClass} colSpan={6}>{t('list.empty')}</td>
              </tr>
            )}
            {!loading && visible.map(row => (
              <tr key={row.domain} className={responsiveTableRowClass}>
                <td className={`${responsiveTableCellClass} font-mono`} data-label={t('list.domain')}>{row.domain}</td>
                <td className={responsiveTableCellClass} data-label={t('list.scope')}>
                  {row.match_subdomains ? t('list.scopeWithSubdomains') : t('list.scopeExact')}
                </td>
                <td className={responsiveTableCellClass} data-label={t('list.description')}>{row.description}</td>
                <td className={responsiveTableCellClass} data-label={t('list.createdBy')}>{row.created_by}</td>
                <td className={responsiveTableCellClass} data-label={t('list.createdAt')}>{row.created_at}</td>
                <td className={responsiveTableActionCellClass} data-label={t('list.actions')}>
                  <button
                    type="button"
                    onClick={() => removeDomain(row.domain)}
                    disabled={saving}
                    className="rounded-lg border border-red-300 px-2.5 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-900/20"
                  >
                    {t('list.remove')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('footnote')}</p>
    </div>
  )
}
