import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

type Listed = {
  interface: string
  ip: string
  prefix: number
  label: string
  scope: string
  panel_added: boolean
  record?: { id: number; note: string; added_at: string }
  removable: boolean
  refusal_reason?: string
}

/*
 * The server's addresses.
 *
 * The list is what the HOST reports, annotated with what the panel knows, and
 * never the other way round: an address configured outside the panel is the one
 * that most needs showing and must not carry a remove button. A row that cannot
 * be removed says why, because "the button is missing" and "the button is
 * missing for a reason" look identical otherwise.
 */
export default function ServerIPsPage() {
  const { t } = useTranslation('ServerIPs')
  const dialog = useDialog()

  // The API answers English because the API is English; the reason CODE is what
  // this maps into the reader's own language.
  const reasonText = useCallback((err: unknown, fallbackKey: string) => {
    const reason = apiReason(err)
    if (reason) {
      const translated = t(`reason.${reason}`, { defaultValue: '' })
      if (translated) return translated
    }
    return apiError(err, t(fallbackKey))
  }, [t])

  const [rows, setRows] = useState<Listed[] | null>(null)
  const [loadError, setLoadError] = useState('')
  const [busy, setBusy] = useState(false)
  const [ip, setIP] = useState('')
  const [prefix, setPrefix] = useState('32')
  const [device, setDevice] = useState('')
  const [note, setNote] = useState('')

  const load = useCallback(() => {
    return api
      .get<{ addresses: Listed[] }>('/system/ips')
      .then((response) => {
        setLoadError('')
        setRows(response.data.addresses ?? [])
      })
      .catch((err) => {
        setRows([])
        setLoadError(reasonText(err, 'error.load'))
      })
  }, [reasonText])

  useEffect(() => {
    void load()
  }, [load])

  // The interface list is taken from what the host reported, so the form can
  // only ever name a device that exists. The backend checks it again.
  const interfaces = useMemo(() => {
    const seen = new Set<string>()
    for (const row of rows ?? []) seen.add(row.interface)
    return [...seen].sort()
  }, [rows])

  const add = async () => {
    setBusy(true)
    try {
      await api.post('/system/ips', {
        ip: ip.trim(),
        prefix: Number(prefix) || 32,
        interface: device,
        note: note.trim(),
      })
      setIP('')
      setNote('')
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('add.failedTitle'),
        message: reasonText(err, 'error.add'),
        tone: 'error',
      })
    } finally {
      setBusy(false)
    }
  }

  const remove = async (row: Listed) => {
    if (!row.record) return
    const confirmed = await dialog.confirm({
      title: t('remove.confirmTitle'),
      message: t('remove.confirmBody', { ip: row.ip, interface: row.interface }),
      confirmLabel: t('remove.confirmAction'),
      dangerous: true,
    })
    if (!confirmed) return

    setBusy(true)
    try {
      await api.delete(`/system/ips/${row.record.id}`)
      await load()
    } catch (err) {
      await dialog.notify({
        title: t('remove.failedTitle'),
        message: reasonText(err, 'error.remove'),
        tone: 'error',
      })
      await load()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.toolsAndSettings'), href: '/tools-settings' },
        { label: t('breadcrumb.serverIPs') },
      ]} />

      <div className="mb-5 max-w-3xl">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="mt-1 text-sm leading-relaxed text-slate-500 dark:text-slate-400">{t('description')}</p>
      </div>

      {loadError && (
        <p className="mb-4 max-w-3xl rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
          {loadError}
        </p>
      )}

      <section className="mb-6 max-w-4xl rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('add.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('add.description')}</p>

        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <label className="text-sm">
            <span className="block text-slate-600 dark:text-slate-300">{t('add.ip')}</span>
            <input
              value={ip}
              onChange={(event) => setIP(event.target.value)}
              placeholder="198.51.100.10"
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm dark:border-slate-600 dark:bg-slate-900"
            />
          </label>
          <label className="text-sm">
            <span className="block text-slate-600 dark:text-slate-300">{t('add.prefix')}</span>
            <input
              value={prefix}
              onChange={(event) => setPrefix(event.target.value)}
              inputMode="numeric"
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm dark:border-slate-600 dark:bg-slate-900"
            />
          </label>
          <label className="text-sm">
            <span className="block text-slate-600 dark:text-slate-300">{t('add.interface')}</span>
            <select
              value={device}
              onChange={(event) => setDevice(event.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-900"
            >
              <option value="">{t('add.interfaceAuto')}</option>
              {interfaces.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </label>
          <label className="text-sm">
            <span className="block text-slate-600 dark:text-slate-300">{t('add.note')}</span>
            <input
              value={note}
              onChange={(event) => setNote(event.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-900"
            />
          </label>
        </div>

        <button
          type="button"
          onClick={() => void add()}
          disabled={busy || ip.trim() === ''}
          className="mt-4 rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {t('add.button')}
        </button>
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('add.ipv4Only')}</p>
      </section>

      <section className="max-w-4xl rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('list.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('list.description')}</p>

        {rows === null ? (
          <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">{t('list.loading')}</p>
        ) : rows.length === 0 ? (
          <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">{t('list.none')}</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                <tr>
                  <th className="py-2 pr-4">{t('list.address')}</th>
                  <th className="py-2 pr-4">{t('list.interface')}</th>
                  <th className="py-2 pr-4">{t('list.origin')}</th>
                  <th className="py-2 pr-4">{t('list.note')}</th>
                  <th className="py-2">{t('list.action')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                {rows.map((row) => (
                  <tr key={`${row.interface}-${row.ip}`}>
                    <td className="py-2 pr-4 align-top font-mono text-xs text-slate-900 dark:text-slate-100">
                      {row.ip}/{row.prefix}
                    </td>
                    <td className="py-2 pr-4 align-top text-xs text-slate-600 dark:text-slate-300">{row.interface}</td>
                    <td className="py-2 pr-4 align-top text-xs text-slate-600 dark:text-slate-300">
                      {row.panel_added ? t('list.originPanel') : t('list.originHost')}
                    </td>
                    <td className="py-2 pr-4 align-top text-xs text-slate-500 dark:text-slate-400">
                      {row.record?.note || ''}
                    </td>
                    <td className="py-2 align-top">
                      {row.removable && row.record ? (
                        <button
                          type="button"
                          onClick={() => void remove(row)}
                          disabled={busy}
                          className="rounded border border-rose-300 px-2 py-1 text-xs text-rose-700 disabled:opacity-50 dark:border-rose-700 dark:text-rose-300"
                        >
                          {t('list.remove')}
                        </button>
                      ) : (
                        // A row without a button says WHY. Otherwise "no button"
                        // and "no button for a reason" look the same.
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {row.refusal_reason
                            ? t(`reason.${row.refusal_reason}`, { defaultValue: t('list.notRemovable') })
                            : t('list.notRecorded')}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
