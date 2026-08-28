import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import ResourceNotice from '@/components/ResourceNotice'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Status = {
  enabled: boolean
  host: string
  port: number
  username: string
  password?: string
  prefix: string
  wp_snippet?: string
  wp_connected?: number
}

export default function RedisPage() {
  const { t } = useTranslation('RedisPage')
  const { confirm } = useDialog()
  const { id } = useParams()
  const [status, setStatus] = useState<Status | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

  // Split so the mount effect never writes state synchronously: fetchStatus
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a write.
  const fetchStatus = useCallback(() => {
    api.get<Status>(`/domains/${id}/redis`)
      .then(response => setStatus(response.data))
      .catch(error => setError(apiError(error)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    fetchStatus()
  }, [fetchStatus])

  useEffect(() => { fetchStatus() }, [fetchStatus])

  async function enable() {
    setError(null); setSuccess(null); setBusy(true)
    try {
      const { data } = await api.post<Status>(`/domains/${id}/redis`, {})
      setStatus(data)
      setSuccess(data.wp_connected && data.wp_connected > 0
        ? t('success.enabledWithWp', { count: data.wp_connected })
        : t('success.enabled'))
    } catch (error) { setError(apiError(error, t('error.enable'))) }
    finally { setBusy(false) }
  }
  async function disable() {
    if (!(await confirm({ message: t('confirm.disable'), dangerous: true }))) return
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.delete(`/domains/${id}/redis`)
      load()
      setSuccess(t('success.disabled'))
    } catch (error) { setError(apiError(error, t('error.disable'))) }
    finally { setBusy(false) }
  }

  function copy(text: string, label: string) {
    navigator.clipboard?.writeText(text)
    setCopied(label)
    setTimeout(() => setCopied(null), 1500)
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' }, { label: t('breadcrumb.redisCache') }]} />
      <div className="flex items-center gap-3 mb-1">
        <span className="text-amber-500 dark:text-amber-400"><Icon d={ICON.bolt} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        {status && (
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${status.enabled
            ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300'
            : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'}`}>
            {status.enabled ? t('status.active') : t('status.disabled')}
          </span>
        )}
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
        {t('subtitle.pre')}<strong>{t('subtitle.bold')}</strong>{t('subtitle.post')}
      </p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? (
        <div className="py-12 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : !status?.enabled ? (
        <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-6 text-center">
          <div className="mb-2 flex justify-center text-amber-500 dark:text-amber-400"><Icon d={ICON.bolt} className="h-8 w-8" /></div>
          <p className="text-sm text-slate-600 dark:text-slate-300 mb-1">{t('empty.message')}</p>
          <p className="text-xs text-slate-400 mb-4">{t('empty.hint')}</p>
          {/* The cache process is shared by the whole server, so its cost is not
              charged to the domain being configured. */}
          <div className="flex justify-center mb-4">
            <ResourceNotice>{t('empty.resourceWarning')}</ResourceNotice>
          </div>
          <button onClick={enable} disabled={busy}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {busy ? t('empty.enabling') : t('empty.enable')}
          </button>
        </div>
      ) : (
        <>
          {/* Connection details */}
          <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl overflow-hidden mb-4">
            <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('connection.title')}</h3>
              <button onClick={disable} disabled={busy}
                className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">
                {t('connection.disable')}
              </button>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-700/60">
              <CopyRow label={t('connection.host')} value={`${status.host}:${status.port}`} onCopy={copy} copied={copied} />
              <CopyRow label={t('connection.username')} value={status.username} onCopy={copy} copied={copied} />
              <CopyRow label={t('connection.password')} value={status.password || ''} secret onCopy={copy} copied={copied} />
              <CopyRow label={t('connection.keyPrefix')} value={status.prefix} onCopy={copy} copied={copied} />
            </div>
          </div>

          {/* WordPress snippet */}
          {status.wp_snippet && (
            <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('wp.title')}</h3>
                <button onClick={() => copy(status.wp_snippet!, 'wp')}
                  className="text-xs px-2.5 py-1 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-md">
                  {copied === 'wp' ? t('wp.copied') : t('wp.copy')}
                </button>
              </div>
              <div className="p-4">
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                  {t('wp.instructionsPre')}<code className="font-mono bg-slate-100 dark:bg-slate-900 px-1 rounded">{t('wp.instructionsFile')}</code>{t('wp.instructionsMid')}<strong>{t('wp.instructionsBold')}</strong>{t('wp.instructionsPost')}
                </p>
                <pre className="text-[11px] font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg p-3 overflow-x-auto text-slate-700 dark:text-slate-200 whitespace-pre">{status.wp_snippet}</pre>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function CopyRow({ label, value, secret, onCopy, copied }: {
  label: string; value: string; secret?: boolean
  onCopy: (text: string, label: string) => void; copied: string | null
}) {
  const { t } = useTranslation('RedisPage')
  const [visible, setVisible] = useState(false)
  const displayedValue = secret && !visible ? '•'.repeat(Math.min(value.length, 20)) : value
  return (
    <div className="flex items-center gap-3 px-4 py-2.5">
      <span className="text-xs text-slate-500 dark:text-slate-400 w-28 shrink-0">{label}</span>
      <span className="flex-1 font-mono text-xs text-slate-800 dark:text-slate-200 truncate">{displayedValue}</span>
      {secret && (
        <button onClick={() => setVisible(current => !current)} className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
          {visible ? t('row.hide') : t('row.show')}
        </button>
      )}
      <button onClick={() => onCopy(value, label)}
        className="text-xs px-2 py-0.5 border border-slate-200 dark:border-slate-700 rounded text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">
        {copied === label ? t('row.copied') : t('row.copy')}
      </button>
    </div>
  )
}
