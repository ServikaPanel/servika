import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'

// System-wide backup settings: the master switch, the disk guard, and ONE
// off-site destination every domain's backup is copied to. Admin only; the
// endpoints behind it are AdminOnly, so the card renders nothing for anyone else.

type Settings = {
  enabled: boolean
  min_free_gb: number
  max_store_gb: number
  remote_enabled: boolean
  remote_type: string
  remote_host: string
  remote_port: number
  remote_username: string
  remote_password?: string
  remote_dir: string
  delete_local: boolean
  last_upload?: string
  last_status?: string
  last_error?: string
  free_gb: number
  store_gb: number
}

const inputClass =
  'w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 ' +
  'bg-white dark:bg-slate-900/40 text-slate-900 dark:text-slate-100 ' +
  'focus:outline-none focus:ring-2 focus:ring-sky-500/40'
const labelClass = 'block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1'

function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      onClick={() => onChange(!on)}
      className={
        'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ' +
        'focus:outline-none focus:ring-2 focus:ring-sky-500/40 ' +
        (on ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600')
      }
    >
      <span
        className={
          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform ' +
          (on ? 'translate-x-6' : 'translate-x-1')
        }
      />
    </button>
  )
}

export default function BackupSettings() {
  const { t } = useTranslation('BackupSettings')
  const isAdmin = useAuth((s) => s.username?.role) === 'admin'
  const [s, setS] = useState<Settings | null>(null)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    if (!isAdmin) return
    api
      .get<Settings>('/admin/backups/settings')
      .then((r) => setS({ ...r.data, remote_password: '' }))
      .catch((e) => setError(apiError(e, t('loadError'))))
  }, [isAdmin, t])

  if (!isAdmin || !s) return null

  function set<K extends keyof Settings>(k: K, v: Settings[K]) {
    setS((o) => (o ? { ...o, [k]: v } : o))
  }

  async function save() {
    if (!s) return
    setError(null)
    setSuccess(null)
    setSaving(true)
    try {
      await api.put('/admin/backups/settings', s)
      const { data } = await api.get<Settings>('/admin/backups/settings')
      setS({ ...data, remote_password: '' })
      setSuccess(t('saved'))
    } catch (e) {
      setError(apiError(e, t('saveError')))
    } finally {
      setSaving(false)
    }
  }

  async function test() {
    if (!s) return
    setError(null)
    setSuccess(null)
    setTesting(true)
    try {
      const { data } = await api.post<{ ok: boolean; error?: string }>('/admin/backups/settings/test', s)
      if (data.ok) setSuccess(t('connectionOk'))
      else setError(String(data.error || ''))
    } catch (e) {
      setError(apiError(e))
    } finally {
      setTesting(false)
    }
  }

  const lowSpace = s.min_free_gb > 0 && s.free_gb < s.min_free_gb

  return (
    <div className="mb-5 rounded-2xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60 flex items-center gap-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('title')}</h3>
        <span className="ml-auto text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
          {t('freeSpace')}: <strong className={lowSpace ? 'text-red-600 dark:text-red-400' : ''}>{s.free_gb.toFixed(1)} GB</strong>
          {' · '}
          {t('backupStore')}: <strong>{s.store_gb.toFixed(1)} GB</strong>
        </span>
      </div>

      <div className="p-4 space-y-5">
        {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
        {success && <div className="px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

        {/* Master switch */}
        <div className="flex items-start gap-3">
          <Toggle on={s.enabled} onChange={(v) => set('enabled', v)} label={t('autoBackup')} />
          <div>
            <div className="text-sm font-medium text-slate-800 dark:text-slate-100">
              {t('autoBackup')} — <span className={s.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'}>{s.enabled ? t('on') : t('off')}</span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('autoBackupHint')}</p>
          </div>
        </div>

        {/* Disk guard */}
        <div>
          <div className="text-sm font-medium text-slate-800 dark:text-slate-100 mb-2">{t('diskProtection')}</div>
          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className={labelClass} htmlFor="min-free">{t('minFree')}</label>
              <input id="min-free" type="number" min={0} className={inputClass} value={s.min_free_gb}
                onChange={(e) => set('min_free_gb', Number(e.target.value))} />
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('minFreeHint')}</p>
            </div>
            <div>
              <label className={labelClass} htmlFor="max-store">{t('maxStore')}</label>
              <input id="max-store" type="number" min={0} className={inputClass} value={s.max_store_gb}
                onChange={(e) => set('max_store_gb', Number(e.target.value))} />
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('unlimited')}</p>
            </div>
          </div>
        </div>

        {/* System-wide remote target */}
        <div>
          <div className="flex items-start gap-3 mb-3">
            <Toggle on={s.remote_enabled} onChange={(v) => set('remote_enabled', v)} label={t('remoteTarget')} />
            <div>
              <div className="text-sm font-medium text-slate-800 dark:text-slate-100">{t('remoteTarget')}</div>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('remoteTargetHint')}</p>
            </div>
          </div>

          {s.remote_enabled && (
            <div className="pl-0 sm:pl-14 space-y-3">
              <div className="grid sm:grid-cols-4 gap-3">
                <div>
                  <label className={labelClass} htmlFor="remote-type">{t('type')}</label>
                  <select id="remote-type" className={inputClass} value={s.remote_type}
                    onChange={(e) => { set('remote_type', e.target.value); set('remote_port', e.target.value === 'ftp' ? 21 : 22) }}>
                    <option value="sftp">SFTP</option>
                    <option value="ftp">FTP</option>
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <label className={labelClass} htmlFor="remote-host">{t('host')}</label>
                  <input id="remote-host" className={inputClass} value={s.remote_host} placeholder="backup.example.com"
                    onChange={(e) => set('remote_host', e.target.value)} />
                </div>
                <div>
                  <label className={labelClass} htmlFor="remote-port">{t('port')}</label>
                  <input id="remote-port" type="number" min={1} max={65535} className={inputClass} value={s.remote_port}
                    onChange={(e) => set('remote_port', Number(e.target.value))} />
                </div>
              </div>
              <div className="grid sm:grid-cols-3 gap-3">
                <div>
                  <label className={labelClass} htmlFor="remote-user">{t('user')}</label>
                  <input id="remote-user" className={inputClass} value={s.remote_username} autoComplete="off"
                    onChange={(e) => set('remote_username', e.target.value)} />
                </div>
                <div>
                  <label className={labelClass} htmlFor="remote-pass">{t('password')}</label>
                  <input id="remote-pass" type="password" className={inputClass} value={s.remote_password || ''} autoComplete="new-password"
                    placeholder={t('passwordHint')}
                    onChange={(e) => set('remote_password', e.target.value)} />
                </div>
                <div>
                  <label className={labelClass} htmlFor="remote-dir">{t('remoteDir')}</label>
                  <input id="remote-dir" className={inputClass} value={s.remote_dir}
                    onChange={(e) => set('remote_dir', e.target.value)} />
                </div>
              </div>

              <div className="flex items-start gap-3">
                <Toggle on={s.delete_local} onChange={(v) => set('delete_local', v)} label={t('deleteLocal')} />
                <div>
                  <div className="text-sm text-slate-800 dark:text-slate-100">{t('deleteLocal')}</div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">{t('deleteLocalHint')}</p>
                </div>
              </div>

              {s.last_upload && (
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {t('lastUpload')}: {s.last_upload} — {s.last_status === 'successful'
                    ? <span className="text-emerald-600 dark:text-emerald-400">{t('statusOk')}</span>
                    : <span className="text-red-600 dark:text-red-400">{t('statusError')}{s.last_error ? ': ' + s.last_error : ''}</span>}
                </p>
              )}

              <button type="button" onClick={test} disabled={testing}
                className="px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700/40 disabled:opacity-50">
                {testing ? t('testing') : t('testConnection')}
              </button>
            </div>
          )}
        </div>

        <div className="pt-1">
          <button type="button" onClick={save} disabled={saving}
            className="px-3.5 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 dark:bg-slate-700 dark:hover:bg-slate-600 text-white dark:text-slate-100 rounded-lg disabled:opacity-50">
            {saving ? t('saving') : t('save')}
          </button>
        </div>
      </div>
    </div>
  )
}
