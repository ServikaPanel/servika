import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import ConfirmDialog from '@/components/ConfirmDialog'
import RestoreDialog, { type RestorePayload } from '@/components/RestoreDialog'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
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
type Backup = { id: number; domain_id: number; type: string; file: string; size_b: number; notes: string; created_at: string; verification?: string }
type Schedule = { freq: 'none' | 'daily' | 'weekly'; hour: number; retention: number; last_backup_at?: string }
type DestType = 'ftp' | 'sftp' | 's3' | 'b2'
type Destination = {
  missing?: boolean
  id?: number; type?: DestType; host?: string; port?: number
  username?: string; remote_dir?: string; active?: boolean
  bucket?: string; region?: string; endpoint?: string; path_style?: boolean
  last_upload?: string; last_status?: string; last_error?: string
}

export default function DomainBackupsPage() {
  const { t } = useTranslation('DomainBackupsPage')
  const { confirm, notify } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [backups, setBackups] = useState<Backup[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [processing, setProcessing] = useState(false)
  const [backupToDelete, setBackupToDelete] = useState<Backup | null>(null)
  const [restoreBackup, setRestoreBackup] = useState<Backup | null>(null)

  const [sched, setSched] = useState<Schedule>({ freq: 'none', hour: 3, retention: 7 })
  const [scheduleSaving, setScheduleSaving] = useState(false)

  const [dest, setDest] = useState<Destination>({ missing: true })
  const [destForm, setDestForm] = useState({
    type: 'sftp' as DestType, host: '', port: 22, username: '', password: '',
    remote_dir: '/', bucket: '', region: '', endpoint: '', path_style: false, active: true,
  })
  const [destinationSaving, setDestinationSaving] = useState(false)
  const [destTest, setDestTest] = useState<{ ok: boolean; error?: string } | null>(null)

  // Split so the mount effect never writes state synchronously: fetchBackups
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchBackups = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<Backup[]>(`/domains/${id}/backups`),
      api.get<Schedule>(`/domains/${id}/backup-schedule`).catch(() => ({ data: { freq: 'none', hour: 3, retention: 7 } as Schedule })),
      api.get<Destination>(`/domains/${id}/backup-destination`).catch(() => ({ data: { missing: true } as Destination })),
    ]).then(([y, s, d]) => {
      setBackups(y.data)
      setSched(s.data)
      setDest(d.data)
      if (!d.data.missing) {
        setDestForm({
          type: (d.data.type || 'sftp') as DestType,
          host: d.data.host || '',
          port: d.data.port || (d.data.type === 'ftp' ? 21 : 22),
          username: d.data.username || '',
          password: '',  // Security: leave blank unless the user chooses to enter it again.
          remote_dir: d.data.remote_dir || '/',
          bucket: d.data.bucket || '',
          region: d.data.region || '',
          endpoint: d.data.endpoint || '',
          path_style: !!d.data.path_style,
          active: !!d.data.active,
        })
      }
    })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    fetchBackups()
  }, [fetchBackups])

  async function saveDest() {
    setDestinationSaving(true); setError(null); setSuccess(null); setDestTest(null)
    try {
      const r = await api.put<Destination>(`/domains/${id}/backup-destination`, destForm)
      setDest(r.data)
      setSuccess(t('toast.destinationSaved'))
      setTimeout(() => setSuccess(null), 4000)
    } catch (e) {
      setError(apiError(e, t('toast.destinationSaveFailed')))
    } finally {
      setDestinationSaving(false)
    }
  }

  async function testDestination() {
    setDestinationSaving(true); setDestTest(null)
    try {
      const r = await api.post<{ ok: boolean; error?: string }>(`/domains/${id}/backup-destination/test`, destForm)
      setDestTest(r.data)
      setTimeout(() => setDestTest(null), 8000)
    } catch (e) {
      setDestTest({ ok: false, error: apiError(e) })
    } finally {
      setDestinationSaving(false)
    }
  }

  async function destDelete() {
    if (!(await confirm({ message: t('toast.confirmDeleteDest'), dangerous: true }))) return
    setDestinationSaving(true)
    try {
      await api.delete(`/domains/${id}/backup-destination`)
      setDest({ missing: true })
      setDestForm({ type: 'sftp', host: '', port: 22, username: '', password: '', remote_dir: '/', bucket: '', region: '', endpoint: '', path_style: false, active: true })
      setSuccess(t('toast.destinationDeleted'))
      setTimeout(() => setSuccess(null), 4000)
    } catch (e) {
      setError(apiError(e))
    } finally {
      setDestinationSaving(false)
    }
  }
  useEffect(() => {
    if (id) api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    fetchBackups()
  }, [id, fetchBackups, report])

  async function saveSchedule(newSchedule: Schedule) {
    setScheduleSaving(true); setError(null); setSuccess(null)
    try {
      const r = await api.put<{ schedule: Schedule }>(`/domains/${id}/backup-schedule`, newSchedule)
      setSched(r.data.schedule)
      setSuccess(newSchedule.freq === 'none'
        ? t('toast.autoDisabled')
        : t('toast.autoEnabled', {
            freq: newSchedule.freq === 'daily' ? t('freq.daily') : t('freq.weekly'),
            hour: String(newSchedule.hour).padStart(2, '0'),
            retention: newSchedule.retention,
          }))
      setTimeout(() => setSuccess(null), 5000)
    } catch (e) {
      setError(apiError(e, t('toast.scheduleSaveFailed')))
    } finally {
      setScheduleSaving(false)
    }
  }

  async function create() {
    setProcessing(true); setError(null); setSuccess(null)
    try {
      await api.post(`/domains/${id}/backups`)
      setSuccess(t('toast.backupCreated'))
      load()
    } catch (e) {
      setError(apiError(e, t('toast.createFailed')))
    } finally {
      setProcessing(false)
    }
  }

  async function remove() {
    if (!backupToDelete) return
    try {
      await api.delete(`/domains/${id}/backups/${backupToDelete.id}`)
      setBackupToDelete(null); load()
    } catch (e) {
      await notify({ message: apiError(e), tone: 'error' })
    }
  }

  async function restore(payload: RestorePayload) {
    if (!restoreBackup) return
    setProcessing(true); setError(null); setSuccess(null)
    try {
      const { data } = await api.post(`/domains/${id}/backups/${restoreBackup.id}/restore`, payload)
      setSuccess(t('toast.restored', { domain: data.domain_name, detail: data.warning ?? '' }))
      setRestoreBackup(null)
    } catch (e) {
      setError(apiError(e, t('toast.restoreFailed')))
    } finally {
      setProcessing(false)
    }
  }

  function download(y: Backup) {
    // Auth via the HttpOnly session cookie (same-origin); no bearer header.
    fetch(`/api/v1/domains/${id}/backups/${y.id}/download`, { credentials: 'include' })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = y.file
        a.click()
      })
  }

  const isObjectStorage = destForm.type === 's3' || destForm.type === 'b2'
  const destIncomplete = isObjectStorage
    ? (!destForm.bucket || !destForm.username)
    : (!destForm.host || !destForm.username)

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.backups') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
        {', '}{t('subtitle.prefix')}{sched.freq === 'none'
          ? t('subtitle.disabled')
          : t('subtitle.enabled', {
              freq: sched.freq === 'daily' ? t('freq.daily') : t('freq.weekly'),
              hour: String(sched.hour).padStart(2, '0'),
              retention: sched.retention,
            })}
      </p>}

      {/* Automatic backup schedule */}
      <div className="mb-5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
        <div className="flex flex-col gap-3 mb-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('schedule.heading')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
              {t('schedule.description')}
            </p>
          </div>
          {sched.last_backup_at && (
            <div className="text-xs text-slate-500 dark:text-slate-500">{t('schedule.lastBackup')} <span className="font-mono">{sched.last_backup_at.replace('T',' ').replace('Z','')}</span></div>
          )}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(['none','daily','weekly'] as const).map(f => {
            const isSelected = sched.freq === f
            const meta: Record<string,{name:string;icon:string;description:string;color:string}> = {
              none: { name:t('schedule.options.none.name'), icon:ICON.pause, description:t('schedule.options.none.description'), color:'slate' },
              daily: { name:t('schedule.options.daily.name'), icon:ICON.moon, description:t('schedule.options.daily.description'), color:'emerald' },
              weekly: { name:t('schedule.options.weekly.name'), icon:ICON.calendar, description:t('schedule.options.weekly.description'), color:'indigo' },
            }
            const m = meta[f]
            const color: Record<string,string> = {
              slate:   isSelected ? 'border-slate-500 bg-slate-100 dark:bg-slate-800 ring-2 ring-slate-400/20'      : 'border-slate-200 dark:border-slate-700 hover:border-slate-400 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800',
              emerald: isSelected ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 ring-2 ring-emerald-500/20': 'border-slate-200 dark:border-slate-700 hover:border-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 dark:bg-emerald-900/20',
              indigo:  isSelected ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 ring-2 ring-indigo-500/20'   : 'border-slate-200 dark:border-slate-700 hover:border-indigo-300 hover:bg-indigo-50 dark:bg-indigo-900/20',
            }
            return (
              <button key={f} type="button" disabled={scheduleSaving || isSelected}
                onClick={() => saveSchedule({ ...sched, freq: f })}
                className={`text-left p-3 border rounded-lg transition disabled:cursor-default ${color[m.color]}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-600 dark:text-slate-300"><Icon d={m.icon} className="h-5 w-5" /></span>
                  {isSelected && <span className="text-[10px] uppercase tracking-wider font-semibold text-emerald-700 dark:text-emerald-300">{t('schedule.active')}</span>}
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{m.name}</div>
                <div className="text-[11px] text-slate-600 dark:text-slate-400 dark:text-slate-500 mt-1 leading-snug">{m.description}</div>
              </button>
            )
          })}
        </div>

        {sched.freq !== 'none' && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500">{t('schedule.runTime')}</span>
              <select
                value={sched.hour}
                onChange={e => saveSchedule({ ...sched, hour: Number(e.target.value) })}
                disabled={scheduleSaving}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm bg-white dark:bg-slate-800">
                {Array.from({length:24},(_,i)=>i).map(h =>
                  <option key={h} value={h}>{String(h).padStart(2,'0')}:00</option>
                )}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500">{t('schedule.retentionLabel')}</span>
              <input type="number" min={1} max={90} value={sched.retention}
                onChange={e => setSched(s => ({...s, retention: Math.max(1, Math.min(90, Number(e.target.value)||1))}))}
                onBlur={() => saveSchedule(sched)}
                disabled={scheduleSaving}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
              <span className="text-[10px] text-slate-500 dark:text-slate-500 mt-0.5 block">{t('schedule.retentionHint')}</span>
            </label>
          </div>
        )}
      </div>

      {/* Remote backup destination (FTP/SFTP) */}
      <div className="mb-5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
        <div className="flex flex-col gap-3 mb-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('destination.heading')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
              {t('destination.description')}
            </p>
          </div>
          {!dest.missing && dest.last_status && (
            <span className={`text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded ${
              dest.last_status === 'successful' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' :
              dest.last_status === 'error' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' :
              'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 dark:text-slate-500'
            }`}>{dest.last_status === 'successful' ? t('destination.statusSuccessful') : dest.last_status === 'error' ? t('destination.statusError') : dest.last_status}</span>
          )}
        </div>

        {!dest.missing && dest.last_upload && (
          <div className="mb-3 text-xs text-slate-500 dark:text-slate-500">
            {t('destination.lastUpload')} <span className="font-mono">{dest.last_upload}</span>
            {dest.last_status === 'error' && dest.last_error && (
              <div className="mt-1 text-[11px] text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-2 font-mono whitespace-pre-wrap">{dest.last_error}</div>
            )}
          </div>
        )}

        <div className="mb-3">
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.typeLabel')}</label>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {([
              { t: 'sftp' as const, label: t('destination.type.sftp'), port: 22 },
              { t: 'ftp' as const, label: t('destination.type.ftp'), port: 21 },
              { t: 's3' as const, label: t('destination.type.s3'), port: 443 },
              { t: 'b2' as const, label: t('destination.type.b2'), port: 443 },
            ]).map(o => {
              const isSelected = destForm.type === o.t
              return (
                <button key={o.t} type="button"
                  onClick={() => setDestForm(f => ({...f, type: o.t, port: o.port}))}
                  className={`text-xs px-3 py-2 rounded border ${isSelected ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300 font-semibold' : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800'}`}>
                  {o.label}
                </button>
              )
            })}
          </div>
        </div>

        {isObjectStorage ? (
          <div className="grid grid-cols-1 sm:grid-cols-6 gap-3 mb-3">
            <div className="sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.bucket')}</label>
              <input type="text" value={destForm.bucket} placeholder="my-backups"
                onChange={e => setDestForm(f => ({...f, bucket: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.region')} {destForm.type === 's3' && <span className="text-[10px] text-slate-400 dark:text-slate-500">{t('destination.regionHint')}</span>}</label>
              <input type="text" value={destForm.region} placeholder="us-east-1"
                onChange={e => setDestForm(f => ({...f, region: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-6">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.endpoint')} {destForm.type === 's3' && <span className="text-[10px] text-slate-400 dark:text-slate-500">{t('destination.endpointHint')}</span>}</label>
              <input type="text" value={destForm.endpoint} placeholder={destForm.type === 'b2' ? 's3.us-west-002.backblazeb2.com' : 'https://s3.example.com'}
                onChange={e => setDestForm(f => ({...f, endpoint: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.accessKeyId')}</label>
              <input type="text" value={destForm.username} autoComplete="off"
                onChange={e => setDestForm(f => ({...f, username: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.secretAccessKey')} {!dest.missing && <span className="text-[10px] text-slate-400 dark:text-slate-500">{t('destination.secretKeepHint')}</span>}</label>
              <input type="password" value={destForm.password} autoComplete="new-password"
                onChange={e => setDestForm(f => ({...f, password: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-4">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.keyPrefix')}</label>
              <input type="text" value={destForm.remote_dir} placeholder="/"
                onChange={e => setDestForm(f => ({...f, remote_dir: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-2 flex items-end">
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                <input type="checkbox" checked={destForm.path_style}
                  onChange={e => setDestForm(f => ({...f, path_style: e.target.checked}))}
                  className="cursor-pointer"/>
                {t('destination.pathStyle')}
              </label>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-6 gap-3 mb-3">
            <div className="sm:col-span-4">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.host')}</label>
              <input type="text" value={destForm.host} placeholder="backup.firma.com"
                onChange={e => setDestForm(f => ({...f, host: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.port')}</label>
              <input type="number" value={destForm.port}
                onChange={e => setDestForm(f => ({...f, port: Number(e.target.value)||0}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.username')}</label>
              <input type="text" value={destForm.username} autoComplete="off"
                onChange={e => setDestForm(f => ({...f, username: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.password')} {!dest.missing && <span className="text-[10px] text-slate-400 dark:text-slate-500">{t('destination.passwordKeepHint')}</span>}</label>
              <input type="password" value={destForm.password} autoComplete="new-password"
                onChange={e => setDestForm(f => ({...f, password: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('destination.remoteDir')}</label>
              <input type="text" value={destForm.remote_dir}
                onChange={e => setDestForm(f => ({...f, remote_dir: e.target.value}))}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono"/>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between flex-wrap gap-3">
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
            <input type="checkbox" checked={destForm.active}
              onChange={e => setDestForm(f => ({...f, active: e.target.checked}))}
              className="cursor-pointer"/>
            {t('destination.activeLabel')}
          </label>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            {destTest && (
              <span className={`text-xs px-2 py-1 rounded font-medium ${destTest.ok ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'}`}>
                {destTest.ok ? t('destination.testSuccess') : t('destination.testError') + (destTest.error?.slice(0, 80) || t('destination.testErrorFallback'))}
              </span>
            )}
            <button type="button" onClick={testDestination} disabled={destinationSaving || destIncomplete}
              className="text-xs px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 disabled:opacity-50">
              {destinationSaving ? t('destination.testing') : t('destination.testConnection')}
            </button>
            <button type="button" onClick={saveDest} disabled={destinationSaving || destIncomplete}
              className="text-xs px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 rounded font-medium">
              {t('destination.save')}
            </button>
            {!dest.missing && (
              <button type="button" onClick={destDelete} disabled={destinationSaving}
                className="text-xs px-3 py-1.5 border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 rounded">
                {t('destination.deleteDestination')}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2 mb-4 sm:flex-row sm:items-center">
        <button onClick={create} disabled={processing} className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
          {processing ? t('backingUp') : t('backupNow')}
        </button>
        <button onClick={load} className="px-3 py-2 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-sm rounded-md">{t('refresh')}</button>
        <span className="text-sm text-slate-500 dark:text-slate-500 sm:ml-auto">{t('backupCount', { count: backups.length })}</span>
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      <div className={responsiveTableContainerClass}>
        {loading ? <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div> :
         backups.length === 0 ? <div className="py-16 text-center text-sm text-slate-500 dark:text-slate-500">{t('empty')}</div> :
        <table className={responsiveTableClass}>
          <thead className={responsiveTableHeadClass}>
            <tr>
              <th className="text-left px-4 py-2.5">{t('columns.file')}</th>
              <th className="text-left px-4 py-2.5">{t('columns.type')}</th>
              <th className="text-left px-4 py-2.5">{t('columns.size')}</th>
              <th className="text-left px-4 py-2.5">{t('columns.created')}</th>
              <th className="text-right px-4 py-2.5">{t('columns.actions')}</th>
            </tr>
          </thead>
          <tbody className={responsiveTableBodyClass}>
            {backups.map(y => (
              <tr key={y.id} className={responsiveTableRowClass}>
                <td data-label={t('columns.file')} className={responsiveTableCodeCellClass}>
                  {y.file}
                  {y.verification === 'corrupt' && (
                    <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded font-semibold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">{t('verify.corrupt')}</span>
                  )}
                  {y.verification === 'remote' && (
                    <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded font-medium bg-slate-100 text-slate-600 dark:bg-slate-700/40 dark:text-slate-300">{t('verify.remote')}</span>
                  )}
                </td>
                <td data-label={t('columns.type')} className={responsiveTableCellClass}>
                  <span className={`text-xs px-1.5 py-0.5 rounded uppercase tracking-wider font-semibold ${
                    y.type === 'scheduled' ? 'bg-sky-100 text-sky-700' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 dark:text-slate-500'
                  }`}>{y.type === 'scheduled' ? t('typeScheduled') : y.type}</span>
                </td>
                <td data-label={t('columns.size')} className={responsiveTableCodeCellClass}>{formatSize(y.size_b)}</td>
                <td data-label={t('columns.created')} className={responsiveTableCellClass}>{y.created_at}</td>
                <td className={responsiveTableActionCellClass}>
                  <button onClick={() => download(y)} className="text-sm text-brand-600 dark:text-brand-400 hover:bg-brand-50 dark:hover:bg-brand-900/30 dark:bg-brand-900/20 px-2 py-1 rounded">{t('row.download')}</button>
                  <button onClick={() => setRestoreBackup(y)} className="text-sm text-amber-700 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-900/30 dark:bg-amber-900/20 px-2 py-1 rounded">{t('row.restore')}</button>
                  <button onClick={() => setBackupToDelete(y)} className="text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 px-2 py-1 rounded">{t('row.delete')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>}
      </div>

      <ConfirmDialog
        open={!!backupToDelete}
        title={t('confirmDelete.title')}
        message={t('confirmDelete.message', { file: backupToDelete?.file })}
        dangerous confirmText={t('confirmDelete.confirm')}
        onConfirm={remove}
        onCancel={() => setBackupToDelete(null)}
      />

      {restoreBackup && (
        <RestoreDialog
          open={!!restoreBackup}
          domainId={id!}
          backupId={restoreBackup.id}
          file={restoreBackup.file}
          systemUser={domain?.system_user ?? ''}
          busy={processing}
          onCancel={() => setRestoreBackup(null)}
          onSubmit={restore}
        />
      )}
    </div>
  )
}

function formatSize(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}