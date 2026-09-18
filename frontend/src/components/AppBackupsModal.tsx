import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Modal from '@/components/Modal'

// One archive as either backend reports it.
//
// `restorable` is optional because only the server-application table has rows
// that predate verified backups. A row with no digest cannot be restored, and
// the screen has to say so rather than offer a button that refuses.
export type AppBackup = {
  id: number
  archive_path: string
  size_bytes: number
  sha256: string
  note?: string
  created_at: string
  restorable?: boolean
}

const BUTTON_CLASS = 'rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs text-slate-700 transition hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'

// formatSize reads an archive size the way an operator sizes a disk.
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}

function canRestore(backup: AppBackup): boolean {
  return backup.restorable !== false
}

// BackupRow is one archive and what can be done with it.
function BackupRow({ backup, busy, onRestore, onDelete }: {
  backup: AppBackup
  busy: boolean
  onRestore: (backup: AppBackup) => void
  onDelete: (backup: AppBackup) => void
}) {
  const { t } = useTranslation('AppBackups')
  return (
    <li className="flex items-center gap-3 rounded-lg border border-slate-200 p-2.5 dark:border-slate-700">
      <div className="min-w-0 flex-1">
        <div className="truncate text-xs font-medium text-slate-800 dark:text-slate-200">
          {new Date(backup.created_at).toLocaleString()}
          <span className="ml-2 font-normal text-slate-500 dark:text-slate-400">{formatSize(backup.size_bytes)}</span>
        </div>
        {backup.note && (
          <div className="truncate text-xs text-slate-500 dark:text-slate-400">{backup.note}</div>
        )}
        {!canRestore(backup) && (
          <div className="text-xs text-amber-600 dark:text-amber-400">{t('unverified')}</div>
        )}
      </div>
      <button onClick={() => onRestore(backup)} disabled={busy || !canRestore(backup)} className={BUTTON_CLASS}>
        {t('restore')}
      </button>
      <button onClick={() => onDelete(backup)} disabled={busy}
        className="rounded-lg px-2.5 py-1.5 text-xs text-red-600 transition hover:bg-red-50 disabled:opacity-50 dark:text-red-400 dark:hover:bg-red-900/30">
        {t('delete')}
      </button>
    </li>
  )
}

// AppBackupsModal lists an application's archives and takes, restores or drops
// one. `base` is the endpoint prefix, which is the only thing that differs
// between a tenant application and a server application.
export default function AppBackupsModal({ open, base, name, onClose }: {
  open: boolean
  base: string
  name: string
  onClose: () => void
}) {
  const { t } = useTranslation('AppBackups')
  const { confirm, notify } = useDialog()
  const [backups, setBackups] = useState<AppBackup[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState('')

  // Split so the mount effect never writes state synchronously: fetchBackups
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchBackups = useCallback(() => {
    api.get<{ backups: AppBackup[] }>(`${base}/backups`)
      .then(r => setBackups(r.data.backups || []))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [base])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchBackups()
  }, [fetchBackups])

  useEffect(() => { fetchBackups() }, [fetchBackups])

  async function take() {
    setBusy(true)
    try {
      await api.post(`${base}/backups`, { note })
      setNote('')
      // The work finishes past the end of the request, so the list is reloaded
      // rather than updated: what it shows now is what exists now, and the
      // finished archive arrives as a notification.
      await notify({ message: t('started'), tone: 'info' })
      load()
    } catch (e) {
      await notify({ message: apiError(e), tone: 'error' })
    } finally {
      setBusy(false)
    }
  }

  async function restore(backup: AppBackup) {
    const ok = await confirm({
      title: t('confirmRestore.title'),
      message: t('confirmRestore.message', { name }),
      confirmLabel: t('restore'),
      dangerous: true,
    })
    if (!ok) return
    setBusy(true)
    try {
      await api.post(`${base}/backups/${backup.id}/restore`)
      await notify({ message: t('restoreStarted'), tone: 'info' })
    } catch (e) {
      await notify({ message: apiError(e), tone: 'error' })
    } finally {
      setBusy(false)
    }
  }

  async function drop(backup: AppBackup) {
    const ok = await confirm({
      title: t('confirmDelete.title'),
      message: t('confirmDelete.message'),
      confirmLabel: t('delete'),
      dangerous: true,
    })
    if (!ok) return
    setBusy(true)
    try {
      await api.delete(`${base}/backups/${backup.id}`)
      load()
    } catch (e) {
      await notify({ message: apiError(e), tone: 'error' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} title={t('title', { name })} onClose={onClose} width="lg">
      <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('explain')}</p>

      <div className="mb-4 flex gap-2">
        <input
          value={note}
          onChange={e => setNote(e.target.value)}
          maxLength={255}
          placeholder={t('notePlaceholder')}
          className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
        />
        <button onClick={take} disabled={busy}
          className="rounded-lg bg-brand-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-brand-700 disabled:opacity-50">
          {t('take')}
        </button>
      </div>

      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {loading && <p className="text-sm text-slate-400 dark:text-slate-500">{t('loading')}</p>}
      {!loading && backups.length === 0 && (
        <p className="text-sm text-slate-500 dark:text-slate-400">{t('empty')}</p>
      )}
      <ul className="space-y-2">
        {backups.map(backup => (
          <BackupRow key={backup.id} backup={backup} busy={busy} onRestore={restore} onDelete={drop} />
        ))}
      </ul>
    </Modal>
  )
}
