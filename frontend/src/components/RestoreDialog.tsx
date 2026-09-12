import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Modal from './Modal'
import { api, apiError } from '@/lib/api'

export type RestoreMode = 'full' | 'files' | 'database' | 'file' | 'db'

type ContentFile = { path: string; size: number; is_dir: boolean }
type ContentDB = { name: string; size: number }
type Contents = { files: ContentFile[]; databases: ContentDB[]; truncated: boolean }

export type RestorePayload = {
  mode: RestoreMode
  clean?: boolean
  paths?: string[]
  target?: string
  db?: string
  target_db?: string
  // Set only when the operator confirmed a restore from an archive the integrity
  // scan recorded as corrupt. The server refuses one without it.
  allow_corrupt?: boolean
}

// canSubmitOf reports whether the chosen mode has everything it needs. A
// selected-files restore with nothing ticked, and a single-database restore
// with no source, are the two the server would refuse.
function canSubmitOf(busy: boolean, mode: RestoreMode, selected: string[], sourceDB: string): boolean {
  if (busy) return false
  if (mode === 'file') return selected.length > 0
  if (mode === 'db') return sourceDB !== ''
  return true
}

// CleanOption offers to empty the target before writing. Only the two whole
// restores can do it; a partial restore has nothing safe to empty.
function CleanOption({ mode, clean, onClean }: {
  mode: RestoreMode
  clean: boolean
  onClean: (value: boolean) => void
}) {
  const { t } = useTranslation('DomainBackupsPage')
  if (mode !== 'full' && mode !== 'files') return null
  return (
    <div className="mb-4 p-3 rounded-lg bg-slate-50 dark:bg-slate-900">
      <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
        <input type="checkbox" checked={clean} onChange={e => onClean(e.target.checked)} />
        {t('restore.cleanLabel')}
      </label>
      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('restore.cleanHint')}</p>
    </div>
  )
}

function ContentsStatus({ loading, loadError }: { loading: boolean; loadError: string | null }) {
  const { t } = useTranslation('DomainBackupsPage')
  if (loadError) return <p className="text-sm text-red-600">{loadError}</p>
  if (loading) return <p className="text-sm text-slate-500 dark:text-slate-400">{t('restore.loadingContents')}</p>
  return null
}

// FileSelector picks the paths of a selected-files restore and where they land.
function FileSelector({ mode, contents, filter, onFilter, selected, onToggle, visibleFiles, target, onTarget }: {
  mode: RestoreMode
  contents: Contents | null
  filter: string
  onFilter: (value: string) => void
  selected: string[]
  onToggle: (path: string) => void
  visibleFiles: ContentFile[]
  target: string
  onTarget: (value: string) => void
}) {
  const { t } = useTranslation('DomainBackupsPage')
  if (mode !== 'file' || !contents) return null
  return (
    <div className="mb-4">
      <div className="flex items-center justify-between gap-2 mb-2">
        <input value={filter} onChange={e => onFilter(e.target.value)}
          placeholder={t('restore.searchPlaceholder')}
          className="flex-1 px-3 py-1.5 text-sm border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-800" />
        <span className="text-xs text-slate-500 dark:text-slate-400">{t('restore.selectedCount', { n: selected.length })}</span>
      </div>
      {contents.files.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">{t('restore.noFiles')}</p>
      ) : (
        <div className="max-h-56 overflow-auto border border-slate-200 dark:border-slate-700 rounded-md divide-y divide-slate-100 dark:divide-slate-700">
          {visibleFiles.map(f => (
            <label key={f.path} className="flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-900">
              <input type="checkbox" checked={selected.includes(f.path)} onChange={() => onToggle(f.path)} />
              <span className="truncate text-slate-700 dark:text-slate-300">{f.is_dir ? `${f.path}/` : f.path}</span>
            </label>
          ))}
        </div>
      )}
      {contents.truncated && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('restore.truncated')}</p>}

      <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mt-3 mb-1">{t('restore.targetLabel')}</p>
      <div className="space-y-1.5">
        <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
          <input type="radio" name="restore-target" checked={target === 'folder'} onChange={() => onTarget('folder')} />
          {t('restore.target.folder')}
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
          <input type="radio" name="restore-target" checked={target === 'in_place'} onChange={() => onTarget('in_place')} />
          {t('restore.target.inPlace')}
        </label>
      </div>
    </div>
  )
}

// DatabasePicker chooses which database in the archive is restored, and under
// which name it lands.
function DatabasePicker({ mode, contents, systemUser, sourceDB, onSourceDB, targetDB, onTargetDB }: {
  mode: RestoreMode
  contents: Contents | null
  systemUser: string
  sourceDB: string
  onSourceDB: (value: string) => void
  targetDB: string
  onTargetDB: (value: string) => void
}) {
  const { t } = useTranslation('DomainBackupsPage')
  if (mode !== 'db' || !contents) return null
  if (contents.databases.length === 0) {
    return (
      <div className="mb-4">
        <p className="text-sm text-slate-500 dark:text-slate-400">{t('restore.noDatabases')}</p>
      </div>
    )
  }
  return (
    <div className="mb-4">
      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('restore.sourceDbLabel')}</label>
      <select value={sourceDB} onChange={e => onSourceDB(e.target.value)}
        className="w-full px-3 py-1.5 text-sm border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-800 mb-3">
        {contents.databases.map(d => <option key={d.name} value={d.name}>{d.name}</option>)}
      </select>
      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('restore.targetDbLabel')}</label>
      <input value={targetDB} onChange={e => onTargetDB(e.target.value)}
        placeholder={`${systemUser}_`}
        className="w-full px-3 py-1.5 text-sm border border-slate-200 dark:border-slate-700 rounded-md bg-white dark:bg-slate-800" />
      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('restore.targetDbHint', { prefix: `${systemUser}_` })}</p>
    </div>
  )
}

// RestoreDialog collects the granular restore options for one backup archive.
// Modes needing archive contents (selected files, single database) fetch the
// read-only listing lazily, so opening the dialog stays cheap.
export default function RestoreDialog({
  open, domainId, backupId, file, systemUser, busy, onCancel, onSubmit,
}: {
  open: boolean
  domainId: string
  backupId: number
  file: string
  systemUser: string
  busy: boolean
  onCancel: () => void
  onSubmit: (payload: RestorePayload) => void
}) {
  const { t } = useTranslation('DomainBackupsPage')
  const [mode, setMode] = useState<RestoreMode>('full')
  const [clean, setClean] = useState(false)
  const [target, setTarget] = useState('folder')
  const [selected, setSelected] = useState<string[]>([])
  const [filter, setFilter] = useState('')
  const [sourceDB, setSourceDB] = useState('')
  const [targetDB, setTargetDB] = useState('')
  const [contents, setContents] = useState<Contents | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  // A ref, not state, so the fetch below can mark itself in flight without a
  // render and without the guard becoming a dependency of its own effect.
  const requested = useRef(false)

  const needsContents = mode === 'file' || mode === 'db'

  // Clearing the form is a reaction to the dialog closing, so it is adjusted
  // during render; an effect would leave the stale selection on screen for one
  // frame of the closing animation.
  const [wasOpen, setWasOpen] = useState(open)
  if (wasOpen !== open) {
    setWasOpen(open)
    if (!open) {
      setMode('full'); setClean(false); setTarget('folder')
      setSelected([]); setFilter(''); setSourceDB(''); setTargetDB('')
      setContents(null); setLoadError(null)
    }
  }

  // Derived: the dialog is loading exactly while it needs a listing, has none,
  // and nothing has failed. Storing that separately meant writing it
  // synchronously from the effect that started the request.
  const loading = open && needsContents && !contents && !loadError

  useEffect(() => {
    if (!open) { requested.current = false; return }
    if (!needsContents || contents || requested.current) return
    requested.current = true
    api.get<Contents>(`/domains/${domainId}/backups/${backupId}/contents`)
      .then(r => {
        setContents(r.data)
        if (r.data.databases.length > 0) setSourceDB(r.data.databases[0].name)
      })
      .catch(e => setLoadError(apiError(e, t('restore.contentsFailed'))))
  }, [open, needsContents, contents, domainId, backupId, t])

  const visibleFiles = useMemo(() => {
    const all = contents?.files ?? []
    const q = filter.trim().toLowerCase()
    const matched = q ? all.filter(f => f.path.toLowerCase().includes(q)) : all
    return matched.slice(0, 500)
  }, [contents, filter])

  function toggle(path: string) {
    setSelected(prev => prev.includes(path) ? prev.filter(p => p !== path) : [...prev, path])
  }

  function submit() {
    if (mode === 'file') { onSubmit({ mode, paths: selected, target }); return }
    if (mode === 'db') { onSubmit({ mode, db: sourceDB, target_db: targetDB.trim() }); return }
    if (mode === 'database') { onSubmit({ mode }); return }
    onSubmit({ mode, clean })
  }

  const canSubmit = canSubmitOf(busy, mode, selected, sourceDB)

  const modes: { value: RestoreMode; label: string }[] = [
    { value: 'full', label: t('restore.mode.full') },
    { value: 'files', label: t('restore.mode.files') },
    { value: 'database', label: t('restore.mode.database') },
    { value: 'file', label: t('restore.mode.file') },
    { value: 'db', label: t('restore.mode.db') },
  ]

  return (
    <Modal open={open} title={t('restore.title')} onClose={onCancel} width="lg">
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-4 break-all">{t('restore.file', { file })}</p>

      <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{t('restore.modeLabel')}</p>
      <div className="space-y-1.5 mb-4">
        {modes.map(m => (
          <label key={m.value} className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
            <input type="radio" name="restore-mode" value={m.value}
              checked={mode === m.value} onChange={() => setMode(m.value)} />
            {m.label}
          </label>
        ))}
      </div>

      <CleanOption mode={mode} clean={clean} onClean={setClean} />

      <ContentsStatus loading={loading} loadError={loadError} />

      <FileSelector mode={mode} contents={contents} filter={filter} onFilter={setFilter}
        selected={selected} onToggle={toggle} visibleFiles={visibleFiles}
        target={target} onTarget={setTarget} />

      <DatabasePicker mode={mode} contents={contents} systemUser={systemUser}
        sourceDB={sourceDB} onSourceDB={setSourceDB} targetDB={targetDB} onTargetDB={setTargetDB} />

      <div className="flex justify-end gap-2 pt-2">
        <button onClick={onCancel} disabled={busy}
          className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 rounded-md text-sm">
          {t('restore.cancel')}
        </button>
        <button onClick={submit} disabled={!canSubmit}
          className="px-4 py-2 text-white rounded-md text-sm font-medium bg-red-600 hover:bg-red-700 disabled:bg-red-300">
          {busy ? t('restore.processing') : t('restore.submit')}
        </button>
      </div>
    </Modal>
  )
}
