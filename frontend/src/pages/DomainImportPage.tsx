import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'

type ArchiveSummary = {
  stage_id: string
  file_name: string
  bytes: number
  summary: {
    members: number
    total_bytes: number
    roots: string[]
    container_root: string
  }
  app: string
  app_dir: string
  can_skip_root: boolean
  warnings: string[]
}

type ConfigChange = {
  path: string
  kind: string
  fields: string[]
  applied: boolean
  note?: string
}

type DBAccount = { db_name: string; db_user: string }

function humanBytes(bytes: number): string {
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

const cardClass =
  'bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm'
const inputClass =
  'w-full px-3 py-2 text-sm border border-slate-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100'
const primaryButtonClass =
  'px-4 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-lg disabled:opacity-50'

function Banners({ error, ok }: { error: string | null; ok: string | null }) {
  return (
    <>
      {error && (
        <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}
      {ok && (
        <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">
          {ok}
        </div>
      )}
    </>
  )
}

type ArchiveStepProps = {
  archiveFile: File | null
  onArchiveFile: (file: File | null) => void
  onUpload: () => void
  uploading: boolean
  staged: ArchiveSummary | null
  target: string
  onTarget: (value: string) => void
  skipRoot: boolean
  onSkipRoot: (value: boolean) => void
  cleanDest: boolean
  onCleanDest: (value: boolean) => void
  onApply: () => void
  extracting: boolean
}

function ArchiveStep(p: ArchiveStepProps) {
  const { t } = useTranslation('DomainImportPage')
  return (
    <section className={`${cardClass} mb-5`}>
      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('archive.title')}</h2>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('archive.description')}</p>

      <div className="flex flex-wrap items-center gap-3 mb-3">
        <input
          type="file"
          accept=".zip,.tar,.gz,.tgz,.bz2,.tbz2,.xz,.txz,.rar"
          onChange={e => p.onArchiveFile(e.target.files?.[0] ?? null)}
          className="text-sm text-slate-600 dark:text-slate-300"
        />
        <button onClick={p.onUpload} disabled={!p.archiveFile || p.uploading} className={primaryButtonClass}>
          {p.uploading ? t('archive.uploading') : t('archive.analyze')}
        </button>
      </div>

      {p.staged && (
        <div className="border-t border-slate-100 dark:border-slate-700 pt-4">
          <ArchiveSummaryList staged={p.staged} />

          {p.staged.warnings.map(warning => (
            <div
              key={warning}
              className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg text-xs text-amber-800 dark:text-amber-300"
            >
              {t(`warnings.${warning}`)}
            </div>
          ))}

          <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
            {t('archive.target')}
          </label>
          <input value={p.target} onChange={e => p.onTarget(e.target.value)} className={`${inputClass} mb-3`} />

          {p.staged.summary.container_root && (
            <label className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300 mb-2">
              <input
                type="checkbox"
                checked={p.skipRoot}
                disabled={!p.staged.can_skip_root}
                onChange={e => p.onSkipRoot(e.target.checked)}
                className="mt-0.5"
              />
              <span>{t('archive.skipRoot', { root: p.staged.summary.container_root })}</span>
            </label>
          )}
          <label className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300 mb-4">
            <input type="checkbox" checked={p.cleanDest} onChange={e => p.onCleanDest(e.target.checked)} className="mt-0.5" />
            <span className="text-red-600 dark:text-red-400">{t('archive.cleanDest')}</span>
          </label>

          <button onClick={p.onApply} disabled={p.extracting} className={primaryButtonClass}>
            {p.extracting ? t('archive.extracting') : t('archive.extract')}
          </button>
        </div>
      )}
    </section>
  )
}

function ArchiveSummaryList({ staged }: { staged: ArchiveSummary }) {
  const { t } = useTranslation('DomainImportPage')
  return (
    <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-4">
      <div>
        <dt className="text-slate-400">{t('archive.file')}</dt>
        <dd className="font-mono text-slate-700 dark:text-slate-200 break-all">{staged.file_name}</dd>
      </div>
      <div>
        <dt className="text-slate-400">{t('archive.size')}</dt>
        <dd className="text-slate-700 dark:text-slate-200">{humanBytes(staged.bytes)}</dd>
      </div>
      <div>
        <dt className="text-slate-400">{t('archive.members')}</dt>
        <dd className="text-slate-700 dark:text-slate-200">{staged.summary.members}</dd>
      </div>
      <div>
        <dt className="text-slate-400">{t('archive.app')}</dt>
        <dd className="text-slate-700 dark:text-slate-200">
          {staged.app ? t(`apps.${staged.app}`) : t('apps.unknown')}
        </dd>
      </div>
    </dl>
  )
}

type DatabaseStepProps = {
  databases: DBAccount[]
  dbName: string
  onDBName: (value: string) => void
  dumpFile: File | null
  onDumpFile: (file: File | null) => void
  truncate: boolean
  onTruncate: (value: boolean) => void
  onImport: () => void
  importing: boolean
}

function DatabaseStep(p: DatabaseStepProps) {
  const { t } = useTranslation('DomainImportPage')
  return (
    <section className={`${cardClass} mb-5`}>
      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('database.title')}</h2>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('database.description')}</p>

      <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
        {t('database.target')}
      </label>
      {p.databases.length > 0 ? (
        <select value={p.dbName} onChange={e => p.onDBName(e.target.value)} className={`${inputClass} mb-3`}>
          {p.databases.map(entry => (
            <option key={entry.db_name} value={entry.db_name}>
              {entry.db_name}
            </option>
          ))}
        </select>
      ) : (
        <input value={p.dbName} onChange={e => p.onDBName(e.target.value)} className={`${inputClass} mb-3`} />
      )}

      <div className="flex flex-wrap items-center gap-3 mb-3">
        <input
          type="file"
          accept=".sql,.gz"
          onChange={e => p.onDumpFile(e.target.files?.[0] ?? null)}
          className="text-sm text-slate-600 dark:text-slate-300"
        />
      </div>
      <label className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300 mb-4">
        <input type="checkbox" checked={p.truncate} onChange={e => p.onTruncate(e.target.checked)} className="mt-0.5" />
        <span className="text-red-600 dark:text-red-400">{t('database.truncate')}</span>
      </label>

      <button onClick={p.onImport} disabled={!p.dumpFile || !p.dbName || p.importing} className={primaryButtonClass}>
        {p.importing ? t('database.importing') : t('database.import')}
      </button>
    </section>
  )
}

type ConfigStepProps = {
  configDir: string
  onConfigDir: (value: string) => void
  dbName: string
  onRewrite: () => void
  rewriting: boolean
  changes: ConfigChange[] | null
}

function ConfigStep(p: ConfigStepProps) {
  const { t } = useTranslation('DomainImportPage')
  return (
    <section className={cardClass}>
      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('config.title')}</h2>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('config.description')}</p>

      <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1">
        {t('config.directory')}
      </label>
      <input value={p.configDir} onChange={e => p.onConfigDir(e.target.value)} className={`${inputClass} mb-4`} />

      <button onClick={p.onRewrite} disabled={!p.dbName || p.rewriting} className={primaryButtonClass}>
        {p.rewriting ? t('config.rewriting') : t('config.rewrite')}
      </button>

      {p.changes && p.changes.length > 0 && (
        <ul className="mt-4 divide-y divide-slate-50 dark:divide-slate-700/50">
          {p.changes.map(change => (
            <ChangeRow key={change.path} change={change} />
          ))}
        </ul>
      )}
    </section>
  )
}

function ChangeRow({ change }: { change: ConfigChange }) {
  const { t } = useTranslation('DomainImportPage')
  return (
    <li className="py-2.5">
      <div className="font-mono text-xs text-slate-700 dark:text-slate-200 break-all">{change.path}</div>
      <div className="text-xs text-slate-400">
        {change.applied
          ? t('config.applied', { fields: change.fields.join(', ') })
          : t(`config.notes.${change.note || 'write_failed'}`)}
      </div>
    </li>
  )
}

export default function DomainImportPage() {
  const { t } = useTranslation('DomainImportPage')
  const { id } = useParams()

  const [error, setError] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)

  // Step 1: the archive.
  const [archiveFile, setArchiveFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [staged, setStaged] = useState<ArchiveSummary | null>(null)
  const [target, setTarget] = useState('public_html')
  const [skipRoot, setSkipRoot] = useState(true)
  const [cleanDest, setCleanDest] = useState(false)
  const [extracting, setExtracting] = useState(false)

  // Step 2: the database.
  const [databases, setDatabases] = useState<DBAccount[]>([])
  const [dbName, setDBName] = useState('')
  const [dumpFile, setDumpFile] = useState<File | null>(null)
  const [truncate, setTruncate] = useState(false)
  const [importing, setImporting] = useState(false)

  // Step 3: the configuration.
  const [configDir, setConfigDir] = useState('public_html')
  const [rewriting, setRewriting] = useState(false)
  const [changes, setChanges] = useState<ConfigChange[] | null>(null)

  useEffect(() => {
    if (!id) return
    api
      .get<DBAccount[]>(`/domains/${id}/databases`)
      .then(r => {
        const list = r.data || []
        setDatabases(list)
        if (list.length > 0) setDBName(list[0].db_name)
      })
      .catch(() => {
        /* the picker falls back to a free-text field when the list is unavailable */
      })
  }, [id])

  function reset() {
    setError(null)
    setOk(null)
  }

  async function uploadArchive() {
    if (!archiveFile) return
    reset()
    setUploading(true)
    setStaged(null)
    try {
      const body = new FormData()
      body.append('archive', archiveFile)
      const { data } = await api.post<ArchiveSummary>(`/domains/${id}/import/archive`, body)
      setStaged(data)
      setSkipRoot(data.can_skip_root)
      if (data.app_dir) setConfigDir(`public_html`)
    } catch (e) {
      setError(apiError(e, t('errors.uploadFailed')))
    } finally {
      setUploading(false)
    }
  }

  async function applyArchive() {
    if (!staged) return
    reset()
    setExtracting(true)
    try {
      const { data } = await api.post(`/domains/${id}/import/archive/apply`, {
        stage_id: staged.stage_id,
        target,
        skip_root: skipRoot,
        clean_dest: cleanDest,
      })
      setOk(t('archive.done', { target: data.target }))
      setStaged(null)
      setArchiveFile(null)
      setConfigDir(data.target)
    } catch (e) {
      setError(apiError(e, t('errors.extractFailed')))
    } finally {
      setExtracting(false)
    }
  }

  async function importDump() {
    if (!dumpFile || !dbName) return
    reset()
    setImporting(true)
    try {
      const body = new FormData()
      body.append('dump', dumpFile)
      body.append('db_name', dbName)
      body.append('truncate', truncate ? '1' : '0')
      const { data } = await api.post(`/domains/${id}/import/sql`, body)
      setOk(t('database.done', { db: data.db_name, size: humanBytes(data.bytes) }))
      setDumpFile(null)
    } catch (e) {
      setError(apiError(e, t('errors.importFailed')))
    } finally {
      setImporting(false)
    }
  }

  async function rewriteConfig() {
    if (!dbName) return
    reset()
    setRewriting(true)
    setChanges(null)
    try {
      const { data } = await api.post<{ changes: ConfigChange[] }>(`/domains/${id}/import/config`, {
        db_name: dbName,
        directory: configDir,
      })
      setChanges(data.changes || [])
      if ((data.changes || []).length === 0) setOk(t('config.none'))
    } catch (e) {
      setError(apiError(e, t('errors.configFailed')))
    } finally {
      setRewriting(false)
    }
  }

  return (
    <div className="px-6 py-5">
      <Breadcrumb
        items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: t('breadcrumb.import') },
        ]}
      />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">{t('subtitle')}</p>

      <Banners error={error} ok={ok} />

      <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800/40 rounded-2xl p-4 mb-5 text-xs text-amber-800 dark:text-amber-300">
        {t('note')}
      </div>

      {/* Step 1 */}
      <ArchiveStep
        archiveFile={archiveFile}
        onArchiveFile={setArchiveFile}
        onUpload={uploadArchive}
        uploading={uploading}
        staged={staged}
        target={target}
        onTarget={setTarget}
        skipRoot={skipRoot}
        onSkipRoot={setSkipRoot}
        cleanDest={cleanDest}
        onCleanDest={setCleanDest}
        onApply={applyArchive}
        extracting={extracting}
      />

      {/* Step 2 */}
      <DatabaseStep
        databases={databases}
        dbName={dbName}
        onDBName={setDBName}
        dumpFile={dumpFile}
        onDumpFile={setDumpFile}
        truncate={truncate}
        onTruncate={setTruncate}
        onImport={importDump}
        importing={importing}
      />

      {/* Step 3 */}
      <ConfigStep
        configDir={configDir}
        onConfigDir={setConfigDir}
        dbName={dbName}
        onRewrite={rewriteConfig}
        rewriting={rewriting}
        changes={changes}
      />

      <div className="mt-4">
        <Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">
          {t('back')}
        </Link>
      </div>
    </div>
  )
}
