import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import { useResourceScope } from '@/lib/scope'

type Status = { installed: boolean; version: string; composer_json: boolean; username: string; dir: string }

const BTN_BASE = 'px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50'
const BTN_FILLED = `${BTN_BASE} bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900`
const BTN_OUTLINE = `${BTN_BASE} border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800`

// PackageRow requires or removes one named package.
function PackageRow({ runningCommand, packageName, onPackageName, onRun }: {
  runningCommand: string | null
  packageName: string
  onPackageName: (value: string) => void
  onRun: (command: string, pkt?: string) => void
}) {
  const { t } = useTranslation('DomainComposerPage')
  const blocked = !!runningCommand || !packageName.trim()
  return (
    <div className="mt-3 flex gap-2">
      <input value={packageName} onChange={e => onPackageName(e.target.value)} placeholder={t('packagePlaceholder')}
        className="flex-1 px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
      <button disabled={blocked} onClick={() => onRun('require', packageName.trim())} className={`${BTN_BASE} bg-emerald-600 hover:bg-emerald-700 text-white`}>require</button>
      <button disabled={blocked} onClick={() => onRun('remove', packageName.trim())} className={`${BTN_BASE} border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20`}>remove</button>
    </div>
  )
}

// CommandBar runs the five composer commands this panel offers.
function CommandBar({ status, runningCommand, packageName, onPackageName, onRun }: {
  status: Status
  runningCommand: string | null
  packageName: string
  onPackageName: (value: string) => void
  onRun: (command: string, pkt?: string) => void
}) {
  const { t } = useTranslation('DomainComposerPage')
  const busy = !!runningCommand
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4 shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <div>
          <span className="text-xs font-mono text-slate-500">{status.version}</span>
          <span className={`ml-2 text-xs ${status.composer_json ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
            {status.composer_json ? t('composerJsonFound') : t('composerJsonNotFound')}
          </span>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <button disabled={busy} onClick={() => onRun('install')} className={BTN_FILLED}>{runningCommand === 'install' ? '…' : 'install'}</button>
        <button disabled={busy} onClick={() => onRun('update')} className={BTN_FILLED}>{runningCommand === 'update' ? '…' : 'update'}</button>
        <button disabled={busy} onClick={() => onRun('dump-autoload')} className={BTN_OUTLINE}>dump-autoload</button>
        <button disabled={busy} onClick={() => onRun('validate')} className={BTN_OUTLINE}>validate</button>
        <button disabled={busy} onClick={() => onRun('show')} className={BTN_OUTLINE}>show</button>
      </div>
      <PackageRow runningCommand={runningCommand} packageName={packageName} onPackageName={onPackageName} onRun={onRun} />
    </div>
  )
}

export default function DomainComposerPage() {
  const { t } = useTranslation('DomainComposerPage')
  const { id, base, backHref, backLabel } = useResourceScope()
  const [d, setD] = useState<Status | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [output, setOutput] = useState<string>('')
  const [runningCommand, setRunningCommand] = useState<string | null>(null)
  const [packageName, setPackageName] = useState('')

  // Split so the mount effect never writes state synchronously: fetchStatus
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh that follows a composer command.
  const fetchStatus = useCallback(() => {
    if (!id) return
    api.get<Status>(`${base}/composer`).then(r => setD(r.data)).catch(e => setError(apiError(e))).finally(() => setLoading(false))
  }, [id, base])

  const load = useCallback(() => {
    setLoading(true)
    fetchStatus()
  }, [fetchStatus])

  useEffect(() => { fetchStatus() }, [fetchStatus])

  async function run(command: string, pkt?: string) {
    const cmd = `${command}${pkt ? ' ' + pkt : ''}`
    const header = t('run.header', { cmd })
    setRunningCommand(command); setError(null); setOutput(`${header}\n\n${t('run.running')}`)
    try {
      const { data } = await api.post(`${base}/composer`, { command, package: pkt || '' })
      setOutput(`${header}\n\n${data.output || t('run.noOutput')}\n\n${data.ok ? t('run.completed') : t('run.failed')}`)
      load()
    } catch (e) {
      setError(apiError(e, t('errors.runFailed'))); setOutput('')
    } finally { setRunningCommand(null) }
  }

  if (loading) return <div className="px-6 py-5 text-slate-400">{t('loading')}</div>
  if (!d) return <div className="px-6 py-5"><div className="text-sm text-red-600">{error || t('notFound')}</div></div>

  return (
    <div className="px-6 py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: t('breadcrumb.composer') },
        ]} />
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('subtitle.pre')}<span className="font-mono">{d.dir}</span>{t('subtitle.mid')}<span className="font-mono">{d.username}</span>{t('subtitle.post')}
        </p>

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

        {!d.installed ? (
          <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-2xl p-5 text-sm text-amber-800 dark:text-amber-200">
            {t('notInstalled')}
          </div>
        ) : (
          <>
            <CommandBar
              status={d} runningCommand={runningCommand} packageName={packageName}
              onPackageName={setPackageName} onRun={run}
            />

            {output && (
              <div className="bg-slate-900 rounded-2xl p-4 shadow-sm">
                <pre className="text-xs font-mono text-slate-100 whitespace-pre-wrap break-all max-h-96 overflow-y-auto">{output}</pre>
              </div>
            )}
          </>
        )}

        <div className="mt-4"><Link to={backHref} className="text-sm text-brand-600 dark:text-brand-400">{backLabel}</Link></div>
      </div>
    </div>
  )
}
