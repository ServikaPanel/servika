import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'
import Modal from '@/components/Modal'
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

type Task = {
  idx: number
  minute: string
  hour: string
  day: string
  month: string
  weekday: string
  command: string
  comment?: string
  enabled: boolean
  type?: string          // "command" | "url" | "php"
  php_version?: string
}

type TaskResponse = {
  idx: number
  minute: string
  hour: string
  day: string
  month: string
  week: string
  command: string
  comment?: string
  enabled: boolean
  type?: string
  php_version?: string
}

type Domain = { id: number; domain_name: string; system_user: string }

type ListResponse = { system_user: string; total: number; tasks: TaskResponse[]; php_versions: string[] }

const PRESETS: Array<{ labelKey: string; selection: { minute: string; hour: string; day: string; month: string; weekday: string } }> = [
  { labelKey: 'everyMinute', selection: { minute: '*', hour: '*', day: '*', month: '*', weekday: '*' } },
  { labelKey: 'everyHour', selection: { minute: '0', hour: '*', day: '*', month: '*', weekday: '*' } },
  { labelKey: 'dailyAt3', selection: { minute: '0', hour: '3', day: '*', month: '*', weekday: '*' } },
  { labelKey: 'mondayAt9', selection: { minute: '0', hour: '9', day: '*', month: '*', weekday: '1' } },
  { labelKey: 'every5Minutes', selection: { minute: '*/5', hour: '*', day: '*', month: '*', weekday: '*' } },
  { labelKey: 'every15Minutes', selection: { minute: '*/15', hour: '*', day: '*', month: '*', weekday: '*' } },
  { labelKey: 'firstOfMonth', selection: { minute: '0', hour: '0', day: '1', month: '*', weekday: '*' } },
]

export default function DomainCronPage() {
  const { t } = useTranslation('DomainCronPage')
  const { confirm, notify } = useDialog()
  const report = useReportError()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [tasks, setTasks] = useState<Task[]>([])
  const [phpVersions, setPhpVersions] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // null = closed, 'new' = add, Task = edit.
  const [modalTask, setModalTask] = useState<Task | 'new' | null>(null)
  const [running, setRunning] = useState<number | null>(null)

  // Split so the mount effect never writes state synchronously: fetchTasks
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchTasks = useCallback(() => {
    if (!id) return
    api.get<ListResponse>(`/domains/${id}/cron`)
      .then(r => {
        setPhpVersions(r.data.php_versions || [])
        setTasks(r.data.tasks.map(task => ({
          idx: task.idx,
          minute: task.minute,
          hour: task.hour,
          day: task.day,
          month: task.month,
          weekday: task.week,
          command: task.command,
          comment: task.comment,
          enabled: task.enabled,
          type: task.type,
          php_version: task.php_version,
        })))
      })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchTasks()
  }, [fetchTasks])

  useEffect(() => {
    if (id) api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
    fetchTasks()
  }, [id, fetchTasks, report])

  async function run(task: Task) {
    setRunning(task.idx)
    try {
      const { data } = await api.post(`/domains/${id}/cron/${task.idx}/run`)
      const output = (data.output || '').trim() || t('run.noOutput')
      const errorLine = data.error ? `\n\n${t('run.errorLabel')}: ${data.error}` : ''
      const heading = data.ok ? t('run.success') : t('run.failed')
      await notify({ message: `${heading}\n\n$ ${data.command}\n\n${output}${errorLine}`, tone: data.ok ? 'info' : 'error' })
    } catch (e) {
      await notify({ message: apiError(e, t('errors.runFailed')), tone: 'error' })
    } finally {
      setRunning(null)
    }
  }

  async function remove(task: Task) {
    if (!(await confirm({ message: t('confirmDelete', { command: task.command.slice(0, 60) }), dangerous: true }))) return
    try {
      await api.delete(`/domains/${id}/cron/${task.idx}`)
      load()
    } catch (e) {
      await notify({ message: apiError(e, t('errors.deleteFailed')), tone: 'error' })
    }
  }

  return (
    <div className="w-full px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.scheduledTasks') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && (
        <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">
          <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
          {', '}
          <span className="font-mono text-slate-600 dark:text-slate-400 dark:text-slate-500">/var/spool/cron/{domain.system_user}</span>
        </p>
      )}

      <div className="grid grid-cols-2 gap-2 mb-4 sm:flex sm:items-center">
        <button
          onClick={() => setModalTask('new')}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-md shadow-sm transition"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          {t('actions.add')}
        </button>
        <button onClick={load} className="px-3 py-2 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-sm rounded-md transition">{t('actions.refresh')}</button>
        <span className="col-span-2 text-sm text-slate-500 dark:text-slate-500 sm:col-span-1 sm:ml-auto">{t('count', { count: tasks.length })}</span>
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      <div className={responsiveTableContainerClass}>
        {loading ? (
          <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
        ) : tasks.length === 0 ? (
          <div className="py-16 text-center">
            <div className="w-14 h-14 mx-auto rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-3">
              <svg className="w-7 h-7 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-500">{t('empty')}</p>
          </div>
        ) : (
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="text-left px-4 py-2.5">{t('columns.schedule')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.command')}</th>
                <th className="text-right px-4 py-2.5">{t('columns.action')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {tasks.map((task) => (
                <tr key={task.idx} className={`${responsiveTableRowClass} ${!task.enabled ? 'opacity-60' : ''}`}>
                  <td data-label={t('columns.schedule')} className={responsiveTableCodeCellClass}>
                    <span className="whitespace-nowrap">{task.minute} {task.hour} {task.day} {task.month} {task.weekday}</span>
                  </td>
                  <td data-label={t('columns.command')} className={responsiveTableCellClass}>
                    <div className="min-w-0 flex-1 text-right lg:text-left">
                      <div className="flex flex-wrap items-center justify-end lg:justify-start gap-2">
                        {!task.enabled && <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">{t('badges.disabled')}</span>}
                        {task.type && task.type !== 'command' && <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300">{task.type === 'php' ? `PHP ${task.php_version || ''}` : task.type}</span>}
                        <span className="font-mono text-slate-800 dark:text-slate-200 break-all lg:truncate lg:max-w-md" title={task.command}>{task.command}</span>
                      </div>
                      {task.comment && <div className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{task.comment}</div>}
                    </div>
                  </td>
                  <td className={`${responsiveTableActionCellClass} space-x-1`}>
                    <button onClick={() => run(task)} disabled={running === task.idx} title={t('row.runTitle')} className="text-sm text-emerald-600 dark:text-emerald-400 hover:text-emerald-700 dark:hover:text-emerald-300 px-2 py-1 rounded hover:bg-emerald-50 dark:hover:bg-emerald-900/30 transition disabled:opacity-50">{running === task.idx ? t('row.running') : t('row.run')}</button>
                    <button onClick={() => setModalTask(task)} className="text-sm text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 px-2 py-1 rounded hover:bg-brand-50 dark:hover:bg-brand-900/30 transition">{t('row.edit')}</button>
                    <button onClick={() => remove(task)} className="text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:text-red-300 px-2 py-1 rounded hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 transition">{t('row.delete')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalTask !== null && (
        <CronTaskModal
          task={modalTask}
          phpVersions={phpVersions}
          domainId={Number(id)}
          onClose={() => setModalTask(null)}
          onSaved={() => { setModalTask(null); load() }}
        />
      )}
    </div>
  )
}

// parseCommand best-effort extracts the raw url/script/args from a generated
// command so an existing typed task can be edited in the same fields it was
// created with.
function parseCommand(task: Task): { url: string; script: string; args: string } {
  if (task.type === 'url') {
    const m = task.command.match(/'([^']+)'/)
    return { url: m ? m[1] : '', script: '', args: '' }
  }
  if (task.type === 'php') {
    const m = task.command.match(/-q '([^']+)'(.*)$/)
    return { url: '', script: m ? m[1] : '', args: m ? m[2].trim() : '' }
  }
  return { url: '', script: '', args: '' }
}

function CronTaskModal({ task, phpVersions, domainId, onClose, onSaved }: {
  task: Task | 'new'; phpVersions: string[]; domainId: number; onClose: () => void; onSaved: () => void
}) {
  const { t } = useTranslation('DomainCronPage')
  const isNew = task === 'new'
  const existing = isNew ? null : (task as Task)
  const parsed = existing ? parseCommand(existing) : { url: '', script: '', args: '' }
  const versions = phpVersions.length ? phpVersions : ['8.3']

  const [enabled, setEnabled] = useState(existing ? existing.enabled : true)
  const [type, setType] = useState(existing?.type || 'command')
  const [minute, setMinute] = useState(existing?.minute || '0')
  const [hour, setHour] = useState(existing?.hour || '3')
  const [day, setDay] = useState(existing?.day || '*')
  const [month, setMonth] = useState(existing?.month || '*')
  const [weekday, setWeekday] = useState(existing?.weekday || '*')
  const [command, setCommand] = useState(existing && (existing.type || 'command') === 'command' ? existing.command : '')
  const [url, setUrl] = useState(parsed.url)
  const [script, setScript] = useState(parsed.script)
  const [args, setArgs] = useState(parsed.args)
  const [phpVersion, setPhpVersion] = useState(existing?.php_version || versions[0])
  const [comment, setComment] = useState(existing?.comment || '')
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function applyPreset(preset: typeof PRESETS[number]['selection']) {
    setMinute(preset.minute); setHour(preset.hour); setDay(preset.day); setMonth(preset.month); setWeekday(preset.weekday)
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setProcessing(true); setError(null)
    try {
      const body: Record<string, unknown> = {
        minute, hour, day, month, week: weekday, enabled, type, comment: comment.trim(),
      }
      if (type === 'command') body.command = command.trim()
      else if (type === 'url') body.url = url.trim()
      else if (type === 'php') { body.script = script.trim(); body.args = args.trim(); body.php_version = phpVersion }

      if (isNew) await api.post(`/domains/${domainId}/cron`, body)
      else await api.put(`/domains/${domainId}/cron/${(task as Task).idx}`, body)
      onSaved()
    } catch (e) {
      setError(apiError(e, t('errors.saveFailed')))
    } finally {
      setProcessing(false)
    }
  }

  const inputCls = 'w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-md text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'

  return (
    <Modal open={true} title={isNew ? t('modal.title') : t('modal.editTitle')} onClose={onClose} width="lg">
      <form onSubmit={submit} className="space-y-4">
        <label className="flex items-center gap-2.5 cursor-pointer select-none">
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="h-4 w-4 accent-brand-600" />
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('modal.enabledLabel')} <span className="font-normal text-slate-400 dark:text-slate-500">{t('modal.enabledHint')}</span></span>
        </label>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.typeLabel')}</label>
          <div className="flex flex-wrap gap-4">
            {[['command', t('modal.typeCommand')], ['url', t('modal.typeUrl')], ['php', t('modal.typePhp')]].map(([v, l]) => (
              <label key={v} className="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                <input type="radio" name="cronType" checked={type === v} onChange={() => setType(v)} className="accent-brand-600" />
                {l}
              </label>
            ))}
          </div>
        </div>

        {type === 'command' && (
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.commandLabel')}</label>
            <input value={command} onChange={e => setCommand(e.target.value)} required placeholder={t('modal.commandPlaceholder')} className={inputCls} />
          </div>
        )}
        {type === 'url' && (
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.urlLabel')}</label>
            <input value={url} onChange={e => setUrl(e.target.value)} required placeholder={t('modal.urlPlaceholder')} className={inputCls} />
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('modal.urlHint')}</p>
          </div>
        )}
        {type === 'php' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-3">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.scriptLabel')}</label>
                <input value={script} onChange={e => setScript(e.target.value)} required placeholder={t('modal.scriptPlaceholder')} className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.phpVersionLabel')}</label>
                <select value={phpVersion} onChange={e => setPhpVersion(e.target.value)} className="px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-md text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
                  {versions.map(s => <option key={s} value={s}>PHP {s}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.argsLabel')} <span className="font-normal text-slate-400 dark:text-slate-500">{t('modal.argsOptional')}</span></label>
              <input value={args} onChange={e => setArgs(e.target.value)} placeholder={t('modal.argsPlaceholder')} className={inputCls} />
            </div>
          </div>
        )}

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.scheduleLabel')}</label>
          <div className="flex flex-wrap gap-1.5 mb-2">
            {PRESETS.map(p => (
              <button key={p.labelKey} type="button" onClick={() => applyPreset(p.selection)}
                className="px-2.5 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-700/60 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-600 hover:bg-brand-100 dark:hover:bg-brand-900/40 hover:text-brand-700 dark:hover:text-brand-300 hover:border-brand-300 dark:hover:border-brand-700 rounded-md transition">
                {t(`presets.${p.labelKey}`)}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-5 gap-2">
            <Field label={t('modal.fields.minute')} value={minute} onChange={setMinute} />
            <Field label={t('modal.fields.hour')} value={hour} onChange={setHour} />
            <Field label={t('modal.fields.day')} value={day} onChange={setDay} />
            <Field label={t('modal.fields.month')} value={month} onChange={setMonth} />
            <Field label={t('modal.fields.weekday')} value={weekday} onChange={setWeekday} />
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">{t('modal.cronHint')} <code className="font-mono">*</code>{t('modal.cronHintPost')} <code className="font-mono">*/5</code>{t('modal.cronEvery')} <code className="font-mono">0,15,30</code>{t('modal.cronList')} <code className="font-mono">9-17</code>{t('modal.cronRange')}</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.descriptionLabel')}</label>
          <input value={comment} onChange={e => setComment(e.target.value)} placeholder={t('modal.descriptionPlaceholder')}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none text-sm" />
        </div>

        {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} disabled={processing} className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 rounded-md text-sm">{t('modal.cancel')}</button>
          <button type="submit" disabled={processing} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
            {processing ? t('modal.saving') : t('modal.save')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full px-2 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
      />
    </div>
  )
}
