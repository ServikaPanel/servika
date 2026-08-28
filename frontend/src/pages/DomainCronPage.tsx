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
}

type Domain = { id: number; domain_name: string; system_user: string }

type ListResponse = { system_user: string; total: number; tasks: TaskResponse[] }

const PRESETS: Array<{ labelKey: string; selection: Omit<Task, 'idx' | 'command' | 'comment'> }> = [
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
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [modal, setModal] = useState(false)
  const [running, setRunning] = useState<number | null>(null)

  // Split so the mount effect never writes state synchronously: fetchTasks
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchTasks = useCallback(() => {
    if (!id) return
    api.get<ListResponse>(`/domains/${id}/cron`)
      .then(r => setTasks(r.data.tasks.map(task => ({
        idx: task.idx,
        minute: task.minute,
        hour: task.hour,
        day: task.day,
        month: task.month,
        weekday: task.week,
        command: task.command,
        comment: task.comment,
      }))))
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
          onClick={() => setModal(true)}
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
                <th className="text-left px-4 py-2.5">{t('columns.min')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.hour')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.day')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.month')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.weekday')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.command')}</th>
                <th className="text-right px-4 py-2.5">{t('columns.action')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {tasks.map((task) => (
                <tr key={task.idx} className={responsiveTableRowClass}>
                  <td data-label={t('columns.min')} className={responsiveTableCodeCellClass}>{task.minute}</td>
                  <td data-label={t('columns.hour')} className={responsiveTableCodeCellClass}>{task.hour}</td>
                  <td data-label={t('columns.day')} className={responsiveTableCodeCellClass}>{task.day}</td>
                  <td data-label={t('columns.month')} className={responsiveTableCodeCellClass}>{task.month}</td>
                  <td data-label={t('columns.weekday')} className={responsiveTableCodeCellClass}>{task.weekday}</td>
                  <td data-label={t('columns.command')} className={responsiveTableCellClass}>
                    <div className="min-w-0 flex-1 text-right lg:text-left">
                      <div className="font-mono text-slate-800 dark:text-slate-200 break-all lg:truncate lg:max-w-md" title={task.command}>{task.command}</div>
                      {task.comment && <div className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{task.comment}</div>}
                    </div>
                  </td>
                  <td className={`${responsiveTableActionCellClass} space-x-1`}>
                    <button onClick={() => run(task)} disabled={running === task.idx} title={t('row.runTitle')} className="text-sm text-emerald-600 dark:text-emerald-400 hover:text-emerald-700 dark:hover:text-emerald-300 px-2 py-1 rounded hover:bg-emerald-50 dark:hover:bg-emerald-900/30 transition disabled:opacity-50">{running === task.idx ? t('row.running') : t('row.run')}</button>
                    <button onClick={() => remove(task)} className="text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:text-red-300 px-2 py-1 rounded hover:bg-red-50 dark:hover:bg-red-900/30 dark:bg-red-900/20 transition">{t('row.delete')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <CronTaskModal open={modal} onClose={() => setModal(false)} onSaved={load} domainId={Number(id)} />
    </div>
  )
}

function CronTaskModal({ open, onClose, onSaved, domainId }: {
  open: boolean; onClose: () => void; onSaved: () => void; domainId: number
}) {
  const { t } = useTranslation('DomainCronPage')
  const [minute, setMinute] = useState('0')
  const [hour, setHour] = useState('3')
  const [day, setDay] = useState('*')
  const [month, setMonth] = useState('*')
  const [weekday, setWeekday] = useState('*')
  const [command, setCommand] = useState('')
  const [comment, setComment] = useState('')
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function applyPreset(preset: typeof PRESETS[number]['selection']) {
    setMinute(preset.minute)
    setHour(preset.hour)
    setDay(preset.day)
    setMonth(preset.month)
    setWeekday(preset.weekday)
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setProcessing(true); setError(null)
    try {
      await api.post(`/domains/${domainId}/cron`, { minute, hour, day, month, week: weekday, command: command.trim(), comment: comment.trim() })
      onSaved()
      setCommand(''); setComment('')
      onClose()
    } catch (e) {
      setError(apiError(e, t('errors.addFailed')))
    } finally {
      setProcessing(false)
    }
  }

  return (
    <Modal open={open} title={t('modal.title')} onClose={onClose} width="lg">
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.presetsLabel')}</label>
          <div className="flex flex-wrap gap-1.5">
            {PRESETS.map(p => (
              <button
                key={p.labelKey}
                type="button"
                onClick={() => applyPreset(p.selection)}
                className="px-2.5 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-700/60 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-600 hover:bg-brand-100 dark:hover:bg-brand-900/40 hover:text-brand-700 dark:hover:text-brand-300 hover:border-brand-300 dark:hover:border-brand-700 rounded-md transition"
              >
                {t(`presets.${p.labelKey}`)}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-5 gap-2">
          <Field label={t('modal.fields.minute')}   value={minute} onChange={setMinute} />
          <Field label={t('modal.fields.hour')}     value={hour}   onChange={setHour} />
          <Field label={t('modal.fields.day')}      value={day}    onChange={setDay} />
          <Field label={t('modal.fields.month')}       value={month}     onChange={setMonth} />
          <Field label={t('modal.fields.weekday')}    value={weekday}  onChange={setWeekday} />
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-500">{t('modal.cronHint')} <code className="font-mono">*</code>{t('modal.cronHintPost')} <code className="font-mono">*/5</code>{t('modal.cronEvery')} <code className="font-mono">0,15,30</code>{t('modal.cronList')} <code className="font-mono">9-17</code>{t('modal.cronRange')}</p>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.commandLabel')}</label>
          <input
            type="text"
            value={command}
            onChange={e => setCommand(e.target.value)}
            placeholder={t('modal.commandPlaceholder')}
            required
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none text-sm font-mono"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('modal.descriptionLabel')}</label>
          <input
            type="text"
            value={comment}
            onChange={e => setComment(e.target.value)}
            placeholder={t('modal.descriptionPlaceholder')}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none text-sm"
          />
        </div>

        {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} disabled={processing} className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 rounded-md text-sm">{t('modal.cancel')}</button>
          <button type="submit" disabled={processing || !command.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
            {processing ? t('modal.adding') : t('modal.addTask')}
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