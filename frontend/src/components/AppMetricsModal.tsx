import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Modal from '@/components/Modal'
import {
  type AppMetrics, formatBytes, formatPercent, formatTasks, formatUptime,
} from '@/lib/appMetrics'

// REFRESH is the poll interval. A CPU percentage is the difference between two
// readings, so the first tick after opening reports 0% whatever the application
// is doing; a shorter interval would not change that and would only add load.
const REFRESH = 5000

// Figure is one measured number with its label.
function Figure({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 p-2.5 dark:border-slate-700">
      <div className="text-[10px] uppercase tracking-wide text-slate-400 dark:text-slate-500">{label}</div>
      <div className="mt-0.5 font-mono text-sm text-slate-800 dark:text-slate-200">{value}</div>
    </div>
  )
}

// Figures draws the snapshot.
function Figures({ metrics }: { metrics: AppMetrics }) {
  const { t } = useTranslation('AppMetrics')
  const words = { d: t('unit.d'), h: t('unit.h'), m: t('unit.m'), s: t('unit.s') }
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      <Figure label={t('memory')} value={formatBytes(metrics.memory_bytes)} />
      <Figure label={t('memoryPeak')} value={formatBytes(metrics.memory_peak_bytes)} />
      <Figure label={t('cpu')} value={formatPercent(metrics.cpu_percent)} />
      <Figure label={t('tasks')} value={formatTasks(metrics.tasks, metrics.tasks_max, t('unlimited'))} />
      <Figure label={t('disk')} value={formatBytes(metrics.disk_bytes)} />
      <Figure label={t('uptime')} value={formatUptime(metrics.uptime_seconds, words) || '-'} />
      <Figure label={t('state')} value={`${metrics.active_state || '-'} / ${metrics.sub_state || '-'}`} />
      <Figure label={t('restarts')} value={String(metrics.restarts)} />
    </div>
  )
}

// AppMetricsModal polls one application's consumption while it is open.
export default function AppMetricsModal({ url, name, onClose }: {
  url: string
  name: string
  onClose: () => void
}) {
  const { t } = useTranslation('AppMetrics')
  const [metrics, setMetrics] = useState<AppMetrics | null>(null)
  const [error, setError] = useState<string | null>(null)

  const fetchMetrics = useCallback(() => {
    api.get<AppMetrics>(url)
      .then(r => { setMetrics(r.data); setError(null) })
      .catch(e => setError(apiError(e)))
  }, [url])

  useEffect(() => {
    fetchMetrics()
    const timer = setInterval(fetchMetrics, REFRESH)
    return () => clearInterval(timer)
  }, [fetchMetrics])

  return (
    <Modal open title={t('title', { name })} onClose={onClose} width="lg">
      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {!metrics && !error && <p className="text-sm text-slate-400 dark:text-slate-500">{t('loading')}</p>}
      {metrics && <Figures metrics={metrics} />}
      {metrics && (
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">{t('cpuNote')}</p>
      )}
    </Modal>
  )
}
