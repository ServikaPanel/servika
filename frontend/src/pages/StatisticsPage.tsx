import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'

// The actual nested /system/usage response shape matches MonitoringPage.
type Usage = {
  system?: { hostname?: string; ip?: string; os_name?: string; kernel?: string; arch?: string; cpu_model?: string; cpu_cores?: number; panel_version?: string }
  cpu?: { percent?: number; cores?: number; load_1m?: number; load_5m?: number; load_15m?: number }
  memory?: { total_kb?: number; used_kb?: number; free_kb?: number; percent?: number }
  swap?: { total_kb?: number; used_kb?: number; percent?: number }
  disk?: { total_byte?: number; used_byte?: number; free_byte?: number; percent?: number; mount?: string }
}

type Counts = { domains: number; activeDomains: number }

function formatBytes(bytes: number) {
  if (!bytes || bytes < 0) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 ** 2) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 ** 3) return (bytes / 1024 / 1024).toFixed(1) + ' MB'
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

const DASH = '–'

// Convert undefined, null, and NaN values to zero.
function numberOrZero(value: number | undefined | null): number {
  return typeof value === 'number' && isFinite(value) ? value : 0
}

/** The core count the metric cards divide by; never zero. */
function coreCount(usage: Usage | null): number {
  return numberOrZero(usage?.cpu?.cores) || numberOrZero(usage?.system?.cpu_cores) || 1
}

function CpuCard({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation('StatisticsPage')
  const cpu = numberOrZero(usage?.cpu?.percent)
  return <Metric title={t('metric.cpu')} value={usage ? cpu.toFixed(1) + '%' : DASH}
    subtitle={usage ? t('coresValue', { cores: coreCount(usage) }) : ''} color="indigo" ratio={cpu} />
}

function MemoryCard({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation('StatisticsPage')
  const memory = numberOrZero(usage?.memory?.percent)
  const subtitle = usage ? `${formatBytes(numberOrZero(usage.memory?.used_kb) * 1024)} / ${formatBytes(numberOrZero(usage.memory?.total_kb) * 1024)}` : ''
  return <Metric title={t('metric.memory')} value={usage ? memory.toFixed(1) + '%' : DASH} subtitle={subtitle} color="emerald" ratio={memory} />
}

function DiskCard({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation('StatisticsPage')
  const disk = numberOrZero(usage?.disk?.percent)
  const subtitle = usage ? `${formatBytes(numberOrZero(usage.disk?.used_byte))} / ${formatBytes(numberOrZero(usage.disk?.total_byte))}` : ''
  return <Metric title={t('metric.disk')} value={usage ? disk.toFixed(1) + '%' : DASH} subtitle={subtitle} color="violet" ratio={disk} />
}

function LoadCard({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation('StatisticsPage')
  const oneMinuteLoad = numberOrZero(usage?.cpu?.load_1m)
  const subtitle = usage
    ? t('loadSub', { five: numberOrZero(usage.cpu?.load_5m).toFixed(2), fifteen: numberOrZero(usage.cpu?.load_15m).toFixed(2) })
    : ''
  return <Metric title={t('metric.load')} value={usage ? oneMinuteLoad.toFixed(2) : DASH} subtitle={subtitle}
    color="amber" ratio={Math.min(100, (oneMinuteLoad / coreCount(usage)) * 100)} />
}

function MetricCards({ usage }: { usage: Usage | null }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
      <CpuCard usage={usage} />
      <MemoryCard usage={usage} />
      <DiskCard usage={usage} />
      <LoadCard usage={usage} />
    </div>
  )
}

function processorValue(usage: Usage | null, t: TFunction): string {
  const model = usage?.system?.cpu_model
  if (!model) return DASH
  return t('processorValue', { model, cores: coreCount(usage) })
}

function swapValue(usage: Usage | null, t: TFunction): string {
  const swap = usage?.swap
  if (!swap) return DASH
  return t('swapValue', {
    percent: numberOrZero(swap.percent).toFixed(1),
    used: formatBytes(numberOrZero(swap.used_kb) * 1024),
    total: formatBytes(numberOrZero(swap.total_kb) * 1024),
  })
}

/** One string field of the system block, or the dash when it is not reported. */
function systemField(usage: Usage | null, key: 'hostname' | 'os_name' | 'kernel' | 'panel_version'): string {
  return usage?.system?.[key] || DASH
}

function SystemCard({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation('StatisticsPage')
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-4">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('system.title')}</h3>
      <div className="space-y-1.5 text-sm">
        <Row label={t('system.hostname')} value={systemField(usage, 'hostname')} />
        <Row label={t('system.os')} value={systemField(usage, 'os_name')} />
        <Row label={t('system.kernel')} value={systemField(usage, 'kernel')} />
        <Row label={t('system.processor')} value={processorValue(usage, t)} />
        <Row label={t('system.swap')} value={swapValue(usage, t)} />
        <Row label={t('system.panelVersion')} value={systemField(usage, 'panel_version')} />
      </div>
    </div>
  )
}

function DomainCountCard({ counts }: { counts: Counts | null }) {
  const { t } = useTranslation('StatisticsPage')
  const total = counts?.domains ?? 0
  const active = counts?.activeDomains ?? 0
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-4">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('domains.title')}</h3>
      <div className="space-y-1.5 text-sm">
        <Row label={t('domains.total')} value={counts ? String(total) : DASH} />
        <Row label={t('domains.active')} value={
          <span className="text-emerald-700 dark:text-emerald-300 font-semibold">{active}</span>
        } />
        <Row label={t('domains.inactive')} value={String(total - active)} />
      </div>
    </div>
  )
}

function SummaryCards({ usage, counts }: { usage: Usage | null; counts: Counts | null }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-5">
      <SystemCard usage={usage} />
      <DomainCountCard counts={counts} />
    </div>
  )
}

export default function StatisticsPage() {
  const { t } = useTranslation('StatisticsPage')
  const [usage, setUsage] = useState<Usage | null>(null)
  const [counts, setCounts] = useState<Counts | null>(null)
  const [error, setError] = useState<string | null>(null)

  function load() {
    api.get<Usage>('/system/usage').then(response => setUsage(response.data)).catch(caughtError => setError(apiError(caughtError)))
    api.get<{ status?: string }[]>('/domains').then(response => {
      const domains = response.data || []
      setCounts({
        domains: domains.length,
        activeDomains: domains.filter(domain => domain.status === 'active').length,
      })
    }).catch(() => {
      // The counts are a secondary tile; the usage error above already reports.
    })
  }
  useEffect(() => { load(); const timer = setInterval(load, 10000); return () => clearInterval(timer) }, [])


  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.statistics') },
      ]} />
      <div className="flex items-center justify-between mb-1">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <span className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">{t('live')}</span>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">{t('subtitle')}</p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      <MetricCards usage={usage} />

      <SummaryCards usage={usage} counts={counts} />

      <div className="text-xs text-slate-400 dark:text-slate-500 text-center mt-6">
        {t('footer.pre')}<a href="/monitoring" className="text-brand-600 dark:text-brand-400 hover:underline">{t('footer.link')}</a>{t('footer.post')}
      </div>
    </div>
  )
}

function Metric({ title, value, subtitle, color, ratio }: { title: string; value: string; subtitle: string; color: string; ratio: number }) {
  const colorMap: Record<string, string> = {
    indigo: 'bg-indigo-500', emerald: 'bg-emerald-500',
    violet: 'bg-violet-500', amber: 'bg-amber-500',
  }
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-4">
      <div className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider">{title}</div>
      <div className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{value}</div>
      <div className="text-[11px] text-slate-500 dark:text-slate-500 mt-0.5 truncate">{subtitle}</div>
      <div className="mt-2 h-1.5 bg-slate-100 dark:bg-slate-700 rounded overflow-hidden">
        <div className={`h-full ${colorMap[color]} transition-all`} style={{ width: Math.min(100, Math.max(0, ratio)) + '%' }} />
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1 border-b border-slate-50 dark:border-slate-700/40 last:border-0">
      <span className="text-xs text-slate-500 dark:text-slate-500 shrink-0">{label}</span>
      <span className="text-xs font-mono text-slate-800 dark:text-slate-200 text-right truncate">{value}</span>
    </div>
  )
}
