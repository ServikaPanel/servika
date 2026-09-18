// Read-only server status for resellers.
//
// The existing Monitoring page calls admin endpoints (/system/processes,
// /domains, /admin/system/logs), most of which return 403 for a reseller. This
// page uses only the endpoints opened to resellers: /system/usage,
// /system/services and /system/version-check.
//
// An admin can open it too (sees the same data as a summary); the real depth
// still lives on the Monitoring page.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import Breadcrumb from '@/components/Breadcrumb'

type Usage = {
  system?: { panel_version?: string }
  cpu?: { percent?: number; cores?: number; load_1m?: number; load_5m?: number; load_15m?: number }
  memory?: { total_kb?: number; used_kb?: number; percent?: number }
  disk?: { total_byte?: number; used_byte?: number; percent?: number }
  uptime_sec?: number
}
type Service = { unit: string; label: string; group: string; status: string }
type VersionCheck = { current?: string; latest?: string; update_available?: boolean }

const STATUS_STYLE: Record<string, string> = {
  active: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300',
  inactive: 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
  failed: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
  absent: 'bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500',
}
function Card({ title, value, sub }: { title: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">{title}</div>
      <div className="mt-1 text-xl font-semibold text-slate-900 dark:text-slate-100">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-400">{sub}</div>}
    </div>
  )
}

const pct = (v?: number) => (v != null ? `${Math.round(v)}%` : '—')
const gb = (bytes?: number) => (bytes != null ? (bytes / 1024 ** 3).toFixed(1) : '0')

function CpuCard({ cpu }: { cpu: Usage['cpu'] }) {
  const { t } = useTranslation('ServerStatusPage')
  const values = [cpu?.load_1m, cpu?.load_5m, cpu?.load_15m].map((y) => (y ?? 0).toFixed(2)).join(' · ')
  const loadText = cpu ? t('loadText', { values }) : undefined
  return <Card title={t('cards.cpu')} value={pct(cpu?.percent)} sub={loadText} />
}

function MemoryCard({ memory }: { memory: Usage['memory'] }) {
  const { t } = useTranslation('ServerStatusPage')
  const total = memory?.total_kb
  const sub = total ? `${Math.round((memory?.used_kb ?? 0) / 1024)} / ${Math.round(total / 1024)} MB` : undefined
  return <Card title={t('cards.memory')} value={pct(memory?.percent)} sub={sub} />
}

function DiskCard({ disk }: { disk: Usage['disk'] }) {
  const { t } = useTranslation('ServerStatusPage')
  const sub = disk?.total_byte ? `${gb(disk.used_byte)} / ${gb(disk.total_byte)} GB` : undefined
  return <Card title={t('cards.disk')} value={pct(disk?.percent)} sub={sub} />
}

function PanelVersionCard({ panelVersion, version }: { panelVersion?: string; version: VersionCheck | null }) {
  const { t } = useTranslation('ServerStatusPage')
  const sub = version?.update_available ? t('updateAvailable', { version: version.latest }) : t('upToDate')
  return <Card title={t('cards.panelVersion')} value={panelVersion ? `v${panelVersion}` : '—'} sub={sub} />
}

function SummaryCards({ usage, version }: { usage: Usage | null; version: VersionCheck | null }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      <CpuCard cpu={usage?.cpu} />
      <MemoryCard memory={usage?.memory} />
      <DiskCard disk={usage?.disk} />
      <PanelVersionCard panelVersion={usage?.system?.panel_version} version={version} />
    </div>
  )
}

function ServicesGrid({ services }: { services: Service[] }) {
  const { t } = useTranslation('ServerStatusPage')
  return (
    <>
      <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">{t('servicesHeading')}</h2>
      {services.length === 0 ? (
        <div className="py-8 text-center text-sm text-slate-400">{t('noServices')}</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {services.map((s) => (
            <div key={s.unit} className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-3 py-2">
              <div className="min-w-0">
                <div className="truncate text-sm text-slate-900 dark:text-slate-100">{s.label}</div>
                <div className="truncate text-[11px] text-slate-400">{s.group}</div>
              </div>
              <span className={`shrink-0 px-2 py-0.5 rounded text-xs ${STATUS_STYLE[s.status] ?? STATUS_STYLE.absent}`}>
                {t(`statuses.${s.status}`, { defaultValue: s.status })}
              </span>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

export default function ServerStatusPage() {
  const { t } = useTranslation('ServerStatusPage')
  const report = useReportError()
  const [usage, setUsage] = useState<Usage | null>(null)
  const [services, setServices] = useState<Service[]>([])
  const [version, setVersion] = useState<VersionCheck | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.get<Usage>('/system/usage').then((r) => { if (!cancelled) setUsage(r.data) }),
      api.get<Service[]>('/system/services').then((r) => { if (!cancelled) setServices(Array.isArray(r.data) ? r.data : []) }),
      api.get<VersionCheck>('/system/version-check').then((r) => { if (!cancelled) setVersion(r.data) }).catch(report('versionInfo')),
    ])
      .catch((e) => { if (!cancelled) setError(apiError(e, t('errorLoad'))) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [t, report])

  return (
    <div className="w-full px-4 py-6">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('breadcrumbServerStatus') }]} />

      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('subtitle')}
        </p>
      </div>

      {error && <div className="mb-4 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm">{error}</div>}

      {loading ? (
        <div className="py-16 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : (
        <>
          <SummaryCards usage={usage} version={version} />

          <ServicesGrid services={services} />
        </>
      )}
    </div>
  )
}
