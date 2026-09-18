import { isAxiosError } from 'axios'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'

// Stored history of the server's own resources. The live chart on the same page
// holds sixty in-memory samples and loses them on a reload, so it cannot answer
// what the server was doing during last night's incident. These series come from
// the system_load table the sampler writes once a minute.

type Point = {
  ts: string
  load_1m: number; load_5m: number; load_15m: number
  memory: number; cpu: number; swap: number; disk: number
  net_rx_bps: number; net_tx_bps: number
}
type History = { hour: number; cores: number; points: Point[] }

const INTERVALS = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
]

const W = 1000, H = 200, P = 24

// One plotted series: which field it reads and the colour it draws in.
type Series = { key: keyof Point; color: string; label: string }

export default function SystemHistoryCharts() {
  const { t } = useTranslation('SystemHistoryCharts')
  const [hours, setHours] = useState(24)
  const [history, setHistory] = useState<History | null>(null)
  const [forbidden, setForbidden] = useState(false)

  useEffect(() => {
    let live = true
    async function tick() {
      if (typeof document !== 'undefined' && document.hidden) return
      try {
        const r = await api.get<History>(`/system/load-history?hour=${hours}`)
        if (live) { setHistory(r.data); setForbidden(false) }
      } catch (e) {
        if (live && isAxiosError(e) && e.response?.status === 403) setForbidden(true)
      }
    }
    tick()
    const timer = setInterval(tick, 60000)
    return () => { live = false; clearInterval(timer) }
  }, [hours])

  const points = useMemo(() => history?.points || [], [history])

  if (forbidden) return null

  return (
    <div className="space-y-5">
      <HistoryCard
        title={t('resources.title')}
        hours={hours}
        onHours={setHours}
        points={points}
        series={[
          { key: 'cpu', color: '#6366f1', label: t('resources.cpu') },
          { key: 'memory', color: '#10b981', label: t('resources.memory') },
          { key: 'swap', color: '#8b5cf6', label: t('resources.swap') },
          { key: 'disk', color: '#f59e0b', label: t('resources.disk') },
        ]}
        yMax={100}
        format={(v) => `${v.toFixed(1)}%`}
      />
      <HistoryCard
        title={t('network.title')}
        hours={hours}
        onHours={setHours}
        points={points}
        series={[
          { key: 'net_rx_bps', color: '#0ea5e9', label: t('network.rx') },
          { key: 'net_tx_bps', color: '#ec4899', label: t('network.tx') },
        ]}
        yMax={networkCeiling(points)}
        format={formatRate}
      />
    </div>
  )
}

// networkCeiling keeps the axis above the busiest sample, with a floor so an
// idle server does not draw its noise as a full-height mountain.
function networkCeiling(points: Point[]): number {
  const peak = points.reduce((high, p) => Math.max(high, p.net_rx_bps, p.net_tx_bps), 0)
  return Math.max(64 * 1024, peak * 1.2)
}

// formatRate writes a per-second byte rate in the largest unit that keeps the
// number readable.
function formatRate(value: number): string {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB/s`
  if (value >= 1024) return `${(value / 1024).toFixed(0)} KB/s`
  return `${Math.round(value)} B/s`
}

type CardProps = {
  title: string
  hours: number
  onHours: (hours: number) => void
  points: Point[]
  series: Series[]
  yMax: number
  format: (value: number) => string
}

function HistoryCard({ title, hours, onHours, points, series, yMax, format }: CardProps) {
  const { t } = useTranslation('SystemHistoryCharts')
  const latest = points[points.length - 1]
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
        <div className="flex items-center gap-0.5 rounded-xl border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-700 dark:bg-slate-900/60">
          {INTERVALS.map(a => (
            <button key={a.hours} onClick={() => onHours(a.hours)}
              className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${hours === a.hours
                ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
              {a.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-4 text-xs">
        {series.map(s => (
          <span key={String(s.key)} className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
            <span className="h-3 w-3 rounded" style={{ background: s.color }} />
            {s.label}
            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
              {latest ? format(Number(latest[s.key])) : '—'}
            </span>
          </span>
        ))}
      </div>

      {points.length < 2
        ? <p className="py-12 text-center text-xs italic text-slate-400 dark:text-slate-500">{t('noData')}</p>
        : <HistorySvg points={points} series={series} yMax={yMax} format={format} />}
    </div>
  )
}

function HistorySvg({ points, series, yMax, format }: { points: Point[]; series: Series[]; yMax: number; format: (v: number) => string }) {
  const innerW = W - P * 2, innerH = H - P * 2
  const xAt = (i: number) => P + (innerW * i) / (points.length - 1)
  const yAt = (v: number) => P + innerH - (Math.max(0, Math.min(v, yMax)) / yMax) * innerH
  const path = (key: keyof Point) => points
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(Number(p[key])).toFixed(1)}`)
    .join(' ')
  const ticks = [0, 0.25, 0.5, 0.75, 1]
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" preserveAspectRatio="none">
      {ticks.map(f => (
        <line key={f} x1={P} y1={yAt(yMax * f)} x2={W - P} y2={yAt(yMax * f)}
          className="stroke-slate-100 dark:stroke-slate-700" strokeWidth="1" />
      ))}
      {series.map(s => (
        <path key={String(s.key)} d={path(s.key)} stroke={s.color} strokeWidth="2" fill="none" vectorEffect="non-scaling-stroke" />
      ))}
      <text x={P + 2} y={P + 10} fontSize="9" className="fill-slate-400 dark:fill-slate-500">{format(yMax)}</text>
      <text x={P + 2} y={H - P + 1} fontSize="9" className="fill-slate-400 dark:fill-slate-500">{format(0)}</text>
      <text x={P} y={H - 4} fontSize="9" className="fill-slate-400 dark:fill-slate-500">{axisLabel(points[0].ts)}</text>
      <text x={W - P} y={H - 4} fontSize="9" textAnchor="end" className="fill-slate-400 dark:fill-slate-500">
        {axisLabel(points[points.length - 1].ts)}
      </text>
    </svg>
  )
}

// axisLabel keeps the stored timestamp as written: the server records local
// time, and reparsing it in the browser would shift every label by the
// operator's own offset.
function axisLabel(ts: string): string {
  return ts.slice(5, 16).replace('-', '/').replace('T', ' ')
}
