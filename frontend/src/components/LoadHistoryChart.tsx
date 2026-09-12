import { isAxiosError } from 'axios'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'

type Point = { ts: string; load_1m: number; load_5m: number; load_15m: number; memory: number }
type Response = { hour: number; cores: number; points: Point[] }

const INTERVALS = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
]

const SERIES = [
  { key: 'load_1m' as const, label: '1min', color: '#f97316' },  // brand
  { key: 'load_5m' as const, label: '5min', color: '#0ea5e9' },  // sky
  { key: 'load_15m' as const, label: '15min', color: '#8b5cf6' }, // violet
]

// SVG plane — uniform scale (text/lines stay sharp)
const W0 = 1000, H = 320, ML = 46, MR = 16, MT = 16, MB = 30

export default function LoadHistoryChart() {
  const { t } = useTranslation('LoadHistoryChart')
  const [hours, setHours] = useState(24)
  const [d, setD] = useState<Response | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const [hover, setHover] = useState<number | null>(null)

  useEffect(() => {
    let on = true
    async function tick() {
      if (typeof document !== 'undefined' && document.hidden) return
      try {
        const r = await api.get<Response>(`/system/load-history?hour=${hours}`)
        if (on) { setD(r.data); setForbidden(false) }
      } catch (e) {
        if (on && isAxiosError(e) && e.response?.status === 403) setForbidden(true)
      }
    }
    tick()
    const t = setInterval(tick, 30000)
    return () => { on = false; clearInterval(t) }
  }, [hours])

  // Memoized because the empty fallback is a fresh array on every render, which
  // would defeat the path memoization further down.
  const pts = useMemo(() => d?.points || [], [d])
  const cores = d?.cores || 0
  const latest = pts[pts.length - 1]

  // Measure card width: keep viewBox at fixed H (px) so text/lines are crisp.
  const wrapRef = useRef<HTMLDivElement>(null)
  const [Wpx, setWpx] = useState(0)
  useEffect(() => {
    const el = wrapRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver((es) => { const w = es[0]?.contentRect.width; if (w && w > 0) setWpx(Math.round(w)) })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const W = Wpx > 40 ? Wpx - 40 : W0 // p-5 card padding = 2×20px

  const cw = W - ML - MR, ch = H - MT - MB

  const g = useMemo(() => {
    if (!pts.length) return null
    const allVals = pts.flatMap(p => [p.load_1m, p.load_5m, p.load_15m])
    const maxVal = Math.max(0.5, cores, ...allVals)
    const yMax = maxVal * 1.08
    // √ scale: detail at low loads + spikes remain visible
    const sq = Math.sqrt(yMax)
    const yAt = (v: number) => MT + (1 - Math.sqrt(Math.max(0, Math.min(v, yMax))) / sq) * ch
    const xAt = (i: number) => ML + (pts.length <= 1 ? cw / 2 : (i / (pts.length - 1)) * cw)

    const smooth = (key: keyof Point) => {
      const xs = pts.map((_, i) => xAt(i))
      const ys = pts.map(p => yAt(p[key] as number))
      const n = xs.length
      if (n === 1) return `M${xs[0].toFixed(1)},${ys[0].toFixed(1)}`
      const dx: number[] = [], m: number[] = []
      for (let i = 0; i < n - 1; i++) { dx[i] = xs[i + 1] - xs[i]; m[i] = (ys[i + 1] - ys[i]) / (dx[i] || 1) }
      const t: number[] = new Array(n)
      t[0] = m[0]; t[n - 1] = m[n - 2]
      for (let i = 1; i < n - 1; i++) t[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2
      for (let i = 0; i < n - 1; i++) {
        if (m[i] === 0) { t[i] = 0; t[i + 1] = 0; continue }
        const a = t[i] / m[i], b = t[i + 1] / m[i], h = Math.hypot(a, b)
        if (h > 3) { const s = 3 / h; t[i] = s * a * m[i]; t[i + 1] = s * b * m[i] }
      }
      let p = `M${xs[0].toFixed(1)},${ys[0].toFixed(1)}`
      for (let i = 0; i < n - 1; i++) {
        const hi = dx[i]
        p += ` C${(xs[i] + hi / 3).toFixed(1)},${(ys[i] + t[i] * hi / 3).toFixed(1)} ${(xs[i + 1] - hi / 3).toFixed(1)},${(ys[i + 1] - t[i + 1] * hi / 3).toFixed(1)} ${xs[i + 1].toFixed(1)},${ys[i + 1].toFixed(1)}`
      }
      return p
    }
    const line1m = smooth('load_1m')
    const area1m = pts.length > 1 ? `${line1m} L${xAt(pts.length - 1).toFixed(1)},${(H - MB).toFixed(1)} L${xAt(0).toFixed(1)},${(H - MB).toFixed(1)} Z` : ''

    const nice = (x: number) => { if (x <= 0) return 0; const p = Math.pow(10, Math.floor(Math.log10(x))); const n = x / p; return (n < 1.5 ? 1 : n < 3 ? 2 : n < 7 ? 5 : 10) * p }
    const rawTicks = [0, nice(yMax * 0.06), nice(yMax * 0.22), nice(yMax * 0.5), Math.round(yMax * 10) / 10]
    const yTicks = [...new Set(rawTicks)].filter(v => v <= yMax).sort((a, b) => a - b)

    const xLabel = (ts: string) => hours > 24 ? ts.slice(5, 10).replace('-', '/') : ts.slice(11, 16)
    const xTickIdx = pts.length > 1 ? [0, Math.floor(pts.length / 3), Math.floor((2 * pts.length) / 3), pts.length - 1] : [0]

    return { yAt, xAt, line1m, area1m, yTicks, xLabel, xTickIdx, yMax, smooth }
  }, [pts, cores, hours, cw, ch])

  if (forbidden) return null

  const hp = hover != null ? pts[hover] : null

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    if (pts.length < 2) return
    const rect = e.currentTarget.getBoundingClientRect()
    const px = ((e.clientX - rect.left) / rect.width) * W
    const df = (px - ML) / cw
    setHover(Math.max(0, Math.min(pts.length - 1, Math.round(df * (pts.length - 1)))))
  }

  return (
    <div ref={wrapRef} className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900/60">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h3>
          <p className="text-[11px] text-slate-400 dark:text-slate-500">
            {t('subtitle')}{cores ? ` · ${t('cores', { count: cores })}` : ''} · {t('scale')}
          </p>
        </div>
        <div className="flex items-center gap-0.5 rounded-xl border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-800 dark:bg-slate-800/60">
          {INTERVALS.map(a => (
            <button key={a.hours} onClick={() => { setHours(a.hours); setHover(null) }}
              className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${hours === a.hours
                ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'}`}>
              {a.label}
            </button>
          ))}
        </div>
      </div>

      <ValueRow hp={hp} latest={latest} cores={cores} />

      {!g ? <NoData /> : (
        <ChartSvg W={W} g={g} pts={pts} hp={hp} hover={hover} cores={cores}
          onMove={onMove} onLeave={() => setHover(null)} />
      )}
    </div>
  )
}

// The plotted geometry of one render. It is computed once per data change and
// read by the chart, so the two cannot disagree about where a point sits.
type Geometry = {
  yAt: (v: number) => number
  xAt: (i: number) => number
  line1m: string
  area1m: string
  yTicks: number[]
  xLabel: (ts: string) => string
  xTickIdx: number[]
  yMax: number
  smooth: (key: keyof Point) => string
}

// ValueRow shows the hovered reading of each series, or the latest one when
// nothing is hovered. A reading above the core count is drawn in red.
function ValueRow({ hp, latest, cores }: { hp: Point | null; latest: Point | undefined; cores: number }) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1.5">
      {SERIES.map(s => {
        const v = hp ? (hp[s.key] as number) : latest ? (latest[s.key] as number) : null
        const over = cores > 0 && v != null && v > cores
        return (
          <div key={s.key} className="flex items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: s.color }} />
            <span className="text-slate-500 dark:text-slate-400">{s.label}</span>
            <span className={`font-mono font-semibold tabular-nums ${over ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-slate-100'}`}>
              {v == null ? '—' : v.toFixed(2)}
            </span>
          </div>
        )
      })}
      {hp && <span className="ml-auto font-mono text-[11px] text-slate-400 dark:text-slate-500">{hp.ts.slice(5, 16).replace('-', '/').replace('T', ' ')}</span>}
    </div>
  )
}

function NoData() {
  const { t } = useTranslation('LoadHistoryChart')
  return (
    <div className="flex h-[240px] flex-col items-center justify-center text-center">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-9 w-9 text-slate-300 dark:text-slate-600">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125 8 8l3 6 4-9 3 6h4" />
      </svg>
      <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">{t('noData')}</p>
      <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">{t('noDataHint')}</p>
    </div>
  )
}

type ChartProps = {
  W: number
  g: Geometry
  pts: Point[]
  hp: Point | null
  hover: number | null
  cores: number
  onMove: (e: React.MouseEvent<SVGSVGElement>) => void
  onLeave: () => void
}

function ChartSvg({ W, g, pts, hp, hover, cores, onMove, onLeave }: ChartProps) {
  const { t } = useTranslation('LoadHistoryChart')
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" onMouseMove={onMove} onMouseLeave={onLeave}>
      <defs>
        <linearGradient id="lh-area" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#f97316" stopOpacity="0.30" />
          <stop offset="70%" stopColor="#f97316" stopOpacity="0.06" />
          <stop offset="100%" stopColor="#f97316" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* horizontal grid + Y labels */}
      {g.yTicks.map((v, i) => (
        <g key={i}>
          <line x1={ML} y1={g.yAt(v)} x2={W - MR} y2={g.yAt(v)} className="stroke-slate-100 dark:stroke-slate-800" strokeWidth="1" />
          <text x={ML - 8} y={g.yAt(v) + 3.5} textAnchor="end" className="fill-slate-400 dark:fill-slate-500" fontSize="11" fontFamily="ui-monospace,monospace">{v.toFixed(v < 10 ? 1 : 0)}</text>
        </g>
      ))}

      {/* core reference (=100% capacity) */}
      {cores > 0 && cores <= g.yMax && (
        <g>
          <line x1={ML} y1={g.yAt(cores)} x2={W - MR} y2={g.yAt(cores)} stroke="#ef4444" strokeWidth="1" strokeDasharray="5 5" opacity="0.55" />
          <text x={W - MR} y={g.yAt(cores) - 5} textAnchor="end" fill="#ef4444" fontSize="10" opacity="0.85">{t('coresCapacity', { count: cores })}</text>
        </g>
      )}

      {/* X labels */}
      {g.xTickIdx.map((idx, i) => (
        <text key={i} x={g.xAt(idx)} y={H - 9} textAnchor={i === 0 ? 'start' : i === g.xTickIdx.length - 1 ? 'end' : 'middle'}
          className="fill-slate-400 dark:fill-slate-500" fontSize="11" fontFamily="ui-monospace,monospace">{g.xLabel(pts[idx].ts)}</text>
      ))}

      {/* area + series (15→5→1 on top) */}
      <path d={g.area1m} fill="url(#lh-area)" />
      <path d={g.smooth('load_15m')} fill="none" stroke="#8b5cf6" strokeWidth="1.5" strokeLinejoin="round" opacity="0.75" />
      <path d={g.smooth('load_5m')} fill="none" stroke="#0ea5e9" strokeWidth="1.8" strokeLinejoin="round" opacity="0.9" />
      <path d={g.line1m} fill="none" stroke="#f97316" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />

      {/* last point pulse */}
      {pts.length > 0 && (
        <g>
          <circle cx={g.xAt(pts.length - 1)} cy={g.yAt(pts[pts.length - 1].load_1m)} r="7" fill="#f97316" opacity="0.18">
            <animate attributeName="r" values="4;9;4" dur="2.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.28;0;0.28" dur="2.4s" repeatCount="indefinite" />
          </circle>
          <circle cx={g.xAt(pts.length - 1)} cy={g.yAt(pts[pts.length - 1].load_1m)} r="3" fill="#f97316" />
        </g>
      )}

      {/* hover crosshair + dot */}
      {hp && hover != null && (
        <g>
          <line x1={g.xAt(hover)} y1={MT} x2={g.xAt(hover)} y2={H - MB} className="stroke-slate-300 dark:stroke-slate-600" strokeWidth="1" strokeDasharray="3 3" />
          <circle cx={g.xAt(hover)} cy={g.yAt(hp.load_1m)} r="3.5" fill="#f97316" stroke="#0d1524" strokeWidth="1.5" />
        </g>
      )}
    </svg>
  )
}
