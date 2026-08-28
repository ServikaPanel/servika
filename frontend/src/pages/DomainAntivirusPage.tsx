import { type ReactNode, useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { containable } from '@/lib/antivirus'
import { getCookie, setCookie } from '@/lib/cookies'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import ResourceNotice from '@/components/ResourceNotice'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Finding = {
  id: number
  file: string
  signature: string
  engine: string
  score: number
  level: string
  // Every rule that fired, where signature names only the highest-scoring one.
  // Empty for a detector with no rule set, such as ClamAV.
  rules: string
  quarantined: number
}
// What the inspect endpoint answers. `truncated` matters: the preview stops at
// 64 KiB and a prefix that reads as the whole file is how a payload appended
// past the cut goes unnoticed.
type Preview = {
  path: string
  size: number
  shown: number
  truncated: boolean
  binary: boolean
  content: string
}

type Quarantined = {
  id: number
  finding_id: number | null
  orig_path: string
  size: number
  signature: string
  engine: string
  created_at: string
  restored_at: string
}
type Scan = { id: number; status: string; engine: string; scanned: number; infected: number; started_at: string; finished_at: string }
type Status = { clamav: boolean; signature_date: string; username: string; last_scan: Scan | null; findings: Finding[] }

// The two things this screen holds: what the last scan found, and what is being
// held after being contained. They are opposite outcomes, so they get separate
// tabs rather than one long scroll, the same split the admin console uses.
type Tab = 'findings' | 'quarantine'
const TABS: Tab[] = ['findings', 'quarantine']

// Which tab was open last, so a reload does not lose the owner's place. A
// cookie, never localStorage, which is barred here. Thirty days matches the
// panel's other page-scoped preference; which tab you last looked at is a
// weaker preference than the theme or the language.
const TAB_COOKIE = 'servika.av.domain.tab'
const TAB_COOKIE_MAX_AGE = 60 * 60 * 24 * 30

// storedTab validates what it read before returning it. The cookie is text the
// reader can edit, and a value matching no tab would hide both sections at once,
// so the page would open blank with nothing saying why.
function storedTab(): Tab {
  const stored = getCookie(TAB_COOKIE)
  return TABS.includes(stored as Tab) ? (stored as Tab) : 'findings'
}

// TabButton keeps the shape MalwareScanPage.tsx already ships, so this screen
// looks like the rest of the panel. The count is drawn ONLY when there is
// something to count: a badge reading 0 takes up room to say there is nothing
// to look at.
function TabButton({ enabled, count, onClick, children }: {
  enabled: boolean
  count?: number
  onClick: () => void
  children: ReactNode
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={enabled}
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition ${
        enabled
          ? 'border-brand-600 text-brand-700 dark:text-brand-300'
          : 'border-transparent text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
      }`}
    >
      {children}
      {count ? (
        <span className="ml-1.5 rounded-full bg-slate-200 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-700 dark:text-slate-300">
          {count}
        </span>
      ) : null}
    </button>
  )
}

// Shield draws the panel's own antivirus mark, filled rather than a single line,
// and moves only while a scan is running: the sweep cone is ABSENT from the DOM
// while the server is idle, so motion here is a fact rather than a decoration.
// It reuses the keyframes MalwareScanPage.tsx defines in styles.css, which also
// carries the reduced-motion switch. It carries no third-party or foreign
// branding: this is Servika's own engine.
function Shield({ scanning, className }: { scanning: boolean; className?: string }) {
  const tone = '#34d399'
  return (
    <svg viewBox="0 0 120 120" className={className} fill="none" role="presentation" aria-hidden="true">
      <defs>
        <linearGradient id="svkAvDomShield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={tone} stopOpacity="0.28" />
          <stop offset="1" stopColor={tone} stopOpacity="0.06" />
        </linearGradient>
        <radialGradient id="svkAvDomSweep" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor={tone} stopOpacity="0.55" />
          <stop offset="1" stopColor={tone} stopOpacity="0" />
        </radialGradient>
      </defs>
      <path
        d="M60 15 L96 28 V59 C96 81 79 98 60 105 C41 98 24 81 24 59 V28 Z"
        fill="url(#svkAvDomShield)"
        stroke={tone}
        strokeWidth="2.5"
        strokeLinejoin="round"
      />
      {scanning && (
        <g className="svk-av-sweep">
          <path d="M60 60 L60 22 A38 38 0 0 1 93 46 Z" fill="url(#svkAvDomSweep)" />
        </g>
      )}
      <path d="M45 61 l10 10 l21 -24" stroke={tone} strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// homeRelativePath drops the tenant home prefix (/home/<user>/) from a displayed
// path. Every finding on this page sits under the domain's own public_html, so
// what is left is the public_html/... path the page's own subtitle already names.
// It is shorter and does not spell out the server layout; a path that is not
// under a home is left whole rather than mangled.
const homeRelativePath = (p: string) => p.replace(/^\/home\/[^/]+\//, '')

// PathBox shows a long file path WITHOUT wrapping the table row onto a second
// line: the path scrolls horizontally inside its own bordered box. The title
// carries the full absolute path, so the owner can still read where the file is.
function PathBox({ path }: { path: string }) {
  return (
    <span
      title={path}
      className="block min-w-0 max-w-full overflow-x-auto whitespace-nowrap rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-200"
    >
      {homeRelativePath(path)}
    </span>
  )
}

export default function DomainAntivirusPage() {
  const { t } = useTranslation('DomainAntivirusPage')

  // A level the panel does not know is shown verbatim rather than dropped or
  // relabelled: a row from a newer backend must not read as something milder
  // than it is.
  const levelLabel = (level: string) =>
    level === 'critical' || level === 'suspicious' ? t(`findings.level.${level}`) : level
  const levelClass = (level: string) =>
    level === 'suspicious'
      ? 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400'
      : 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-400'

  const { confirm } = useDialog()
  const { id } = useParams()
  const [d, setD] = useState<Status | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [startingScan, setStartingScan] = useState(false)
  // The scan being followed: set either by a scan the user just started or by a
  // status load that found one already running. Null means nothing to poll.
  const [pollScanID, setPollScanID] = useState<number | null>(null)
  const scanning = startingScan || pollScanID !== null
  const [signatureLoading, setSignatureLoading] = useState(false)
  const [held, setHeld] = useState<Quarantined[]>([])
  // Which quarantined file is being looked at, and what is in it. Restoring was
  // a blind decision before this: the screen listed a path and offered to put
  // the file back without ever showing what it was.
  const [previewID, setPreviewID] = useState<number | null>(null)
  const [preview, setPreview] = useState<Preview | null>(null)
  const [heldFailed, setHeldFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  // The open tab is read in a lazy initializer, not an effect: an effect would
  // draw the default for one frame before correcting it, and set-state-in-effect
  // is a hard ESLint gate here.
  const [tab, setTab] = useState<Tab>(storedTab)

  function selectTab(next: Tab) {
    setTab(next)
    setCookie(TAB_COOKIE, next, TAB_COOKIE_MAX_AGE)
  }

  const load = useCallback(() => {
    if (!id) return
    api.get<Status>(`/domains/${id}/antivirus`).then(r => {
      setD(r.data)
      setPollScanID(r.data.last_scan?.status === 'running' ? r.data.last_scan.id : null)
    }).catch(e => setError(apiError(e))).finally(() => setLoading(false))
    // The held files are read separately: they outlive the scan that produced
    // them, so a domain with no scan at all can still be holding something.
    // A list that could not be read says so. Drawing "nothing is being held" over
    // a failed request tells the owner their site is clear of something that may
    // still be sitting in the store.
    api.get<{ entries: Quarantined[] }>(`/domains/${id}/antivirus/quarantine`)
      .then(r => { setHeld(r.data.entries); setHeldFailed(false) })
      .catch(() => { setHeld([]); setHeldFailed(true) })
  }, [id])

  useEffect(() => { load() }, [load])

  // One effect owns the scan polling, so the loader no longer has to start it
  // and the two are not mutually recursive. Its cleanup replaces the interval
  // ref: leaving the page or picking up a different scan clears the old timer.
  useEffect(() => {
    if (!id || pollScanID === null) return
    let stopped = false
    const timer = setInterval(() => {
      api.get<Scan & { findings: Finding[] }>(`/domains/${id}/antivirus/scan/${pollScanID}`)
        .then(({ data }) => {
          if (stopped || data.status === 'running') return
          setPollScanID(null)
          load()
        })
        .catch(() => { if (!stopped) setPollScanID(null) })
    }, 2500)
    return () => { stopped = true; clearInterval(timer) }
  }, [id, pollScanID, load])

  async function scan() {
    setError(null); setStartingScan(true)
    try {
      const { data } = await api.post(`/domains/${id}/antivirus/scan`, {})
      setPollScanID(data.scan_id)
    } catch (e) { setError(apiError(e, t('toast.startScanFailed'))) }
    finally { setStartingScan(false) }
  }

  async function quarantineFinding(b: Finding) {
    if (!(await confirm({ message: t('confirmQuarantine', { file: b.file }), dangerous: true }))) return
    setError(null)
    // The finding is named by its id: the server reads the path from that row and
    // refuses to take one from the request.
    try { await api.post(`/domains/${id}/antivirus/quarantine`, { finding_id: b.id }); load() }
    catch (e) { setError(apiError(e, t('toast.quarantineFailed'))) }
  }

  async function quarantineAll(scanID: number, count: number) {
    if (!(await confirm({ message: t('confirmQuarantineAll', { count }), dangerous: true }))) return
    setError(null); setBusy(true)
    try {
      const { data } = await api.post<{ quarantined: number; failed: number }>(
        `/domains/${id}/antivirus/quarantine/all`, { scan_id: scanID })
      // A partial result is said out loud. Reporting a cleanup that left files
      // behind as a success is how a compromised site looks clean.
      if (data.failed > 0) setError(t('toast.quarantineAllPartial', { done: data.quarantined, failed: data.failed }))
      load()
    } catch (e) { setError(apiError(e, t('toast.quarantineFailed'))) }
    finally { setBusy(false) }
  }

  async function restore(entry: Quarantined) {
    if (!(await confirm({ message: t('held.confirmRestore', { file: entry.orig_path }), dangerous: true }))) return
    setError(null); setBusy(true)
    try { await api.post(`/domains/${id}/antivirus/quarantine/${entry.id}/restore`, {}); load() }
    catch (e) { setError(apiError(e, t('held.restoreFailed'))) }
    finally { setBusy(false) }
  }

  async function inspect(entry: Quarantined) {
    if (previewID === entry.id) { setPreviewID(null); setPreview(null); return }
    setError(null); setPreviewID(entry.id); setPreview(null)
    api.get<Preview>(`/domains/${id}/antivirus/quarantine/${entry.id}/inspect`)
      .then(response => setPreview(response.data))
      .catch(e => { setPreviewID(null); setError(apiError(e, t('held.inspectFailed'))) })
  }

  async function purge(entry: Quarantined) {
    if (!(await confirm({ message: t('held.confirmDelete', { file: entry.orig_path }), dangerous: true }))) return
    setError(null); setBusy(true)
    try { await api.delete(`/domains/${id}/antivirus/quarantine/${entry.id}`); load() }
    catch (e) { setError(apiError(e, t('held.deleteFailed'))) }
    finally { setBusy(false) }
  }

  async function updateSignature() {
    setSignatureLoading(true); setError(null)
    try { await api.post(`/domains/${id}/antivirus/update-signature`, {}); load() }
    catch (e) { setError(apiError(e, t('toast.updateSignatureFailed'))) }
    finally { setSignatureLoading(false) }
  }

  if (loading) return <div className="px-4 py-4 text-slate-400 sm:px-6 sm:py-5">{t('loading')}</div>
  if (!d) return <div className="px-4 py-4 sm:px-6 sm:py-5"><div className="text-sm text-red-600">{error || t('notFound')}</div></div>

  const activeFindings = d.findings.filter(finding => !finding.quarantined)

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: t('breadcrumb.antivirus') },
        ]} />
        <div className="flex items-center gap-3 mb-1">
          <Shield scanning={scanning} className="h-10 w-10 flex-shrink-0" />
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          <span className="font-mono">public_html</span> {t('subtitlePrefix')}
        </p>

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

        {/* Status and actions */}
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm space-y-0.5">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${d.clamav ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                <span className="text-slate-700 dark:text-slate-200">{t('status.enginePrefix')} <span className="font-medium">{d.clamav ? t('status.engineFull') : t('status.engineHeuristics')}</span></span>
              </div>
              {d.clamav && <div className="text-xs text-slate-400 ml-4">{t('status.signatureDatabase', { date: d.signature_date || '-' })}</div>}
              {d.last_scan && <div className="text-xs text-slate-400 ml-4">
                {t('status.latestScan', { date: d.last_scan.finished_at || d.last_scan.started_at, scanned: d.last_scan.scanned, infected: d.last_scan.infected })}
              </div>}
            </div>
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              {d.clamav && <button onClick={updateSignature} disabled={signatureLoading || scanning}
                className="px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50">
                {signatureLoading ? t('status.updating') : t('status.updateSignatures')}</button>}
              <button onClick={scan} disabled={scanning}
                className="px-4 py-2 text-sm font-medium bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-lg disabled:opacity-50">
                {scanning ? t('status.scanning') : t('status.scanNow')}</button>
            </div>
          </div>
          {scanning ? (
            <div className="mt-3 flex items-center gap-2 text-sm text-brand-600 dark:text-brand-400">
              <span className="inline-block w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
              {t('status.inProgress')}
            </div>
          ) : (
            /* Stated before the scan starts, not while it runs: by then the cost
               has already been paid and the progress line has the floor. */
            <div className="mt-3">
              <ResourceNotice>{t('status.resourceWarning')}</ResourceNotice>
            </div>
          )}
        </div>

        {/* The status and action bar stays above the tabs, because the scan
            button and the engine line belong to both sections. The two lists
            below both loaded on mount, so their badges are correct whichever
            tab is open. */}
        <div role="tablist" className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-700">
          <TabButton enabled={tab === 'findings'} count={activeFindings.length} onClick={() => selectTab('findings')}>{t('tabs.findings')}</TabButton>
          <TabButton enabled={tab === 'quarantine'} count={held.length} onClick={() => selectTab('quarantine')}>{t('tabs.quarantine')}</TabButton>
        </div>

        {/* Findings */}
        {tab === 'findings' && (
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('findings.title')} {d.last_scan && <span className="text-xs font-normal text-slate-400">{t('findings.fromLatest')}</span>}
            </h3>
            {d.last_scan && activeFindings.length > 0 && (
              <button
                onClick={() => quarantineAll(d.last_scan!.id, activeFindings.length)}
                disabled={busy || scanning}
                className="rounded-lg border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 transition hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-900/30"
              >
                {t('findings.quarantineAll', { count: activeFindings.length })}
              </button>
            )}
          </div>
          {!d.last_scan ? (
            <div className="text-center py-8 text-sm text-slate-500 dark:text-slate-400">{t('findings.noScans')}</div>
          ) : activeFindings.length === 0 && d.findings.length === 0 ? (
            <div className="text-center py-8">
              <Shield scanning={false} className="mx-auto mb-2 h-14 w-14" />
              <p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">{t('findings.clean')}</p>
            </div>
          ) : (
            <div className={responsiveTableContainerClass}>
              <table className={responsiveTableClass}>
                <thead className={responsiveTableHeadClass}>
                  <tr>
                    <th className="py-2 pr-3 text-left">{t('findings.colFile')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colLevel')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colSignature')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colEngine')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colStatus')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody className={responsiveTableBodyClass}>
                  {d.findings.map((b, i) => (
                    <tr key={i} className={responsiveTableRowClass}>
                      <td data-label={t('findings.colFile')} className={`${responsiveTableCellClass} lg:min-w-[20rem]`}><PathBox path={b.file} /></td>
                      <td data-label={t('findings.colLevel')} className={responsiveTableCellClass}>
                        <span className={`text-xs px-1.5 py-0.5 rounded ${levelClass(b.level)}`}>{levelLabel(b.level)}</span>
                      </td>
                      <td data-label={t('findings.colSignature')} className={responsiveTableCellClass}>
                        <div>{b.signature}</div>
                        {/* The other rules that fired. A suspicious verdict is
                            reached by adding up evidence, so showing only the
                            strongest one hides why the total got there. */}
                        {b.rules && b.rules !== b.signature && (
                          <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 break-words">{b.rules}</div>
                        )}
                      </td>
                      <td data-label={t('findings.colEngine')} className={responsiveTableCellClass}><span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500">{b.engine}</span></td>
                      <td data-label={t('findings.colStatus')} className={responsiveTableCellClass}>
                        {b.quarantined ? <span className="text-xs text-amber-600 dark:text-amber-400">{t('findings.quarantined')}</span>
                          : <span className="text-xs text-red-600 dark:text-red-400">{t('findings.active')}</span>}
                      </td>
                      <td className={responsiveTableActionCellClass}>
                        {/* A finding whose subject is not a file has nothing to
                            contain, and the server refuses it, so no button is
                            drawn rather than one that always fails. */}
                        {!b.quarantined && (containable(b.engine)
                          ? <button onClick={() => quarantineFinding(b)} className="text-xs text-red-600 dark:text-red-400 hover:underline whitespace-nowrap">{t('findings.quarantine')}</button>
                          : <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{t('findings.notAFile')}</span>)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        )}

        {/* Held files. Listed even when no scan has run, because they outlive the
            scan that produced them and a false positive has to be reachable. */}
        {tab === 'quarantine' && (
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('held.title')}</h3>
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('held.subtitle')}</p>
          {heldFailed ? (
            <div className="py-6 text-center text-sm text-red-600 dark:text-red-400">{t('held.loadFailed')}</div>
          ) : held.length === 0 ? (
            <div className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('held.empty')}</div>
          ) : (
            <div className={responsiveTableContainerClass}>
              <table className={responsiveTableClass}>
                <thead className={responsiveTableHeadClass}>
                  <tr>
                    <th className="py-2 pr-3 text-left">{t('held.colFile')}</th>
                    <th className="py-2 pr-3 text-left">{t('held.colSignature')}</th>
                    <th className="py-2 pr-3 text-left">{t('held.colDate')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody className={responsiveTableBodyClass}>
                  {held.map(entry => (
                    <tr key={entry.id} className={responsiveTableRowClass}>
                      <td data-label={t('held.colFile')} className={`${responsiveTableCellClass} lg:min-w-[20rem]`}><PathBox path={entry.orig_path} /></td>
                      <td data-label={t('held.colSignature')} className={responsiveTableCellClass}>{entry.signature || '-'}</td>
                      <td data-label={t('held.colDate')} className={responsiveTableCellClass}>
                        {entry.restored_at ? t('held.restoredOn', { date: entry.restored_at }) : entry.created_at}
                      </td>
                      <td className={responsiveTableActionCellClass}>
                        {!entry.restored_at && (
                          <div className="flex gap-3 whitespace-nowrap">
                            <button onClick={() => inspect(entry)}
                              className="text-xs text-slate-600 hover:underline dark:text-slate-300">
                              {previewID === entry.id ? t('held.inspectClose') : t('held.inspect')}</button>
                            <button onClick={() => restore(entry)} disabled={busy}
                              className="text-xs text-brand-600 hover:underline disabled:opacity-50 dark:text-brand-400">
                              {t('held.restore')}</button>
                            <button onClick={() => purge(entry)} disabled={busy}
                              className="text-xs text-red-600 hover:underline disabled:opacity-50 dark:text-red-400">
                              {t('held.delete')}</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {previewID !== null && (
                <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-900/60">
                  {!preview ? (
                    <p className="text-xs text-slate-500 dark:text-slate-400">{t('held.inspectLoading')}</p>
                  ) : preview.binary ? (
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {t('held.inspectBinary', { size: preview.size })}
                    </p>
                  ) : (
                    <>
                      <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">
                        {preview.truncated
                          ? t('held.inspectTruncated', { shown: preview.shown, size: preview.size })
                          : t('held.inspectWhole', { size: preview.size })}
                      </p>
                      {/* The content is a KNOWN MALICIOUS file. React escapes
                          text, so it is drawn as text and never as markup, and
                          nothing here evaluates it. */}
                      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 text-[11px] leading-relaxed text-slate-800 dark:bg-slate-950 dark:text-slate-200">
                        {preview.content}
                      </pre>
                    </>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
        )}

        <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link></div>
      </div>
    </div>
  )
}
