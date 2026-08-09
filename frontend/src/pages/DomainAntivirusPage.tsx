import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError as apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import ResourceNotice from '@/components/ResourceNotice'
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

type Finding = { id: number; file: string; signature: string; engine: string; quarantined: number }
type Scan = { id: number; status: string; engine: string; scanned: number; infected: number; started_at: string; finished_at: string }
type Status = { clamav: boolean; signature_date: string; username: string; last_scan: Scan | null; findings: Finding[] }

export default function DomainAntivirusPage() {
  const { t } = useTranslation('DomainAntivirusPage')
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

  const load = useCallback(() => {
    if (!id) return
    api.get<Status>(`/domains/${id}/antivirus`).then(r => {
      setD(r.data)
      setPollScanID(r.data.last_scan?.status === 'running' ? r.data.last_scan.id : null)
    }).catch(e => setError(apiError(e))).finally(() => setLoading(false))
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
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
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

        {/* Findings */}
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
            {t('findings.title')} {d.last_scan && <span className="text-xs font-normal text-slate-400">{t('findings.fromLatest')}</span>}
          </h3>
          {!d.last_scan ? (
            <div className="text-center py-8 text-sm text-slate-500 dark:text-slate-400">{t('findings.noScans')}</div>
          ) : activeFindings.length === 0 && d.findings.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-3xl mb-2">✅</div>
              <p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">{t('findings.clean')}</p>
            </div>
          ) : (
            <div className={responsiveTableContainerClass}>
              <table className={responsiveTableClass}>
                <thead className={responsiveTableHeadClass}>
                  <tr>
                    <th className="py-2 pr-3 text-left">{t('findings.colFile')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colSignature')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colEngine')}</th>
                    <th className="py-2 pr-3 text-left">{t('findings.colStatus')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody className={responsiveTableBodyClass}>
                  {d.findings.map((b, i) => (
                    <tr key={i} className={responsiveTableRowClass}>
                      <td data-label={t('findings.colFile')} className={`${responsiveTableCodeCellClass} break-all`}>{b.file}</td>
                      <td data-label={t('findings.colSignature')} className={responsiveTableCellClass}>{b.signature}</td>
                      <td data-label={t('findings.colEngine')} className={responsiveTableCellClass}><span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500">{b.engine}</span></td>
                      <td data-label={t('findings.colStatus')} className={responsiveTableCellClass}>
                        {b.quarantined ? <span className="text-xs text-amber-600 dark:text-amber-400">{t('findings.quarantined')}</span>
                          : <span className="text-xs text-red-600 dark:text-red-400">{t('findings.active')}</span>}
                      </td>
                      <td className={responsiveTableActionCellClass}>
                        {!b.quarantined && <button onClick={() => quarantineFinding(b)} className="text-xs text-red-600 dark:text-red-400 hover:underline whitespace-nowrap">{t('findings.quarantine')}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('backToSubscription')}</Link></div>
      </div>
    </div>
  )
}
