import { useTranslation } from 'react-i18next'
import {
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

export type SecurityFinding = {
  id: number
  domain_id: number
  domain_name: string
  app_type: string
  install_path: string
  package_name: string
  installed_version: string
  cve_id: string
  severity: string
  cvss: number
  title: string
  fixed_in: string
  source: string
  first_seen: string
  last_seen: string
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  low: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300',
}

/**
 * Renders the findings.
 *
 * The CVSS column is blank rather than zero when the feed gave no number. OSV
 * publishes a CVSS vector, not a base score, and the backend refuses to compute
 * one from it, so a 0.0 here would read as "harmless" for a finding whose
 * severity word may well be critical.
 */
export default function SecurityFindingsTable({
  findings,
  loading,
  showDomain = false,
}: {
  findings: SecurityFinding[]
  loading: boolean
  showDomain?: boolean
}) {
  const { t } = useTranslation('SiteSecurity')

  return (
    <div className={responsiveTableContainerClass}>
      <table className={responsiveTableClass}>
        <thead className={responsiveTableHeadClass}>
          <tr>
            <th className="px-3 py-2 text-left">{t('table.severity')}</th>
            {showDomain && <th className="px-3 py-2 text-left">{t('table.domain')}</th>}
            <th className="px-3 py-2 text-left">{t('table.package')}</th>
            <th className="px-3 py-2 text-left">{t('table.installed')}</th>
            <th className="px-3 py-2 text-left">{t('table.fixedIn')}</th>
            <th className="px-3 py-2 text-left">{t('table.advisory')}</th>
            <th className="px-3 py-2 text-left">{t('table.firstSeen')}</th>
          </tr>
        </thead>
        <tbody className={responsiveTableBodyClass}>
          {loading && (
            <tr className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} colSpan={showDomain ? 7 : 6}>{t('table.loading')}</td>
            </tr>
          )}
          {!loading && findings.length === 0 && (
            <tr className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} colSpan={showDomain ? 7 : 6}>{t('table.empty')}</td>
            </tr>
          )}
          {!loading && findings.map(finding => (
            <tr key={finding.id} className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} data-label={t('table.severity')}>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                  SEVERITY_CLASS[finding.severity] || SEVERITY_CLASS.low
                }`}>
                  {finding.severity ? t(`severity.${finding.severity}`, { defaultValue: finding.severity }) : t('severity.unknown')}
                </span>
                {finding.cvss > 0 && (
                  <span className="ml-2 font-mono text-xs text-slate-500 dark:text-slate-400">{finding.cvss.toFixed(1)}</span>
                )}
              </td>
              {showDomain && (
                <td className={responsiveTableCellClass} data-label={t('table.domain')}>{finding.domain_name}</td>
              )}
              <td className={responsiveTableCellClass} data-label={t('table.package')}>
                <div className="font-mono text-xs">{finding.package_name}</div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  {t(`appType.${finding.app_type}`, { defaultValue: finding.app_type })} · {finding.install_path}
                </div>
              </td>
              <td className={`${responsiveTableCellClass} font-mono text-xs`} data-label={t('table.installed')}>
                {finding.installed_version}
              </td>
              <td className={`${responsiveTableCellClass} font-mono text-xs`} data-label={t('table.fixedIn')}>
                {finding.fixed_in || t('table.noFix')}
              </td>
              <td className={responsiveTableCellClass} data-label={t('table.advisory')}>
                {finding.source ? (
                  <a href={finding.source} target="_blank" rel="noreferrer noopener"
                    className="font-mono text-xs text-brand-600 hover:underline dark:text-brand-400">
                    {finding.cve_id}
                  </a>
                ) : (
                  <span className="font-mono text-xs">{finding.cve_id}</span>
                )}
                {finding.title && (
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">{finding.title}</div>
                )}
              </td>
              <td className={responsiveTableCellClass} data-label={t('table.firstSeen')}>{finding.first_seen}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
