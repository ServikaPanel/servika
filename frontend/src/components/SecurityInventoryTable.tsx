import { useTranslation } from 'react-i18next'
import {
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

export type SecurityApp = {
  domain_id: number
  domain_name: string
  app_type: string
  install_path: string
  app_version: string
  package_count: number
  finding_count: number
  last_scanned: string
}

/**
 * Renders what the last sweep inspected.
 *
 * A row with no findings is the point of this table. The findings list alone
 * cannot say whether an empty result means every site is clean or that nothing
 * was ever looked at, and those are opposite answers.
 */
export default function SecurityInventoryTable({
  apps,
  loading,
}: {
  apps: SecurityApp[]
  loading: boolean
}) {
  const { t } = useTranslation('SiteSecurity')

  return (
    <div className={responsiveTableContainerClass}>
      <table className={responsiveTableClass}>
        <thead className={responsiveTableHeadClass}>
          <tr>
            <th className="px-3 py-2 text-left">{t('table.domain')}</th>
            <th className="px-3 py-2 text-left">{t('inventory.application')}</th>
            <th className="px-3 py-2 text-left">{t('inventory.version')}</th>
            <th className="px-3 py-2 text-left">{t('inventory.packages')}</th>
            <th className="px-3 py-2 text-left">{t('inventory.findings')}</th>
            <th className="px-3 py-2 text-left">{t('inventory.lastScanned')}</th>
          </tr>
        </thead>
        <tbody className={responsiveTableBodyClass}>
          {loading && (
            <tr className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} colSpan={6}>{t('table.loading')}</td>
            </tr>
          )}
          {!loading && apps.length === 0 && (
            <tr className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} colSpan={6}>{t('inventory.empty')}</td>
            </tr>
          )}
          {!loading && apps.map(app => (
            <tr key={`${app.domain_id}:${app.app_type}:${app.install_path}`} className={responsiveTableRowClass}>
              <td className={responsiveTableCellClass} data-label={t('table.domain')}>{app.domain_name}</td>
              <td className={responsiveTableCellClass} data-label={t('inventory.application')}>
                <div>{t(`appType.${app.app_type}`, { defaultValue: app.app_type })}</div>
                <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{app.install_path}</div>
              </td>
              {/* A dash, never a zero or an invented value: npm and Composer
                  installations carry no version of their own for this to read. */}
              <td className={`${responsiveTableCellClass} font-mono text-xs`} data-label={t('inventory.version')}>
                {app.app_version || '—'}
              </td>
              <td className={responsiveTableCellClass} data-label={t('inventory.packages')}>{app.package_count}</td>
              <td className={responsiveTableCellClass} data-label={t('inventory.findings')}>
                {app.finding_count > 0 ? (
                  <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">
                    {app.finding_count}
                  </span>
                ) : (
                  <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
                    {t('inventory.clean')}
                  </span>
                )}
              </td>
              <td className={responsiveTableCellClass} data-label={t('inventory.lastScanned')}>{app.last_scanned}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
