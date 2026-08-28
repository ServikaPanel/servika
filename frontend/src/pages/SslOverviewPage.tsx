// Server-wide certificate overview. Its real purpose is not missing one that
// is about to expire: the list arrives sorted by nearest expiry date.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import OverviewList, { type Column, type Badge } from '@/components/OverviewList'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import { sslState } from '@/lib/ssl'

type Row = {
  domain_id: number
  domain_name: string
  status: string
  ssl_enabled: boolean
  ssl_expiry: string
  ssl_source?: string
  remaining_days: number | null
}

// Let's Encrypt issues 90-day certificates and renews 30 days out; under 14
// days means "renewal did not run", hence the separate threshold.
function RemainingBadge({ days }: { days: number | null }) {
  const { t } = useTranslation('SslOverviewPage')
  if (days === null) return <span className="text-slate-400">—</span>
  const danger = 'px-2 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300'
  const warn = 'px-2 py-0.5 rounded text-xs font-medium bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300'
  if (days < 0) return <span className={danger}>{t('remaining.expiredAgo', { days: Math.abs(days) })}</span>
  if (days <= 14) return <span className={danger}>{t('remaining.days', { days })}</span>
  if (days <= 30) return <span className={warn}>{t('remaining.days', { days })}</span>
  return <span className="text-slate-600 dark:text-slate-400">{t('remaining.days', { days })}</span>
}

export default function SslOverviewPage() {
  const { t } = useTranslation('SslOverviewPage')
  const columns: Column<Row>[] = [
    {
      title: t('column.domain'),
      cell: (s) => (
        <Link to={`/subscriptions/${s.domain_id}/ssl`} className="font-medium text-slate-900 dark:text-slate-100 hover:text-brand-600 dark:hover:text-brand-400 transition">
          {s.domain_name}
        </Link>
      ),
    },
    {
      title: t('column.ssl'),
      // A self-signed certificate is not a lesser kind of protected: the visitor
      // meets a full-page browser warning, so the site is effectively shut. It
      // also sorts here as if it expired in 14 days, since by its own dates it
      // is a year out and would otherwise sit at the bottom of this screen.
      cell: (s) => {
        const state = sslState(s.ssl_enabled, s.ssl_source)
        if (state === 'selfSigned') {
          return <span title={t('ssl.selfSignedHint')} className="px-2 py-0.5 rounded text-xs bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">{t('ssl.selfSigned')}</span>
        }
        return state === 'trusted'
          ? <span className="px-2 py-0.5 rounded text-xs bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300">{t('ssl.enabled')}</span>
          : <span className="px-2 py-0.5 rounded text-xs bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400">{t('ssl.none')}</span>
      },
    },
    { title: t('column.expiry'), cell: (s) => (s.ssl_expiry || <span className="text-slate-400">—</span>) },
    { title: t('column.remaining'), cell: (s) => <RemainingBadge days={s.remaining_days} /> },
    {
      title: t('column.status'),
      cell: (s) => (s.status === 'active'
        ? <span className="text-xs text-slate-500">{t('status.active')}</span>
        : <span className="text-xs text-amber-600">{t('status.passive')}</span>),
    },
  ]

  return (
    <OverviewList<Row>
      title={t('title')}
      icon={<Icon d={ICON.lock} className="h-6 w-6" />}
      description={t('description')}
      endpoint="/overview/ssl"
      columns={columns}
      searchField={(s) => s.domain_name}
      rowKey={(s) => s.domain_id}
      emptyMessage={t('emptyMessage')}
      summary={(list): Badge[] => {
        const expiring = list.filter((s) => s.remaining_days !== null && s.remaining_days <= 14).length
        const active = list.filter((s) => s.ssl_enabled).length
        return [
          { label: t('summary.withSsl'), value: active },
          ...(expiring > 0 ? [{ label: t('summary.expiring'), value: expiring, tone: 'danger' as const }] : []),
        ]
      }}
    />
  )
}
