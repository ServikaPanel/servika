import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import { CategoryIcon } from '@/components/NotificationIcon'
import {
  type Notification,
  describeNotification,
  iconBox,
  relativeTime,
  tone,
} from '@/lib/notifications'

// The whole alert history for whoever is signed in, scoped by the same
// ownership chain the API applies. It reads the same /notifications endpoint the
// bell does, so a customer, a reseller and an admin each see only their own
// rows; the two filters below are drawn from that already-scoped set and never
// widen it.
export default function NotificationsPage() {
  const { t, i18n } = useTranslation(['NotificationsPage', 'TopBar'])
  const navigate = useNavigate()
  const [items, setItems] = useState<Notification[]>([])
  const [loading, setLoading] = useState(true)
  // A failed load is SAID rather than drawn as an empty list: "no alerts" and
  // "the alerts could not be read" are opposite claims.
  const [failed, setFailed] = useState(false)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [category, setCategory] = useState('') // '' = every category

  const load = useCallback(() => {
    api.get<{ notifications: Notification[] }>('/notifications')
      .then(response => { setItems(response.data.notifications || []); setFailed(false) })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  function markAll() {
    api.post('/notifications/read-all', {})
      .then(() => setItems(list => list.map(item => ({ ...item, read: true }))))
      .catch(() => setFailed(true))
  }

  function open(item: Notification) {
    if (!item.read) {
      api.post(`/notifications/${item.id}/read`, {}).catch(() => { /* the list already reflects it */ })
      setItems(list => list.map(row => (row.id === item.id ? { ...row, read: true } : row)))
    }
    // A domain alert goes to that domain's antivirus page; a panel-wide one to
    // the server sweep page. Both sit behind the same ownership checks the API
    // applies, so a link nobody may follow simply refuses there.
    if (item.category === 'antivirus') {
      navigate(item.domain_id ? `/subscriptions/${item.domain_id}/imunify` : '/malware-scan')
    }
  }

  // A category is named from the NotificationsPage namespace, falling back to a
  // capitalised slug for a category this build does not know a label for.
  const categoryLabel = (key: string) =>
    t(`category.${key}`, { defaultValue: key ? key[0].toUpperCase() + key.slice(1) : t('category.general') })

  // The chips are derived from the LOADED set, so only categories that are
  // actually present appear.
  const categories = Array.from(new Set(items.map(item => item.category).filter(Boolean)))
  const shown = items
    .filter(item => (unreadOnly ? !item.read : true))
    .filter(item => (category ? item.category === category : true))
  const unreadCount = items.filter(item => !item.read).length

  const chip = (value: string, label: string) => (
    <button
      key={value || 'all'}
      onClick={() => setCategory(value)}
      className={`rounded-full border px-3 py-1.5 text-xs font-medium transition ${
        category === value
          ? 'border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-300'
          : 'border-slate-200 text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <div className="mx-auto max-w-4xl">
        <Breadcrumb items={[{ label: t('home'), href: '/' }, { label: t('title') }]} />
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
          {unreadCount > 0 && (
            <button
              onClick={markAll}
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-800"
            >
              {t('markAllRead', { n: unreadCount })}
            </button>
          )}
        </div>

        <div className="mb-4 flex flex-wrap items-center gap-2">
          <button
            onClick={() => setUnreadOnly(value => !value)}
            className={`rounded-full border px-3 py-1.5 text-xs font-medium transition ${
              unreadOnly
                ? 'border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-300'
                : 'border-slate-200 text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            {unreadOnly ? '● ' : '○ '}{t('unreadOnly')}
          </button>
          {categories.length > 0 && <span className="mx-1 h-5 w-px bg-slate-200 dark:bg-slate-700" />}
          {categories.length > 0 && chip('', t('allCategories'))}
          {categories.map(cat => chip(cat, categoryLabel(cat)))}
        </div>

        {failed && (
          <div className="mb-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-900/20 dark:text-rose-300">
            {t('failed')}
          </div>
        )}

        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
          {loading ? (
            <div className="px-4 py-12 text-center text-sm text-slate-400">{t('loading')}</div>
          ) : shown.length === 0 ? (
            <div className="px-4 py-16 text-center">
              <svg className="mx-auto mb-3 h-10 w-10 text-slate-300 dark:text-slate-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1" />
              </svg>
              <p className="text-sm text-slate-400 dark:text-slate-500">{unreadOnly ? t('emptyUnread') : t('empty')}</p>
            </div>
          ) : (
            shown.map(item => (
              <button
                key={item.id}
                onClick={() => open(item)}
                title={item.created_at}
                className={`flex w-full gap-3 border-b border-slate-100 px-4 py-3.5 text-left transition last:border-b-0 hover:bg-slate-50 dark:border-slate-700/50 dark:hover:bg-slate-700/40 ${item.read ? '' : 'bg-brand-50/40 dark:bg-brand-900/10'}`}
              >
                <span className={`mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg ${iconBox(item.level)}`}>
                  <CategoryIcon category={item.category} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-start justify-between gap-2">
                    <span className={`text-sm ${tone(item.level)} ${item.read ? 'font-medium' : 'font-semibold'}`}>
                      {item.domain || t('TopBar:notify.serverWide')}
                    </span>
                    <span className="flex flex-shrink-0 items-center gap-2">
                      <span className="whitespace-nowrap text-[11px] text-slate-400 dark:text-slate-500">{relativeTime(item.created_unix, i18n.language)}</span>
                      {!item.read && <span className="h-2 w-2 rounded-full bg-brand-500" />}
                    </span>
                  </span>
                  <span className="mt-1 block break-words text-xs text-slate-500 dark:text-slate-400">{describeNotification(item, t)}</span>
                  <span className="mt-2 inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-700/60">{categoryLabel(item.category)}</span>
                    {item.level === 'critical' && (
                      <span className="rounded bg-rose-100 px-1.5 py-0.5 text-rose-600 dark:bg-rose-900/30 dark:text-rose-400">{t('critical')}</span>
                    )}
                  </span>
                </span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
