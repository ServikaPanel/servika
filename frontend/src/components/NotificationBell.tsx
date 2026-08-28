import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'
import { CategoryIcon } from '@/components/NotificationIcon'
import {
  type Notification,
  describeNotification,
  iconBox,
  relativeTime,
  tone,
} from '@/lib/notifications'

// How often the badge is refreshed while the panel is open. A notification is
// not a live feed: the events behind it are a nightly sweep and a file-write
// detection, so a minute is soon enough and a shorter interval is a request per
// open tab per second for a count that rarely changes.
const POLL_MS = 60_000

export default function NotificationBell() {
  const { t, i18n } = useTranslation('TopBar')
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState<Notification[]>([])
  const [unread, setUnread] = useState(0)
  // A failed load is SAID rather than drawn as an empty list: "no alerts" and
  // "the alerts could not be read" are opposite claims and an empty dropdown
  // makes the second look like the first.
  const [failed, setFailed] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)

  // State is written only from the promise callbacks, so the mount effect never
  // sets state synchronously.
  const load = useCallback(() => {
    api.get<{ notifications: Notification[]; unread: number }>('/notifications')
      .then(response => {
        setItems(response.data.notifications || [])
        setUnread(response.data.unread || 0)
        setFailed(false)
      })
      .catch(() => setFailed(true))
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(load, POLL_MS)
    return () => clearInterval(timer)
  }, [load])

  useEffect(() => {
    if (!open) return
    function onClickOutside(event: MouseEvent) {
      if (!boxRef.current?.contains(event.target as Node)) setOpen(false)
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    window.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClickOutside)
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  function markRead(item: Notification) {
    if (item.read) return
    api.post(`/notifications/${item.id}/read`, {}).then(load).catch(() => setFailed(true))
  }

  function markAll() {
    api.post('/notifications/read-all', {}).then(load).catch(() => setFailed(true))
  }

  function openItem(item: Notification) {
    markRead(item)
    setOpen(false)
    // A domain alert goes to that domain's antivirus page; a panel-wide one to
    // the server sweep page. Both are behind the same ownership checks the API
    // applies, so a link nobody may follow simply refuses there.
    if (item.category === 'antivirus') {
      navigate(item.domain_id ? `/subscriptions/${item.domain_id}/imunify` : '/malware-scan')
    }
  }

  return (
    <div className="relative" ref={boxRef}>
      <button
        onClick={() => { setOpen(value => !value); if (!open) load() }}
        aria-label={t('notifications')}
        title={t('notifications')}
        className="relative hidden sm:inline-flex p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unread > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[1.1rem] px-1 rounded-full bg-rose-600 text-[10px] font-semibold leading-4 text-white text-center">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-[27rem] max-w-[calc(100vw-1.5rem)] max-h-96 overflow-y-auto rounded-xl border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-900 z-50">
          <div className="sticky top-0 z-10 flex items-center justify-between px-3 py-2 border-b border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900">
            <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">
              {t('notifications')}
              {unread > 0 && <span className="ml-1.5 font-normal text-slate-400">{t('notify.newCount', { n: unread })}</span>}
            </span>
            {unread > 0 && (
              <button onClick={markAll} className="text-xs text-brand-600 hover:underline dark:text-brand-400">
                {t('notify.markAll')}
              </button>
            )}
          </div>
          {failed ? (
            <p className="px-3 py-4 text-xs text-rose-700 dark:text-rose-300">{t('notify.failed')}</p>
          ) : items.length === 0 ? (
            <div className="px-3 py-8 text-center">
              <svg className="mx-auto mb-2 h-8 w-8 text-slate-300 dark:text-slate-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1" />
              </svg>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('notify.empty')}</p>
            </div>
          ) : (
            <ul>
              {items.map(item => (
                <li key={item.id} className="border-b border-slate-100 last:border-0 dark:border-slate-800">
                  <button
                    onClick={() => openItem(item)}
                    title={item.created_at}
                    className={`flex w-full gap-3 px-3 py-2.5 text-left transition hover:bg-slate-50 dark:hover:bg-slate-800/60 ${item.read ? 'opacity-60' : 'bg-brand-50/50 dark:bg-brand-900/10'}`}
                  >
                    <span className={`mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg ${iconBox(item.level)}`}>
                      <CategoryIcon category={item.category} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-start gap-1.5">
                        <span className={`block text-xs ${tone(item.level)} ${item.read ? 'font-medium' : 'font-semibold'}`}>
                          {item.domain || t('notify.serverWide')}
                        </span>
                        {!item.read && <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-500" />}
                      </span>
                      <span className="mt-0.5 block text-xs text-slate-700 dark:text-slate-300 line-clamp-2">{describeNotification(item, t)}</span>
                      <span className="mt-1 block text-[10px] text-slate-400 dark:text-slate-500">{relativeTime(item.created_unix, i18n.language)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {!failed && items.length > 0 && (
            <button
              onClick={() => { setOpen(false); navigate('/notifications') }}
              className="sticky bottom-0 w-full border-t border-slate-100 bg-white px-4 py-2.5 text-center text-xs font-medium text-brand-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-brand-400 dark:hover:bg-slate-800/60"
            >
              {t('notify.showAll')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
