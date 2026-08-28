import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'

// One alert as the server reports it.
//
// `key` and `params` are what the sentence is COMPOSED from, in the reader's
// language. `title` and `message` are the server's English and are the fallback:
// a notification written by something this build does not know about still shows
// as words rather than as a blank row.
type Notification = {
  id: number
  level: string
  category: string
  title: string
  message: string
  key: string
  params: string
  domain_id: number | null
  domain: string
  ref_type: string
  ref_id: number
  read: boolean
  created_at: string
  // The same instant as an epoch, so relative time needs no timezone guess.
  created_unix: number
}

// How often the badge is refreshed while the panel is open. A notification is
// not a live feed: the events behind it are a nightly sweep and a file-write
// detection, so a minute is soon enough and a shorter interval is a request per
// open tab per second for a count that rarely changes.
const POLL_MS = 60_000

function tone(level: string): string {
  if (level === 'critical') return 'text-rose-700 dark:text-rose-300'
  if (level === 'warning') return 'text-amber-700 dark:text-amber-300'
  return 'text-slate-600 dark:text-slate-400'
}

// The icon box behind each alert is coloured by severity, so the list reads at a
// glance: a critical alert is not the same weight as an informational one.
const ICON_BOX: Record<string, string> = {
  critical: 'bg-rose-100 text-rose-600 dark:bg-rose-900/30 dark:text-rose-400',
  warning: 'bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400',
  info: 'bg-sky-100 text-sky-600 dark:bg-sky-900/30 dark:text-sky-400',
}
function iconBox(level: string): string {
  return ICON_BOX[level] || ICON_BOX.info
}

// The category decides the glyph: a shield for antivirus, a bell for the rest.
function CategoryIcon({ category }: { category: string }) {
  const shield = 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'
  const bell = 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1'
  return (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d={category === 'antivirus' ? shield : bell} />
    </svg>
  )
}

// A relative time ("3 hours ago") in the reader's language, from Intl rather than
// twelve hand-translated strings, the same way country names come from
// Intl.DisplayNames.
//
// It takes the epoch the server sends (created_unix), never the created_at
// string: that string is formatted in the DB session timezone, so parsing it as
// local browser time is wrong by the offset between them, which for a "3 hours
// ago" label is hours. The epoch is the true instant whatever the timezone.
function relativeTime(unix: number, lang: string): string {
  if (!unix) return ''
  const then = unix * 1000
  const seconds = Math.round((then - Date.now()) / 1000)
  const abs = Math.abs(seconds)
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' })
  if (abs < 60) return rtf.format(Math.round(seconds), 'second')
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour')
  if (abs < 604800) return rtf.format(Math.round(seconds / 86400), 'day')
  return new Date(then).toLocaleDateString(lang)
}

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

  // The sentence is built in the reader's language from the key the server sent.
  // The English falls back for a key this build does not know, which is what a
  // panel running against a newer server sees.
  function describe(item: Notification): string {
    if (!item.key) return item.message
    let params: Record<string, unknown>
    try {
      params = item.params ? (JSON.parse(item.params) as Record<string, unknown>) : {}
    } catch {
      // Measured: translating with an empty parameter set renders the template's
      // own placeholders, "Malware found on ?domain: ?count file(s)". A sentence
      // with holes in it is worse than the server's English, which at least says
      // what happened.
      return item.message
    }
    return t(`notify.${item.key}`, { ...params, defaultValue: item.message })
  }

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
        <div className="absolute right-0 mt-2 w-[22rem] max-w-[calc(100vw-1.5rem)] max-h-96 overflow-y-auto rounded-xl border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-900 z-50">
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
                        <span className={`block text-xs truncate ${tone(item.level)} ${item.read ? 'font-medium' : 'font-semibold'}`}>
                          {item.domain || t('notify.serverWide')}
                        </span>
                        {!item.read && <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-500" />}
                      </span>
                      <span className="mt-0.5 block text-xs text-slate-700 dark:text-slate-300 line-clamp-2">{describe(item)}</span>
                      <span className="mt-1 block text-[10px] text-slate-400 dark:text-slate-500">{relativeTime(item.created_unix, i18n.language)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
