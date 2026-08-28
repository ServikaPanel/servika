import type { TFunction } from 'i18next'

// One alert as the server reports it.
//
// `key` and `params` are what the sentence is COMPOSED from, in the reader's
// language. `title` and `message` are the server's English and are the fallback:
// a notification written by something this build does not know about still shows
// as words rather than as a blank row.
export type Notification = {
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

// The text tone of a level. It is the screen's colour, not a policy.
export function tone(level: string): string {
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
export function iconBox(level: string): string {
  return ICON_BOX[level] || ICON_BOX.info
}

// A relative time ("3 hours ago") in the reader's language, from Intl rather than
// twelve hand-translated strings, the same way country names come from
// Intl.DisplayNames.
//
// It takes the epoch the server sends (created_unix), never the created_at
// string: that string is formatted in the DB session timezone, so parsing it as
// local browser time is wrong by the offset between them, which for a "3 hours
// ago" label is hours. The epoch is the true instant whatever the timezone.
export function relativeTime(unix: number, lang: string): string {
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

// The sentence is built in the reader's language from the key the server sent.
// The English falls back for a key this build does not know, which is what a
// panel running against a newer server sees. The key lives in the TopBar
// namespace (`notify.*`), so it is resolved with an explicit ns and works
// whatever the caller's default namespace is.
export function describeNotification(item: Notification, t: TFunction): string {
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
  return t(`notify.${item.key}`, { ns: 'TopBar', ...params, defaultValue: item.message })
}
