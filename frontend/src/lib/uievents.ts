// Reports what the panel's interface did.
//
// The panel is a single-page application: moving between screens asks the
// server for nothing, so request_logs holds no row for it. These reports are
// the only record that a screen was opened or a button was pressed.
//
// Nothing here blocks a screen. Events are queued in memory and flushed on a
// timer, and a flush that fails is dropped rather than retried: a report about
// something that already happened is not worth a second request.

import { api, apiBase } from './api'
import { getCookie, setCookie } from './cookies'

export type UIEventType =
  | 'page_view'
  | 'search'
  | 'form_submit'
  | 'click_action'
  | 'client_error'

type QueuedEvent = {
  type: UIEventType
  path: string
  data?: Record<string, unknown>
}

// The server refuses a batch longer than 100, so the queue flushes well before
// that. A flush also happens every ten seconds, whichever comes first.
const maxQueue = 25
const flushInterval = 10_000

// The browser session id. It ties the reports of one tab together, and ties
// them to the recording of the same tab.
//
// A session cookie, so it lives as long as the browser window and never longer.
// It carries no identity: the server takes the account from the JWT.
const sessionCookie = 'servika_ui_session'

let queue: QueuedEvent[] = []
let timer: ReturnType<typeof setInterval> | null = null

/** Returns this tab's session id, creating one on the first call. */
export function sessionID(): string {
  const existing = getCookie(sessionCookie)
  if (existing) return existing
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  const fresh = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  setCookie(sessionCookie, fresh)
  return fresh
}

/** Queues one interface event. It never throws and never waits. */
export function report(type: UIEventType, path: string, data?: Record<string, unknown>) {
  queue.push({ type, path, data })
  if (queue.length >= maxQueue) void flush()
}

/** Sends what is queued. A failure drops the batch instead of retrying it. */
async function flush() {
  if (queue.length === 0) return
  const events = queue
  queue = []
  try {
    await api.post('/ui-events', { session_id: sessionID(), events })
  } catch {
    // Deliberately silent. A report that could not be delivered is not worth
    // an error on a screen the operator is using for something else.
  }
}

/**
 * Starts the timer and the page-close flush. Calling it twice does nothing.
 *
 * The close path uses sendBeacon: a fetch started in beforeunload is cancelled
 * with the page, so the last batch of every visit would be lost.
 */
export function startReporting() {
  if (timer !== null) return
  timer = setInterval(() => { void flush() }, flushInterval)
  window.addEventListener('beforeunload', sendBeacon)
}

/** Stops the timer. It exists so a test can leave no interval behind. */
export function stopReporting() {
  if (timer === null) return
  clearInterval(timer)
  timer = null
  window.removeEventListener('beforeunload', sendBeacon)
}

function sendBeacon() {
  if (queue.length === 0) return
  const body = JSON.stringify({ session_id: sessionID(), events: queue })
  queue = []
  // A Blob keeps the JSON content type; a bare string would be sent as
  // text/plain and the handler would refuse to parse it.
  navigator.sendBeacon(`${apiBase}/ui-events`, new Blob([body], { type: 'application/json' }))
}
