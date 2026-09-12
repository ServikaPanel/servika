// The session recorder, and the masking contract it runs under.
//
// THE MASKING CONTRACT
//
// Panel screens show database passwords, mail passwords, API keys and customer
// data. The usual rrweb approach is to mark the elements that carry those and
// leave the rest visible. That is fail-open here: the next screen somebody adds
// leaks every secret on it until a reviewer notices the missing mark.
//
// This is the inverse, and it is fail-closed:
//
//   maskTextSelector: '*'   every text node, without exception
//   maskAllInputs: true     every input value
//   blockSelector           canvas and iframe, whose pixels are not text
//
// A recording therefore shows structure, clicks, scrolling and mouse movement,
// and no readable content at all. It answers "what did the user DO", never
// "what was ON the screen". A new screen needs no marking, and there is no such
// thing as an element somebody forgot to mark.
//
// internal/uievents/mask_test.go reads THIS file and fails the build if either
// of the two lines above disappears. Do not restate the contract anywhere else:
// one place to read, one place to break.
//
// rrweb documents blockClass/blockSelector, ignoreClass/ignoreSelector,
// maskTextClass/maskTextSelector, maskAllInputs, maskInputOptions and
// checkoutEveryNth/Nms. maskAllText and the unmask* options are NOT documented,
// so nothing here relies on them.

import { apiBase } from './api'
import { sessionID } from './uievents'

// The screens the recorder must never run on. The replay screen plays another
// account's session, so recording it would store that session a second time,
// and the log screens show rows the recording has no business copying.
const excluded = ['/session-replay', '/request-log', '/app-log']

// A batch is sent every ten seconds, and a full DOM snapshot is taken every
// five minutes so a replay can start in the middle of a long session.
const flushInterval = 10_000
const checkoutEveryNms = 5 * 60 * 1000

type RRWebEvent = unknown

let stopRecording: (() => void) | null = null
let timer: ReturnType<typeof setInterval> | null = null
let pending: RRWebEvent[] = []
let seq = 0

/** Reports whether the recorder may run on this path. */
export function recordable(path: string): boolean {
  return !excluded.some(prefix => path.startsWith(prefix))
}

/**
 * Starts recording. Does nothing when a recording is already running.
 *
 * rrweb is loaded by dynamic import, so the library is downloaded only by a
 * browser that actually records: it never enters the main chunk.
 */
export async function startRecording() {
  if (stopRecording !== null) return
  const { record } = await import('rrweb')
  const stop = record({
    emit(event) { pending.push(event) },
    maskTextSelector: '*',
    maskAllInputs: true,
    blockSelector: 'canvas, iframe, [data-rr-block]',
    checkoutEveryNms,
  })
  if (!stop) return
  stopRecording = stop
  timer = setInterval(() => { void flushBatch() }, flushInterval)
  window.addEventListener('beforeunload', beaconBatch)
}

/** Stops recording and sends what is left. */
export function stopRecordingSession() {
  if (stopRecording === null) return
  stopRecording()
  stopRecording = null
  if (timer !== null) {
    clearInterval(timer)
    timer = null
  }
  window.removeEventListener('beforeunload', beaconBatch)
  beaconBatch()
}

/**
 * Sends one batch.
 *
 * A refused batch stops the recorder rather than being retried: the server
 * refuses when the operator turned the feature off or the account withdrew its
 * consent, and a recorder that kept sending would waste bandwidth for the life
 * of the tab.
 */
async function flushBatch() {
  if (pending.length === 0) return
  const events = pending
  pending = []
  const body = JSON.stringify({
    session_id: sessionID(),
    seq: seq++,
    url: location.href,
    events,
  })
  try {
    const response = await fetch(`${apiBase}/replay`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body,
    })
    if (response.status === 403 || response.status === 413) stopRecordingSession()
  } catch {
    // A network failure is not a refusal. The batch is already dropped; the
    // next one is sent normally.
  }
}

function beaconBatch() {
  if (pending.length === 0) return
  const body = JSON.stringify({
    session_id: sessionID(),
    seq: seq++,
    url: location.href,
    events: pending,
  })
  pending = []
  // A Blob keeps the JSON content type; a bare string would arrive as
  // text/plain and the handler would refuse to parse it.
  navigator.sendBeacon(`${apiBase}/replay`, new Blob([body], { type: 'application/json' }))
}
