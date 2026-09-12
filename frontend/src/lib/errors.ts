import { useCallback, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { AxiosError } from 'axios'
import { apiError } from '@/lib/api'

// A background request that fails silently leaves the screen showing an empty
// list, and an empty list reads as "there is nothing here" rather than "this
// could not be loaded". That renders a failure as if it were a fact. Every
// caller that has nowhere to put an inline error routes through here instead,
// so the user sees that something did not load and the console keeps the full
// object for diagnosis.

export type ReportedError = {
  id: number
  /** Already-translated label naming what failed to load. */
  context: string
  /** Diagnostic text from the API. English, because the API is English. */
  detail: string
}

/** How long one entry stays on screen. */
const ERROR_TTL_MS = 9_000
/** The same context is not re-announced within this window. */
const THROTTLE_MS = 30_000
/** A burst of failures must not bury the page under a wall of banners. */
const MAX_ENTRIES = 4

type Listener = (entries: ReportedError[]) => void

let entries: ReportedError[] = []
let nextId = 1
const listeners = new Set<Listener>()
const lastReportedAt = new Map<string, number>()

function emit() {
  for (const listener of listeners) listener(entries)
}

export function subscribeErrors(listener: Listener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function getReportedErrors(): ReportedError[] {
  return entries
}

export function dismissError(id: number) {
  const next = entries.filter(entry => entry.id !== id)
  if (next.length === entries.length) return
  entries = next
  emit()
}

/**
 * Decides whether a rejection is worth telling the user about.
 *
 * A 401 is not: the response interceptor already logs the session out, and a
 * banner would flash on the way to the login screen. A cancelled request is not
 * either: the caller abandoned it on purpose, usually by navigating away.
 */
function isReportable(err: unknown): boolean {
  const error = err as AxiosError
  if (error?.response?.status === 401) return false
  if (error?.code === 'ERR_CANCELED') return false
  return true
}

/**
 * Announces a failed request under an already-translated context label.
 *
 * The full error object always reaches the console, whether or not the banner
 * is throttled, so nothing is lost to the rate limit.
 */
function reportError(context: string, err: unknown) {
  // The label is a separate argument, never part of the format string: a `%s`
  // inside a translated label would otherwise consume `err` and hide it.
  console.error('[servika]', `${context}:`, err)
  if (!isReportable(err)) return

  const now = Date.now()
  const previous = lastReportedAt.get(context)
  if (previous !== undefined && now - previous < THROTTLE_MS) return
  lastReportedAt.set(context, now)

  const entry: ReportedError = { id: nextId++, context, detail: apiError(err) }
  entries = [...entries, entry].slice(-MAX_ENTRIES)
  emit()

  setTimeout(() => dismissError(entry.id), ERROR_TTL_MS)
}

/**
 * Builds a `.catch` handler for a request whose failure has nowhere else to go.
 *
 * Takes the resolved label rather than a translation key, so the throttle is
 * keyed on the same string the user sees and useReportError stays the only
 * place that knows which namespace the labels live in.
 */
function catchAndReport(context: string): (err: unknown) => void {
  return (err: unknown) => reportError(context, err)
}

/**
 * Returns a factory that turns a context key from the ErrorSurface namespace
 * into a `.catch` handler.
 *
 *   const report = useReportError()
 *   api.get('/plans').then(setPlans).catch(report('plans'))
 *
 * The label is resolved here rather than inside the reporter so the banner
 * speaks the language the user is reading, not the language the module was
 * loaded in.
 */
export function useReportError() {
  const { t } = useTranslation('ErrorSurface')
  // Latest-ref so the returned factory keeps one identity for the component's
  // lifetime. It appears in effect dependency arrays all over the panel, and a
  // new identity on every language change would re-run those effects, refetching
  // data the user did not ask to reload. The label is still read at call time,
  // so the banner speaks the language currently on screen.
  const translate = useRef(t)
  useEffect(() => {
    translate.current = t
  }, [t])
  return useCallback(
    (contextKey: string) => catchAndReport(translate.current(`contexts.${contextKey}`)),
    [],
  )
}
