// Session replay: the server-wide switch and the account's own consent.
//
// Both live in one card because they answer the same question from two sides.
// The switch is admin only and decides whether ANY browser may record; the
// consent is the account's own and decides whether THIS browser may. A
// recording only happens when both say yes, and the server asks both again on
// every batch.
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import { consentChangedEvent } from '@/lib/tracking'
import { useAuth } from '@/store/auth'

export type ReplayConsent = {
  enabled: boolean
  consented: boolean
  at: string
}

export default function SessionReplaySetting() {
  const { t } = useTranslation('SessionReplaySetting')
  const { confirm } = useDialog()
  const role = useAuth(state => state.username?.role)
  const [state, setState] = useState<ReplayConsent | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const isAdmin = role === 'admin'

  // One read answers both halves: the consent endpoint reports the switch as
  // well, because a browser that only knew its own consent would keep asking
  // for one on a panel where recording is off.
  const load = useCallback(() => {
    api.get<ReplayConsent>('/me/replay-consent')
      .then(response => setState(response.data))
      .catch(cause => setError(apiError(cause, t('errors.load'))))
  }, [t])

  useEffect(() => { load() }, [load])

  async function run(action: () => Promise<void>, done: string) {
    setError('')
    setMessage('')
    setBusy(true)
    try {
      await action()
      setMessage(done)
      // The recorder decides from the same two answers, so it is told rather
      // than left to notice on the next page load.
      window.dispatchEvent(new Event(consentChangedEvent))
    } catch (cause) {
      setError(apiError(cause, t('errors.save')))
    } finally {
      setBusy(false)
    }
  }

  function toggleSwitch(next: boolean) {
    return run(async () => {
      await api.put('/system/session-replay', { enabled: next })
      const { data } = await api.get<ReplayConsent>('/me/replay-consent')
      setState(data)
    }, next ? t('messages.switchOn') : t('messages.switchOff'))
  }

  function setConsent(next: boolean) {
    return run(async () => {
      const { data } = await api.put<ReplayConsent>('/me/replay-consent', { accepted: next })
      setState(data)
    }, next ? t('messages.consentGiven') : t('messages.consentWithdrawn'))
  }

  async function forget() {
    const ok = await confirm({
      title: t('forget.confirmTitle'),
      message: t('forget.confirm'),
      confirmLabel: t('forget.action'),
      dangerous: true,
    })
    if (!ok) return
    await run(async () => { await api.delete('/me/replay-data') }, t('messages.forgotten'))
  }

  if (!state) return null

  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/></svg>
        </div>
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h2>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{t('description')}</p>
        </div>
      </div>

      {error && <div className="text-sm px-3 py-2 rounded-lg border bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 mb-3">{error}</div>}
      {message && <div className="text-sm px-3 py-2 rounded-lg border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 mb-3">{message}</div>}

      {isAdmin && (
        <label className="flex cursor-pointer items-start gap-2 mb-4">
          <input
            type="checkbox"
            checked={state.enabled}
            disabled={busy}
            onChange={event => toggleSwitch(event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
          />
          <span>
            <span className="block text-sm font-medium text-slate-900 dark:text-slate-100">{t('switch.label')}</span>
            <span className="block text-xs text-slate-500 dark:text-slate-500">{t('switch.hint')}</span>
          </span>
        </label>
      )}

      <p className="text-sm text-slate-700 dark:text-slate-300">{t('masking')}</p>

      {state.enabled ? (
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <span className="text-sm text-slate-700 dark:text-slate-300">
            {state.consented ? t('consent.given', { at: state.at }) : t('consent.missing')}
          </span>
          <button
            type="button"
            onClick={() => setConsent(!state.consented)}
            disabled={busy}
            className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {state.consented ? t('consent.withdraw') : t('consent.accept')}
          </button>
          <button
            type="button"
            onClick={forget}
            disabled={busy}
            className="px-4 py-2 text-sm font-medium rounded-lg border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {t('forget.action')}
          </button>
        </div>
      ) : (
        <p className="mt-4 text-xs text-slate-500 dark:text-slate-500">{t('offHint')}</p>
      )}
    </section>
  )
}
