// Asks the account, once, whether its session may be recorded.
//
// The recorder never starts without an answer stored on the SERVER, so this
// banner is the only thing that can start one. Declining is remembered in a
// cookie rather than on the server: the server column has two states, consent
// or none, and adding a third to remember a refusal would give the write path a
// second question to keep in step with the first.
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/lib/api'
import { getCookie, setCookie } from '@/lib/cookies'
import { consentChangedEvent } from '@/lib/tracking'
import type { ReplayConsent } from './SessionReplaySetting'

// The refusal is remembered for a year, the same window the panel gives its
// other dismissed notices.
const declinedCookie = 'replay_consent_declined'
const declinedMaxAge = 365 * 24 * 3600

export default function ReplayConsentBanner() {
  const { t } = useTranslation('ReplayConsentBanner')
  const [state, setState] = useState<ReplayConsent | null>(null)
  const [declined, setDeclined] = useState(getCookie(declinedCookie) === '1')
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api.get<ReplayConsent>('/me/replay-consent')
      .then(response => setState(response.data))
      .catch(() => setState(null))
  }, [])

  useEffect(() => { load() }, [load])

  async function accept() {
    setBusy(true)
    try {
      const { data } = await api.put<ReplayConsent>('/me/replay-consent', { accepted: true })
      setState(data)
      // Without this the recorder would only start on the next page load.
      window.dispatchEvent(new Event(consentChangedEvent))
    } finally {
      setBusy(false)
    }
  }

  function decline() {
    setCookie(declinedCookie, '1', declinedMaxAge)
    setDeclined(true)
  }

  if (declined || !state || !state.enabled || state.consented) return null

  return (
    <div className="mx-6 md:mx-8 mt-4 rounded-2xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 px-4 py-3">
      <p className="text-sm font-medium text-amber-900 dark:text-amber-200">{t('title')}</p>
      <p className="mt-1 text-xs text-amber-800 dark:text-amber-300">{t('body')}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={accept}
          disabled={busy}
          className="px-3 py-1.5 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {t('accept')}
        </button>
        <button
          type="button"
          onClick={decline}
          disabled={busy}
          className="px-3 py-1.5 text-sm font-medium rounded-lg border border-amber-300 dark:border-amber-700 text-amber-900 dark:text-amber-200 hover:bg-amber-100 dark:hover:bg-amber-900/40 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {t('decline')}
        </button>
      </div>
    </div>
  )
}
