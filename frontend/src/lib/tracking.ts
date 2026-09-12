// Ties the two client-side recorders to the router.
//
// One hook, mounted once by the dashboard layout. It reports a page_view on
// every route change, and starts or stops the session recorder as the answer to
// "may this be recorded" changes.

import { useEffect, useState } from 'react'
import { useLocation } from 'react-router'
import { api } from './api'
import { report, startReporting, stopReporting } from './uievents'
import { recordable, startRecording, stopRecordingSession } from './replay'

// The event the consent banner fires after an account agrees. Without it the
// recorder would only start on the next page load.
export const consentChangedEvent = 'servika:replay-consent'

type consentAnswer = { enabled: boolean; consented: boolean }

export function useInterfaceTracking() {
  const location = useLocation()
  const [allowed, setAllowed] = useState(false)

  useEffect(() => {
    startReporting()
    return stopReporting
  }, [])

  // A route change in a single-page application asks the server for nothing, so
  // this report is the only record that the screen was opened.
  useEffect(() => {
    report('page_view', location.pathname)
  }, [location.pathname])

  useEffect(() => {
    let live = true
    const read = () => {
      api.get<consentAnswer>('/me/replay-consent')
        .then(response => { if (live) setAllowed(response.data.enabled && response.data.consented) })
        .catch(() => { if (live) setAllowed(false) })
    }
    read()
    window.addEventListener(consentChangedEvent, read)
    return () => {
      live = false
      window.removeEventListener(consentChangedEvent, read)
    }
  }, [])

  useEffect(() => {
    if (allowed && recordable(location.pathname)) {
      void startRecording()
    } else {
      stopRecordingSession()
    }
  }, [allowed, location.pathname])
}
