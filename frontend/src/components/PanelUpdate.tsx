import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'

type UpdateStatus = {
  tool_available: boolean
  running: boolean
  status: string
}

type UpdateLog = {
  log: string
  running: boolean
  status: string
}

type VersionStatus = {
  enabled: boolean
  current: string
  latest: string
  update_available: boolean
  announcement: string
  critical: boolean
  release_date: string
  build_date: string
  last_check?: string
  error: string
}

function formatCheckTime(value: string | undefined, notCheckedLabel: string) {
  if (!value) return notCheckedLabel
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

/**
 * Derives the final outcome from the update log, or null while it is still
 * undecided.
 *
 * The `running` flag alone is not enough: the update restarts the panel, so the
 * poll that would have reported the transition can be lost, leaving the spinner
 * up forever. Both markers below come from assets/ops/servika-update and are
 * mutually exclusive branches of its health check. The script disables colour
 * when stdout is not a terminal, and the log is a redirected file, so it is
 * plain text.
 *
 * A killed update (machine reboot, OOM) leaves neither marker and stays null on
 * purpose: reporting success for a process that never finished would be worse
 * than showing nothing.
 */
function finishedOutcome(log: string): 'done' | 'failed' | null {
  if (log.includes('Update complete')) return 'done'
  if (log.includes('✗')) return 'failed' // the script's die() prefix
  return null
}

// VersionBadges marks a critical release, or an ordinary one when the release is
// not critical, beside the title.
function VersionBadges({ version }: { version: VersionStatus | null }) {
  const { t } = useTranslation('PanelUpdate')
  return (
    <>
      {version?.critical && <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">{t('badges.critical')}</span>}
      {version?.update_available && !version.critical && <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-medium bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300">{t('badges.updateAvailable')}</span>}
    </>
  )
}

// VersionGrid holds the four version facts of the info box.
function VersionGrid({ version }: { version: VersionStatus }) {
  const { t } = useTranslation('PanelUpdate')
  return (
    <div className="grid gap-2 sm:grid-cols-4">
      <div><span className="block text-slate-400 dark:text-slate-500">{t('labels.current')}</span><span className="font-medium text-slate-900 dark:text-slate-100">{version.current || t('unknown')}</span></div>
      <div><span className="block text-slate-400 dark:text-slate-500">{t('labels.latest')}</span><span className="font-medium text-slate-900 dark:text-slate-100">{version.latest || t('unknown')}</span></div>
      <div><span className="block text-slate-400 dark:text-slate-500">{t('labels.buildDate')}</span><span className="font-medium text-slate-900 dark:text-slate-100">{version.build_date || t('unknown')}</span></div>
      <div><span className="block text-slate-400 dark:text-slate-500">{t('labels.lastCheck')}</span><span className="font-medium text-slate-900 dark:text-slate-100">{formatCheckTime(version.last_check, t('notCheckedYet'))}</span></div>
    </div>
  )
}

// VersionPanel is the info box below the description: the version facts, the
// announcement, and why a check produced nothing.
function VersionPanel({ version }: { version: VersionStatus | null }) {
  const { t } = useTranslation('PanelUpdate')
  if (!version) return null
  return (
    <div className="mt-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-950/20 p-3 text-xs text-slate-600 dark:text-slate-300">
      <VersionGrid version={version} />
      {version.announcement && (
        <div className={`mt-3 rounded-lg px-3 py-2 ${version.critical ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300' : 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300'}`}>
          {version.announcement}
          {version.release_date && <span className="ml-1 opacity-80">({version.release_date})</span>}
        </div>
      )}
      {version.error && <div className="mt-2 text-slate-500 dark:text-slate-400">{t('lastCheckFailed', { error: version.error })}</div>}
      {!version.enabled && <div className="mt-2 text-slate-500 dark:text-slate-400">{t('checksDisabled')}</div>}
    </div>
  )
}

// RunState reports the update while it runs and its outcome once it settles.
function RunState({ running, outcome }: { running: boolean; outcome: 'done' | 'failed' | null }) {
  const { t } = useTranslation('PanelUpdate')
  if (running) {
    return (
      <div className="mt-2 inline-flex items-center gap-2 text-xs text-emerald-700 dark:text-emerald-300">
        <span className="w-3 h-3 rounded-full border-2 border-emerald-500 border-t-transparent animate-spin" />
        {t('running')}
      </div>
    )
  }
  if (outcome === 'done') {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-2 px-3 py-2 rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-800 dark:text-emerald-200 text-xs">
        <span className="font-semibold">{t('outcome.successTitle')}</span>
        <span className="opacity-80">{t('outcome.successHint')}</span>
        <button onClick={() => window.location.reload()}
          className="ml-auto text-xs px-2.5 py-1 rounded-md bg-emerald-600 text-white hover:bg-emerald-700 transition font-medium">
          {t('outcome.reload')}
        </button>
      </div>
    )
  }
  if (outcome === 'failed') {
    return (
      <div className="mt-2 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-xs">
        <span className="font-semibold">{t('outcome.failedTitle')}</span> {t('outcome.failedHint')}
      </div>
    )
  }
  return null
}

// ActionRow is the button row, which asks for a confirmation before it starts.
function ActionRow({ confirmation, running, starting, refreshing, onAsk, onCancel, onStart, onRefresh }: {
  confirmation: boolean
  running: boolean
  starting: boolean
  refreshing: boolean
  onAsk: () => void
  onCancel: () => void
  onStart: () => void
  onRefresh: () => void
}) {
  const { t } = useTranslation('PanelUpdate')
  return (
    <div className="mt-3 flex flex-col sm:flex-row sm:items-center gap-2">
      {!confirmation ? (
        <>
          <button onClick={onAsk} disabled={running || starting}
            className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:opacity-90 transition font-medium disabled:opacity-40 disabled:cursor-not-allowed">
            {t('checkAndInstall')}
          </button>
          <button onClick={onRefresh} disabled={refreshing || running}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition disabled:opacity-40 disabled:cursor-not-allowed">
            {refreshing ? t('checking') : t('refreshStatus')}
          </button>
        </>
      ) : (
        <>
          <span className="text-xs text-slate-600 dark:text-slate-300">{t('confirmPrompt')}</span>
          <button onClick={onStart} disabled={starting}
            className="text-xs px-3 py-1.5 rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition font-medium disabled:opacity-40">
            {starting ? t('starting') : t('confirmYes')}
          </button>
          <button onClick={onCancel} className="text-xs px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition">
            {t('cancel')}
          </button>
        </>
      )}
    </div>
  )
}

/** Displays update status, starts an update, and follows its persistent log. */
export default function PanelUpdate() {
  const { t, i18n } = useTranslation('PanelUpdate')
  const [status, setStatus] = useState<UpdateStatus | null>(null)
  const [version, setVersion] = useState<VersionStatus | null>(null)
  const [log, setLog] = useState('')
  const [running, setRunning] = useState(false)
  const [outcome, setOutcome] = useState<'done' | 'failed' | null>(null)
  const [starting, setStarting] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [confirmation, setConfirmation] = useState(false)
  const logRef = useRef<HTMLPreElement>(null)

  // These three write only from promise callbacks. The mount effect calls them,
  // and a write in an awaited body still counts as that effect's own
  // continuation, which would force an extra render pass on every visit.
  const loadStatus = useCallback(() => {
    return api.get<UpdateStatus>('/system/update')
      .then(response => {
        setStatus(response.data)
        setRunning(response.data.running)
      })
      .catch(() => {
        // The API can be temporarily unavailable while the panel restarts.
      })
  }, [])

  // The announcement is published per language in the manifest, so the server needs
  // the language the panel is actually displaying to pick the right translation.
  // i18n.language is that value; users.pref_lang is only its persisted seed. Keeping
  // it in the dependency array re-fetches the notice when the language switches, so
  // the text follows the switcher without a reload.
  const loadVersion = useCallback(() => {
    return api.get<VersionStatus>('/system/version-check', { params: { lang: i18n.language } })
      .then(response => setVersion(response.data))
      .catch(() => {
        // Version checks are informational and must not block updates.
      })
  }, [i18n.language])

  // Reads the log, and stops the spinner as soon as EITHER the server reports
  // the update as finished OR the log itself says so. The second condition is
  // what survives a lost transition across the panel restart.
  //
  // announce is set only by the poll, so the banner reports an update that just
  // concluded in this session. At mount the log is displayed but not announced;
  // otherwise the result of an update run days ago would greet the user forever.
  const loadLog = useCallback((announce: boolean) => {
    return api.get<UpdateLog>('/system/update/log').then(response => {
      setLog(response.data.log)
      const settled = finishedOutcome(response.data.log)
      if (!response.data.running || settled) {
        setRunning(false)
        if (announce && settled) {
          setOutcome(settled)
          loadVersion()
        }
      }
    })
  }, [loadVersion])

  useEffect(() => {
    loadStatus()
    loadLog(false).catch(() => {
      // No update has ever run, or the panel is restarting.
    })
    loadVersion()
  }, [loadStatus, loadLog, loadVersion])

  useEffect(() => {
    if (!running) return
    let stopped = false
    const poll = async () => {
      try {
        if (stopped) return
        await loadLog(true)
      } catch {
        // Polling continues across the expected panel restart.
      }
    }
    const interval = window.setInterval(poll, 2000)
    poll()
    return () => {
      stopped = true
      window.clearInterval(interval)
    }
  }, [running, loadLog])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [log])

  async function refreshVersion() {
    setError(null)
    setRefreshing(true)
    try {
      const response = await api.post<VersionStatus>('/system/version-check/refresh', null, { params: { lang: i18n.language } })
      setVersion(response.data)
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.refresh')))
    } finally {
      setRefreshing(false)
    }
  }

  async function start() {
    setError(null)
    setStarting(true)
    setConfirmation(false)
    setOutcome(null)
    try {
      await api.post('/system/update/start')
      setLog(t('logStarted'))
      setRunning(true)
    } catch (caughtError) {
      setError(apiError(caughtError, t('errors.start')))
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="mb-6 p-4 border rounded-2xl bg-emerald-50 dark:bg-emerald-900/15 border-emerald-200 dark:border-emerald-800/50">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('title')}</span>
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-medium bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">{t('badges.server')}</span>
            <VersionBadges version={version} />
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">
            {t('description')}
            {status && !status.tool_available && t('toolMissing')}
          </div>

          <VersionPanel version={version} />

          {error && <div className="mt-2 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-xs">{error}</div>}

          <RunState running={running} outcome={outcome} />

          {log && (
            <pre ref={logRef} className="mt-2 text-[11px] font-mono bg-slate-900 text-slate-300 rounded-lg p-2.5 max-h-56 overflow-auto whitespace-pre-wrap leading-relaxed">{log}</pre>
          )}

          <ActionRow
            confirmation={confirmation} running={running} starting={starting} refreshing={refreshing}
            onAsk={() => setConfirmation(true)} onCancel={() => setConfirmation(false)}
            onStart={start} onRefresh={refreshVersion}
          />
        </div>
      </div>
    </div>
  )
}
