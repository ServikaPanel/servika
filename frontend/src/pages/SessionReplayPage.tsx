// Session replay — plays back a recorded panel session next to the interface
// events of the same session.
//
// Admin only, and the recorder never runs on this screen: playing another
// account's session on a page that is itself being recorded would store that
// session a second time.
//
// Text in a recording is masked, always. This screen shows what was done, never
// what was on the screen; the timeline beside it is where the words are.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import EmptyState from '@/components/EmptyState'

type Recording = {
  id: number
  session_id: string
  user_id: number
  username: string
  page_url: string
  started_at: string
  updated_at: string
  batches: number
}

type UIEvent = {
  id: number
  ts: string
  event_type: string
  path: string
  event_data: string
}

// rrweb refuses to play fewer than two events, so a recording that never got
// past its first snapshot is reported rather than handed to the player.
const minimumEvents = 2

export default function SessionReplayPage() {
  const { t } = useTranslation('SessionReplayPage')
  const [list, setList] = useState<Recording[]>([])
  const [selected, setSelected] = useState<Recording | null>(null)
  const [timeline, setTimeline] = useState<UIEvent[]>([])
  const [error, setError] = useState('')
  const [playerError, setPlayerError] = useState('')
  const [loading, setLoading] = useState(true)
  const stage = useRef<HTMLDivElement>(null)

  useEffect(() => {
    api.get<Recording[]>('/system/replay-sessions?limit=200')
      .then(response => setList(Array.isArray(response.data) ? response.data : []))
      .catch(cause => setError(apiError(cause, t('errors.load'))))
      .finally(() => setLoading(false))
  }, [t])

  const play = useCallback(async (recording: Recording) => {
    setSelected(recording)
    setPlayerError('')
    setTimeline([])
    const target = stage.current
    if (!target) return
    target.replaceChildren()
    try {
      const [{ data }, player] = await Promise.all([
        api.get<{ events: unknown[] }>(`/system/replay/${recording.id}`),
        loadPlayer(),
      ])
      const events = Array.isArray(data.events) ? data.events : []
      if (events.length < minimumEvents) {
        setPlayerError(t('errors.tooShort'))
        return
      }
      new player({ target, props: { events, width: 960, height: 540, autoPlay: false } })
    } catch (cause) {
      setPlayerError(apiError(cause, t('errors.play')))
    }
    api.get<UIEvent[]>(`/system/ui-events?session_id=${encodeURIComponent(recording.session_id)}&limit=500`)
      .then(response => setTimeline(Array.isArray(response.data) ? response.data : []))
      .catch(() => setTimeline([]))
  }, [t])

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('title') }]} />

      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('subtitle')}</p>
      </div>

      {error && <div className="mb-4 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm">{error}</div>}

      {loading ? (
        <div className="py-16 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : list.length === 0 ? (
        <EmptyState title={t('empty.title')} description={t('empty.description')} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[20rem_minmax(0,1fr)]">
          <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800">
            <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[36rem] overflow-y-auto">
              {list.map(recording => (
                <li key={recording.id}>
                  <button
                    type="button"
                    onClick={() => void play(recording)}
                    className={`w-full text-left px-3 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-900/60 ${selected?.id === recording.id ? 'bg-brand-50 dark:bg-brand-900/20' : 'bg-white dark:bg-slate-950'}`}
                  >
                    <span className="block text-sm text-slate-800 dark:text-slate-200">{recording.username || t('anonymous')}</span>
                    <span className="block font-mono text-xs text-slate-500">{recording.started_at}</span>
                    <span className="block text-xs text-slate-400 truncate">{recording.page_url}</span>
                    <span className="block text-xs text-slate-400">{t('batches', { count: recording.batches })}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="mb-3 text-xs text-slate-500 dark:text-slate-500">{t('maskingNote')}</p>
            {playerError && <div className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm">{playerError}</div>}
            <div ref={stage} className="overflow-auto rounded-xl border border-slate-200 dark:border-slate-800 bg-white p-2" />
            {!selected && <p className="mt-3 text-sm text-slate-400">{t('pickOne')}</p>}
            {timeline.length > 0 && (
              <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                <table className="w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-900/60">
                    <tr>
                      {['time', 'event', 'path', 'data'].map(column => (
                        <th key={column} className="px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {t(`columns.${column}`)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-950">
                    {timeline.map(event => (
                      <tr key={event.id} className="align-top">
                        <td className="px-3 py-2 whitespace-nowrap font-mono text-xs text-slate-500">{event.ts}</td>
                        <td className="px-3 py-2 whitespace-nowrap text-xs text-slate-700 dark:text-slate-300">{event.event_type}</td>
                        <td className="px-3 py-2 font-mono text-xs text-slate-500 break-all">{event.path || '—'}</td>
                        <td className="px-3 py-2 font-mono text-xs text-slate-500 break-all">{event.event_data || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

type PlayerConstructor = new (options: {
  target: HTMLElement
  props: { events: unknown[]; width: number; height: number; autoPlay: boolean }
}) => unknown

/**
 * Loads the player and its stylesheet on first use.
 *
 * Dynamic import for the same reason the recorder uses one: the player is a
 * large dependency that only this screen needs, so it stays out of the chunk
 * every other screen downloads.
 */
async function loadPlayer(): Promise<PlayerConstructor> {
  await import('rrweb-player/dist/style.css')
  const module = await import('rrweb-player')
  return module.default as unknown as PlayerConstructor
}
