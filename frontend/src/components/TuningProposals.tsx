import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

type Proposal = {
  id: string
  service: string
  param: string
  current: string
  proposed: string
  rationale: string
  file: string
  effect: string
  group: string
  increase_only: boolean
}

type Change = {
  id: number
  service: string
  param: string
  target_path: string
  old_value: string
  new_value: string
  reverted: boolean
  created_at: string
  backup_present: boolean
}

type ProposalsResponse = {
  memory_mb: number
  cpus: number
  proposals: Proposal[]
  unreadable: string[]
}

/*
 * The parameter-by-parameter half of server tuning.
 *
 * Two rules from the backend are visible here and must stay visible. A
 * parameter that belongs to a group can only be approved WITH its group, so
 * ticking one ticks them all: php-fpm refuses a pool whose pm.* values
 * disagree, and it refuses at the next start rather than at the write, so a
 * screen that allowed one would report success on a service that never comes
 * back. And a refusal arrives as a reason CODE, never as a sentence, because
 * this screen writes the sentence in twelve languages.
 */
export default function TuningProposals() {
  const { t } = useTranslation('Tuning')
  const dialog = useDialog()

  const [data, setData] = useState<ProposalsResponse | null>(null)
  const [changes, setChanges] = useState<Change[]>([])
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [loadError, setLoadError] = useState('')

  // Nothing here sets state SYNCHRONOUSLY, including the error reset: this runs
  // from a mount effect, and a synchronous setState there is what
  // react-hooks/set-state-in-effect refuses. Every settle goes through a
  // promise callback instead.
  const load = useCallback(() => {
    return Promise.all([
      api.get<ProposalsResponse>('/system/optimize/proposals'),
      api.get<{ changes: Change[] }>('/system/optimize/history'),
    ])
      .then(([proposals, history]) => {
        setLoadError('')
        setData(proposals.data)
        setChanges(history.data.changes ?? [])
        setChosen(new Set())
      })
      .catch((err) => setLoadError(apiError(err, t('error.load'))))
  }, [t])

  useEffect(() => {
    void load()
  }, [load])

  // Ticking one member of a group ticks the whole group, because the backend
  // applies them together and a half-approved group is a configuration the
  // service refuses.
  const groupOf = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const proposal of data?.proposals ?? []) {
      if (!proposal.group) continue
      map.set(proposal.group, [...(map.get(proposal.group) ?? []), proposal.id])
    }
    return map
  }, [data])

  const toggle = (proposal: Proposal) => {
    const ids = proposal.group ? (groupOf.get(proposal.group) ?? [proposal.id]) : [proposal.id]
    setChosen((previous) => {
      const next = new Set(previous)
      const turningOn = !previous.has(proposal.id)
      for (const id of ids) {
        if (turningOn) next.add(id)
        else next.delete(id)
      }
      return next
    })
  }

  // The API answers English because the API is English; the reason CODE is what
  // this maps into the reader's own language. Falling back to the message is a
  // last resort, not the normal path.
  const reasonText = (err: unknown) => {
    const reason = apiReason(err)
    if (reason) {
      const translated = t(`reason.${reason}`, { defaultValue: '' })
      if (translated) return translated
    }
    return apiError(err, t('error.apply'))
  }

  const apply = async () => {
    if (chosen.size === 0) return
    const ids = [...chosen]
    const restarts = (data?.proposals ?? []).filter(
      (proposal) => ids.includes(proposal.id) && proposal.effect === 'restart',
    )
    const confirmed = await dialog.confirm({
      title: t('apply.confirmTitle'),
      message: restarts.length > 0 ? t('apply.confirmRestart') : t('apply.confirmBody'),
      confirmLabel: t('apply.confirmAction'),
    })
    if (!confirmed) return

    setBusy(true)
    try {
      await api.post('/system/optimize/apply', { ids })
      await load()
      await dialog.notify({ title: t('apply.doneTitle'), message: t('apply.doneBody') })
    } catch (err) {
      await dialog.notify({ title: t('apply.failedTitle'), message: reasonText(err), tone: 'error' })
      await load()
    } finally {
      setBusy(false)
    }
  }

  const revert = async (change: Change) => {
    const confirmed = await dialog.confirm({
      title: t('revert.confirmTitle'),
      message: t('revert.confirmBody', { param: change.param, file: change.target_path }),
      confirmLabel: t('revert.confirmAction'),
      dangerous: true,
    })
    if (!confirmed) return

    setBusy(true)
    try {
      await api.post(`/system/optimize/history/${change.id}/revert`)
      await load()
    } catch (err) {
      await dialog.notify({ title: t('revert.failedTitle'), message: reasonText(err), tone: 'error' })
      await load()
    } finally {
      setBusy(false)
    }
  }

  const proposals = data?.proposals ?? []

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('proposals.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('proposals.description')}</p>

        {data && (
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {t('proposals.measured')}: {data.memory_mb} MB / {data.cpus}
          </p>
        )}

        {loadError && (
          <p className="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
            {loadError}
          </p>
        )}

        {/* A reading that failed is named. A screen that showed an empty list
            without saying so would report a tuned server, which is the one
            answer this must never give by accident. */}
        {(data?.unreadable ?? []).length > 0 && (
          <div className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-200">
            <p className="font-medium">{t('proposals.unreadable')}</p>
            <ul className="mt-1 list-disc pl-5">
              {(data?.unreadable ?? []).map((note) => <li key={note}>{note}</li>)}
            </ul>
          </div>
        )}

        {data && proposals.length === 0 && !loadError && (
          <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">{t('proposals.none')}</p>
        )}

        {proposals.length > 0 && (
          <>
            <div className="mt-4 overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  <tr>
                    <th className="w-10 py-2" />
                    <th className="py-2 pr-4">{t('table.parameter')}</th>
                    <th className="py-2 pr-4">{t('table.current')}</th>
                    <th className="py-2 pr-4">{t('table.proposed')}</th>
                    <th className="py-2 pr-4">{t('table.effect')}</th>
                    <th className="py-2">{t('table.why')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                  {proposals.map((proposal) => (
                    <tr key={proposal.id}>
                      <td className="py-2 align-top">
                        <input
                          type="checkbox"
                          className="h-4 w-4"
                          checked={chosen.has(proposal.id)}
                          onChange={() => toggle(proposal)}
                          aria-label={proposal.id}
                        />
                      </td>
                      <td className="py-2 pr-4 align-top">
                        <div className="font-medium text-slate-900 dark:text-slate-100">{proposal.param}</div>
                        <div className="text-xs text-slate-500 dark:text-slate-400">{proposal.service}</div>
                        <div className="text-xs text-slate-400 dark:text-slate-500">{proposal.file}</div>
                        {proposal.group && (
                          <div className="mt-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-700 dark:text-slate-300">
                            {t('table.appliedTogether')}
                          </div>
                        )}
                      </td>
                      <td className="py-2 pr-4 align-top font-mono text-xs text-slate-600 dark:text-slate-300">
                        {proposal.current || t('table.notSet')}
                      </td>
                      <td className="py-2 pr-4 align-top font-mono text-xs text-slate-900 dark:text-slate-100">
                        {proposal.proposed}
                      </td>
                      <td className="py-2 pr-4 align-top text-xs text-slate-600 dark:text-slate-300">
                        {t(`effect.${proposal.effect}`)}
                      </td>
                      <td className="py-2 align-top text-xs text-slate-600 dark:text-slate-300">{proposal.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <button
              type="button"
              onClick={() => void apply()}
              disabled={busy || chosen.size === 0}
              className="mt-4 rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {t('apply.button')}: {chosen.size}
            </button>
          </>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('history.title')}</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('history.description')}</p>

        {changes.length === 0 ? (
          <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">{t('history.none')}</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                <tr>
                  <th className="py-2 pr-4">{t('table.parameter')}</th>
                  <th className="py-2 pr-4">{t('history.from')}</th>
                  <th className="py-2 pr-4">{t('history.to')}</th>
                  <th className="py-2 pr-4">{t('history.when')}</th>
                  <th className="py-2">{t('history.action')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                {changes.map((change) => (
                  <tr key={change.id}>
                    <td className="py-2 pr-4 align-top">
                      <div className="font-medium text-slate-900 dark:text-slate-100">{change.param}</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">{change.service}</div>
                    </td>
                    <td className="py-2 pr-4 align-top font-mono text-xs text-slate-600 dark:text-slate-300">
                      {change.old_value || t('table.notSet')}
                    </td>
                    <td className="py-2 pr-4 align-top font-mono text-xs text-slate-600 dark:text-slate-300">
                      {change.new_value}
                    </td>
                    <td className="py-2 pr-4 align-top text-xs text-slate-500 dark:text-slate-400">
                      {new Date(change.created_at).toLocaleString()}
                    </td>
                    <td className="py-2 align-top">
                      {change.reverted ? (
                        <span className="text-xs text-slate-500 dark:text-slate-400">{t('history.reverted')}</span>
                      ) : change.backup_present ? (
                        <button
                          type="button"
                          onClick={() => void revert(change)}
                          disabled={busy}
                          className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200"
                        >
                          {t('history.revert')}
                        </button>
                      ) : (
                        <span className="text-xs text-amber-700 dark:text-amber-300">{t('history.backupGone')}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
