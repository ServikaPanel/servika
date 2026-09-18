import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'

// The subdomain's own IP access list. It is separate from the domain's:
// restricting the main site does not restrict an API host, and the two lists
// never merge.

type IPAccessMode = 'off' | 'block' | 'allow'
type IPRule = { id: number; ip_cidr: string; created_at: string }
type IPRulesResponse = { mode?: IPAccessMode; rules?: IPRule[] }

const MODES: IPAccessMode[] = ['off', 'block', 'allow']

function ModeSelector({ mode, busy, onChange }: {
  mode: IPAccessMode; busy: boolean; onChange: (next: IPAccessMode) => void
}) {
  const { t } = useTranslation('SubdomainIPRulesCard')
  return (
    <div className="flex flex-wrap gap-2 mb-3">
      {MODES.map(option => (
        <button key={option} disabled={busy} onClick={() => onChange(option)}
          className={`px-3 py-1.5 rounded-full text-xs font-medium border transition disabled:opacity-50 ${mode === option
            ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 border-transparent'
            : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/50'}`}>
          {t(`modes.${option}`)}
        </button>
      ))}
    </div>
  )
}

function RuleList({ rules, busy, onDelete }: {
  rules: IPRule[]; busy: boolean; onDelete: (rule: IPRule) => void
}) {
  const { t } = useTranslation('SubdomainIPRulesCard')
  if (rules.length === 0) {
    return <p className="text-xs text-slate-400 py-2">{t('empty')}</p>
  }
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/60 mb-3">
      {rules.map(rule => (
        <li key={rule.id} className="flex items-center justify-between gap-3 py-2">
          <span className="font-mono text-sm text-slate-800 dark:text-slate-100">{rule.ip_cidr}</span>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-400">{rule.created_at}</span>
            <button disabled={busy} onClick={() => onDelete(rule)}
              className="text-xs px-3 py-1.5 rounded-full border border-slate-200 dark:border-slate-700 text-slate-500 hover:border-red-300 hover:text-red-600 dark:hover:border-red-800 dark:hover:text-red-400 disabled:opacity-50 transition">
              {t('actions.delete')}
            </button>
          </div>
        </li>
      ))}
    </ul>
  )
}

export default function SubdomainIPRulesCard({ domainID, subdomainID }: {
  domainID: string; subdomainID: string
}) {
  const { t } = useTranslation('SubdomainIPRulesCard')
  const { confirm } = useDialog()
  const [mode, setMode] = useState<IPAccessMode>('off')
  const [rules, setRules] = useState<IPRule[]>([])
  const [newRule, setNewRule] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const base = `/domains/${domainID}/subdomain/${subdomainID}/ip-rules`

  const fetchRules = useCallback(() => {
    api.get<IPRulesResponse>(base)
      .then(response => {
        setMode(response.data?.mode || 'off')
        setRules(response.data?.rules || [])
      })
      // Not [] here: an empty list says "this subdomain restricts nothing",
      // which is the one answer a refused request must never invent.
      .catch(caught => setError(apiError(caught, t('errors.loadFailed'))))
  }, [base, t])

  useEffect(() => { fetchRules() }, [fetchRules])

  // write runs one change and reloads, so the card always shows what the server
  // stored rather than what the click assumed.
  const write = useCallback(async (change: () => Promise<unknown>, fallbackKey: string) => {
    setBusy(true); setError(null)
    try {
      await change()
      fetchRules()
    } catch (caught) { setError(apiError(caught, t(fallbackKey))) }
    finally { setBusy(false) }
  }, [fetchRules, t])

  const changeMode = (next: IPAccessMode) =>
    write(() => api.put(`${base}/mode`, { mode: next }), 'errors.modeFailed')

  async function addRule(event: React.SubmitEvent) {
    event.preventDefault()
    const value = newRule.trim()
    if (!value) return
    await write(() => api.post(base, { ip_cidr: value }), 'errors.addFailed')
    setNewRule('')
  }

  async function deleteRule(rule: IPRule) {
    if (!(await confirm({ message: t('confirm.delete', { rule: rule.ip_cidr }), dangerous: true }))) return
    await write(() => api.delete(`${base}/${rule.id}`), 'errors.deleteFailed')
  }

  return (
    <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
      <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('title')}</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('note')}</p>
      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}

      <ModeSelector mode={mode} busy={busy} onChange={changeMode} />
      {mode !== 'off' && <RuleList rules={rules} busy={busy} onDelete={deleteRule} />}

      <form onSubmit={addRule} className="flex flex-wrap items-end gap-2">
        <label className="block">
          <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('addLabel')}</span>
          <input value={newRule} onChange={event => setNewRule(event.target.value)}
            placeholder="203.0.113.7"
            className="mt-1 w-56 px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
        </label>
        <button type="submit" disabled={busy || !newRule.trim()}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
          {t('actions.add')}
        </button>
      </form>
    </div>
  )
}
