import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { countryFlag, countryNamer, sortByName } from '@/lib/countries'

type Props = {
  /** Every code the downloaded database carries. Nothing else can be picked. */
  available: string[]
  selected: string[]
  disabled?: boolean
  /** Refuses further selection once reached; already selected codes stay removable. */
  max?: number
  onChange: (codes: string[]) => void
  labels: { search: string; none: string; selected: string; limit: string }
}

/**
 * Picks countries by their name in the reader's language.
 *
 * The list is what the DATABASE carries, never a hardcoded set: a code the
 * database does not know would be stored, render no ranges and block nobody,
 * which is exactly the silent hole the backend refuses on the write path.
 */
export default function CountryPicker({ available, selected, disabled, max, onChange, labels }: Props) {
  const { i18n } = useTranslation()
  const [query, setQuery] = useState('')

  const nameOf = useMemo(() => countryNamer(i18n.language), [i18n.language])
  const sorted = useMemo(() => sortByName(available, nameOf), [available, nameOf])
  const chosen = useMemo(() => new Set(selected), [selected])

  const visible = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase(i18n.language)
    if (!needle) return sorted
    return sorted.filter(code =>
      code.toLowerCase().includes(needle) || nameOf(code).toLocaleLowerCase(i18n.language).includes(needle))
  }, [sorted, query, nameOf, i18n.language])

  const full = max !== undefined && selected.length >= max

  function toggle(code: string) {
    if (chosen.has(code)) {
      onChange(selected.filter(item => item !== code))
      return
    }
    if (full) return
    onChange([...selected, code])
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <input value={query} onChange={event => setQuery(event.target.value)} placeholder={labels.search} disabled={disabled}
          className="flex-1 min-w-[200px] px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-50" />
        <span className="text-[11px] text-slate-400">{labels.selected}</span>
      </div>

      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-2">
          {sortByName(selected, nameOf).map(code => (
            <button key={code} type="button" onClick={() => toggle(code)} disabled={disabled}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-600 disabled:opacity-50">
              <span aria-hidden="true">{countryFlag(code)}</span>{nameOf(code)}<span className="text-slate-400">×</span>
            </button>
          ))}
        </div>
      )}

      {full && <p className="text-[11px] text-amber-600 dark:text-amber-400 mb-2">{labels.limit}</p>}

      <div className="max-h-56 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg">
        {visible.length === 0 ? (
          <p className="px-3 py-6 text-center text-sm text-slate-400">{labels.none}</p>
        ) : (
          <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
            {visible.map(code => {
              const active = chosen.has(code)
              return (
                <li key={code}>
                  <label className={`flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/40 ${disabled || (full && !active) ? 'opacity-50 cursor-not-allowed' : ''}`}>
                    <input type="checkbox" checked={active} disabled={disabled || (full && !active)} onChange={() => toggle(code)} />
                    <span aria-hidden="true">{countryFlag(code)}</span>
                    <span className="truncate text-slate-700 dark:text-slate-200">{nameOf(code)}</span>
                    <span className="ml-auto font-mono text-[11px] text-slate-400">{code}</span>
                  </label>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}
