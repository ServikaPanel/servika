import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import CountryPicker from '@/components/CountryPicker'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type HotlinkSettings = {
  active: boolean
  allowed: string[]
}

type GeoMode = 'off' | 'allow' | 'deny'

type DatabaseStatus = {
  configured: boolean
  available: boolean
  build_date?: string
  updated_at?: string
  last_error?: string
  countries: string[]
  ipv6: boolean
}

type GeoResponse = {
  mode: GeoMode
  countries: string[]
  database: DatabaseStatus
}

type RateLimitResponse = {
  rps: number
  ladder: number[]
}

// The ceiling the backend enforces. Kept here too so the picker stops offering
// selections the save would refuse, rather than letting the reader find out.
const MAX_COUNTRIES = 40

type IPAccessMode = 'off' | 'block' | 'allow'

type IPRule = {
  id: number
  ip_cidr: string
  created_at: string
}

type IPRulesResponse = {
  mode: IPAccessMode
  rules: IPRule[]
}

const MODE_BADGE: Record<IPAccessMode, string> = {
  off: 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300',
  block: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300',
  allow: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
}

export default function DomainAccessControlPage() {
  const { t } = useTranslation('DomainAccessControlPage')
  const { confirm } = useDialog()
  const { id } = useParams()
  const [hotlink, setHotlink] = useState<HotlinkSettings>({ active: false, allowed: [] })
  const [allowedInput, setAllowedInput] = useState('')
  const [mode, setMode] = useState<IPAccessMode>('off')
  const [rules, setRules] = useState<IPRule[]>([])
  const [newRule, setNewRule] = useState('')
  const [geoMode, setGeoMode] = useState<GeoMode>('off')
  const [geoCountries, setGeoCountries] = useState<string[]>([])
  const [database, setDatabase] = useState<DatabaseStatus | null>(null)
  const [rps, setRps] = useState(0)
  const [ladder, setLadder] = useState<number[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Split so the mount effect never writes state synchronously: fetchSettings
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchSettings = useCallback(() => {
    if (!id) return
    Promise.all([
      api.get<HotlinkSettings>(`/domains/${id}/hotlink`),
      api.get<IPRulesResponse>(`/domains/${id}/ip-rules`),
      api.get<GeoResponse>(`/domains/${id}/geo`),
      api.get<RateLimitResponse>(`/domains/${id}/rate-limit`),
    ]).then(([hotlinkResponse, rulesResponse, geoResponse, rateResponse]) => {
      const nextHotlink = hotlinkResponse.data || { active: false, allowed: [] }
      setHotlink(nextHotlink)
      setAllowedInput((nextHotlink.allowed || []).join('\n'))
      setMode(rulesResponse.data?.mode || 'off')
      setRules(rulesResponse.data?.rules || [])
      setGeoMode(geoResponse.data?.mode || 'off')
      setGeoCountries(geoResponse.data?.countries || [])
      setDatabase(geoResponse.data?.database || null)
      setRps(rateResponse.data?.rps || 0)
      setLadder(rateResponse.data?.ladder || [])
    }).catch(error => setError(apiError(error))).finally(() => setLoading(false))
  }, [id])

  // A refused write carries a stable reason CODE beside its English message, so
  // the reader gets a sentence in their own language instead of the API's.
  const reasonText = useCallback((caught: unknown, fallbackKey: string) => {
    const reason = apiReason(caught)
    if (reason) return t(`reasons.${reason}`)
    return apiError(caught, t(fallbackKey))
  }, [t])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchSettings()
  }, [fetchSettings])

  useEffect(() => { fetchSettings() }, [fetchSettings])

  function parseAllowedDomains() {
    return allowedInput
      .split(/[\n,]+/)
      .map(item => item.trim().toLowerCase())
      .filter(Boolean)
  }

  async function saveHotlink(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setBusy(true)
    try {
      const allowed = parseAllowedDomains()
      await api.put(`/domains/${id}/hotlink`, { active: hotlink.active, allowed })
      setSuccess(t('messages.hotlinkSaved'))
      load()
    } catch (error) { setError(apiError(error, t('errors.hotlinkFailed'))) }
    finally { setBusy(false) }
  }

  async function saveMode(nextMode = mode) {
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.put(`/domains/${id}/ip-rules/mode`, { mode: nextMode })
      setMode(nextMode)
      setSuccess(t('messages.modeSaved'))
      load()
    } catch (error) { setError(apiError(error, t('errors.modeFailed'))) }
    finally { setBusy(false) }
  }

  async function addRule(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.post(`/domains/${id}/ip-rules`, { ip_cidr: newRule.trim() })
      setNewRule('')
      setSuccess(t('messages.ruleAdded'))
      load()
    } catch (error) { setError(apiError(error, t('errors.addFailed'))) }
    finally { setBusy(false) }
  }

  async function saveGeo(nextMode: GeoMode, nextCountries: string[]) {
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.put(`/domains/${id}/geo`, { mode: nextMode, countries: nextCountries })
      setGeoMode(nextMode)
      setGeoCountries(nextCountries)
      setSuccess(t('geo.saved'))
      load()
    } catch (caught) { setError(reasonText(caught, 'geo.failed')) }
    finally { setBusy(false) }
  }

  async function saveRate(nextRps: number) {
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.put(`/domains/${id}/rate-limit`, { rps: nextRps })
      setRps(nextRps)
      setSuccess(t('rate.saved'))
    } catch (caught) { setError(reasonText(caught, 'rate.failed')) }
    finally { setBusy(false) }
  }

  async function deleteRule(rule: IPRule) {
    if (!(await confirm({ message: t('confirmDelete', { ip: rule.ip_cidr }), dangerous: true }))) return
    setError(null); setSuccess(null); setBusy(true)
    try {
      await api.delete(`/domains/${id}/ip-rules/${rule.id}`)
      setSuccess(t('messages.ruleDeleted'))
      load()
    } catch (error) { setError(apiError(error, t('errors.deleteFailed'))) }
    finally { setBusy(false) }
  }

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: t('breadcrumb.accessControl') },
      ]} />
      <div className="flex items-center gap-3 mb-1">
        <span><Icon d={ICON.ban} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${MODE_BADGE[mode]}`}>{t(`modes.${mode}.label`)}</span>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">
        {t('subtitle')}
      </p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {loading ? (
        <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
      ) : (
        <>
          <form onSubmit={saveHotlink} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
            <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
              <div>
                <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('hotlink.title')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('hotlink.description')}</p>
              </div>
              <label className="flex items-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-600 dark:text-slate-300">
                <input type="checkbox" checked={hotlink.active} onChange={event => setHotlink({ ...hotlink, active: event.target.checked })} />
                {t('hotlink.enabled')}
              </label>
            </div>
            <label className="block">
              <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('hotlink.allowedLabel')}</span>
              <textarea value={allowedInput} onChange={event => setAllowedInput(event.target.value)} rows={4} placeholder={'cdn.example.com\n*.partner.example'}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
            <p className="text-[11px] text-slate-400 mt-2">{t('hotlink.hint')}</p>
            <button disabled={busy} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
              {busy ? t('hotlink.saving') : t('hotlink.save')}
            </button>
          </form>

          <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('ipMode.title')}</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(Object.keys(MODE_BADGE) as IPAccessMode[]).map(item => {
                const active = mode === item
                return (
                  <button key={item} type="button" onClick={() => saveMode(item)} disabled={busy}
                    className={`text-left p-4 border rounded-xl transition disabled:opacity-60 ${active ? 'border-slate-900 dark:border-slate-100 bg-slate-50 dark:bg-slate-900/40' : 'border-slate-200 dark:border-slate-700 hover:border-slate-400'}`}>
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t(`modes.${item}.label`)}</span>
                      {active && <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">{t('ipMode.selected')}</span>}
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">{t(`modes.${item}.description`)}</p>
                  </button>
                )
              })}
            </div>
          </div>

          <form onSubmit={addRule} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-5">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('newRule.title')}</h3>
            <div className="flex flex-wrap items-end gap-2">
              <label className="block flex-1 min-w-[260px]">
                <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('newRule.label')}</span>
                <input value={newRule} onChange={event => setNewRule(event.target.value)} required placeholder={t('newRule.placeholder')}
                  className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
              </label>
              <button disabled={busy || !newRule.trim()} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                {busy ? t('newRule.adding') : t('newRule.add')}
              </button>
            </div>
          </form>

          <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('rules.title')}</h3>
            {rules.length === 0 ? (
              <div className="text-center py-6">
                <div className="mb-1"><Icon d={ICON.ban} className="h-6 w-6" /></div>
                <p className="text-sm text-slate-500 dark:text-slate-400">{t('rules.empty')}</p>
              </div>
            ) : (
              <ul className="divide-y divide-slate-100 dark:divide-slate-700/60">
                {rules.map(rule => (
                  <li key={rule.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <div className="font-mono text-sm text-slate-800 dark:text-slate-200">{rule.ip_cidr}</div>
                      <div className="text-[11px] text-slate-400">{t('rules.created', { date: rule.created_at })}</div>
                    </div>
                    <button onClick={() => deleteRule(rule)} disabled={busy} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">{t('rules.delete')}</button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <form onSubmit={event => { event.preventDefault(); saveGeo(geoMode, geoCountries) }}
            className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mt-5">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('geo.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('geo.description')}</p>

            {!database?.available ? (
              <div className="px-3 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200">
                {database?.configured ? t('geo.notDownloaded') : t('geo.notConfigured')}
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                  {(['off', 'allow', 'deny'] as GeoMode[]).map(item => {
                    const active = geoMode === item
                    return (
                      <button key={item} type="button" onClick={() => setGeoMode(item)} disabled={busy}
                        className={`text-left p-4 border rounded-xl transition disabled:opacity-60 ${active ? 'border-slate-900 dark:border-slate-100 bg-slate-50 dark:bg-slate-900/40' : 'border-slate-200 dark:border-slate-700 hover:border-slate-400'}`}>
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t(`geo.modes.${item}.label`)}</span>
                          {active && <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">{t('ipMode.selected')}</span>}
                        </div>
                        <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">{t(`geo.modes.${item}.description`)}</p>
                      </button>
                    )
                  })}
                </div>

                {geoMode !== 'off' && (
                  <CountryPicker
                    available={database.countries}
                    selected={geoCountries}
                    disabled={busy}
                    max={MAX_COUNTRIES}
                    onChange={setGeoCountries}
                    labels={{
                      search: t('geo.search'),
                      none: t('geo.noMatch'),
                      selected: t('geo.selected', { n: geoCountries.length, max: MAX_COUNTRIES }),
                      limit: t('geo.limitReached', { max: MAX_COUNTRIES }),
                    }} />
                )}

                <ul className="mt-3 space-y-1 text-[11px] text-slate-500 dark:text-slate-400 list-disc list-inside">
                  <li>{t('geo.noteAcme')}</li>
                  <li>{t('geo.noteIpRules')}</li>
                  <li>{t('geo.noteCdn')}</li>
                  {!database.ipv6 && <li className="text-amber-600 dark:text-amber-400">{t('geo.noteNoIpv6')}</li>}
                  {database.build_date && <li>{t('geo.buildDate', { date: database.build_date })}</li>}
                </ul>

                <button disabled={busy} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
                  {busy ? t('geo.saving') : t('geo.save')}
                </button>
              </>
            )}
          </form>

          <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mt-5">
            <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('rate.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('rate.description')}</p>
            <div className="flex flex-wrap gap-2">
              {[0, ...ladder].map(value => {
                const active = rps === value
                return (
                  <button key={value} type="button" onClick={() => saveRate(value)} disabled={busy || active}
                    className={`px-3 py-2 text-sm rounded-lg border transition disabled:opacity-60 ${active ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-semibold' : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-slate-400'}`}>
                    {value === 0 ? t('rate.off') : t('rate.perSecond', { rate: value })}
                  </button>
                )
              })}
            </div>
            <ul className="mt-3 space-y-1 text-[11px] text-slate-500 dark:text-slate-400 list-disc list-inside">
              <li>{t('rate.noteStatic')}</li>
              <li>{t('rate.noteBurst', { burst: rps > 0 ? rps * 2 : 0 })}</li>
              <li>{t('rate.noteStatus')}</li>
            </ul>
          </div>

          <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('back')}</Link></div>
        </>
      )}
    </div>
  )
}
