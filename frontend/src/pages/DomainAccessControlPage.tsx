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

const FIELD_CLASS = 'mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none'
const CARD_CLASS = 'bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4'
const PRIMARY_BUTTON_CLASS = 'px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50'
const CHOICE_CLASS = 'text-left p-4 border rounded-xl transition disabled:opacity-60'

// The four loaders answer with a partial body on an older panel, so each
// response is normalized once here rather than defaulted at every read site.
function normalizeHotlink(data?: HotlinkSettings | null): HotlinkSettings {
  return { active: data?.active === true, allowed: data?.allowed || [] }
}

function normalizeRules(data?: IPRulesResponse | null): IPRulesResponse {
  return { mode: data?.mode || 'off', rules: data?.rules || [] }
}

function normalizeGeo(data?: GeoResponse | null): { mode: GeoMode; countries: string[]; database: DatabaseStatus | null } {
  return { mode: data?.mode || 'off', countries: data?.countries || [], database: data?.database || null }
}

function normalizeRate(data?: RateLimitResponse | null): RateLimitResponse {
  return { rps: data?.rps || 0, ladder: data?.ladder || [] }
}

// HotlinkCard names the sites allowed to embed this domain's own files.
function HotlinkCard({ hotlink, allowedInput, busy, onHotlink, onAllowedInput, onSubmit }: {
  hotlink: HotlinkSettings
  allowedInput: string
  busy: boolean
  onHotlink: (value: HotlinkSettings) => void
  onAllowedInput: (value: string) => void
  onSubmit: (event: React.SubmitEvent) => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <form onSubmit={onSubmit} className={`${CARD_CLASS} mb-5`}>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
        <div>
          <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('hotlink.title')}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('hotlink.description')}</p>
        </div>
        <label className="flex items-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-600 dark:text-slate-300">
          <input type="checkbox" checked={hotlink.active} onChange={event => onHotlink({ ...hotlink, active: event.target.checked })} />
          {t('hotlink.enabled')}
        </label>
      </div>
      <label className="block">
        <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('hotlink.allowedLabel')}</span>
        <textarea value={allowedInput} onChange={event => onAllowedInput(event.target.value)} rows={4} placeholder={'cdn.example.com\n*.partner.example'}
          className={FIELD_CLASS} />
      </label>
      <p className="text-[11px] text-slate-400 mt-2">{t('hotlink.hint')}</p>
      <button disabled={busy} className={`mt-3 ${PRIMARY_BUTTON_CLASS}`}>
        {busy ? t('hotlink.saving') : t('hotlink.save')}
      </button>
    </form>
  )
}

// ChoiceButton is one option of the mode pickers below.
function ChoiceButton({ active, disabled, label, description, onClick }: {
  active: boolean
  disabled: boolean
  label: string
  description: string
  onClick: () => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <button type="button" onClick={onClick} disabled={disabled}
      className={`${CHOICE_CLASS} ${active ? 'border-slate-900 dark:border-slate-100 bg-slate-50 dark:bg-slate-900/40' : 'border-slate-200 dark:border-slate-700 hover:border-slate-400'}`}>
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{label}</span>
        {active && <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">{t('ipMode.selected')}</span>}
      </div>
      <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">{description}</p>
    </button>
  )
}

// IPModeCard decides whether the rule list blocks or allows.
function IPModeCard({ mode, busy, onSelect }: {
  mode: IPAccessMode
  busy: boolean
  onSelect: (mode: IPAccessMode) => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <div className={`${CARD_CLASS} mb-5`}>
      <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('ipMode.title')}</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {(Object.keys(MODE_BADGE) as IPAccessMode[]).map(item => (
          <ChoiceButton key={item} active={mode === item} disabled={busy}
            label={t(`modes.${item}.label`)} description={t(`modes.${item}.description`)}
            onClick={() => onSelect(item)} />
        ))}
      </div>
    </div>
  )
}

// NewRuleForm adds one address or CIDR to the rule list.
function NewRuleForm({ newRule, busy, onNewRule, onSubmit }: {
  newRule: string
  busy: boolean
  onNewRule: (value: string) => void
  onSubmit: (event: React.SubmitEvent) => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <form onSubmit={onSubmit} className={`${CARD_CLASS} mb-5`}>
      <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-3">{t('newRule.title')}</h3>
      <div className="flex flex-wrap items-end gap-2">
        <label className="block flex-1 min-w-[260px]">
          <span className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">{t('newRule.label')}</span>
          <input value={newRule} onChange={event => onNewRule(event.target.value)} required placeholder={t('newRule.placeholder')}
            className={FIELD_CLASS} />
        </label>
        <button disabled={busy || !newRule.trim()} className={PRIMARY_BUTTON_CLASS}>
          {busy ? t('newRule.adding') : t('newRule.add')}
        </button>
      </div>
    </form>
  )
}

// RulesCard lists the addresses the mode above applies to.
function RulesCard({ rules, busy, onDelete }: {
  rules: IPRule[]
  busy: boolean
  onDelete: (rule: IPRule) => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <div className={CARD_CLASS}>
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
              <button onClick={() => onDelete(rule)} disabled={busy} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">{t('rules.delete')}</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// GeoNotes states what the country filter does not cover.
function GeoNotes({ database }: { database: DatabaseStatus }) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <ul className="mt-3 space-y-1 text-[11px] text-slate-500 dark:text-slate-400 list-disc list-inside">
      <li>{t('geo.noteAcme')}</li>
      <li>{t('geo.noteIpRules')}</li>
      <li>{t('geo.noteCdn')}</li>
      {!database.ipv6 && <li className="text-amber-600 dark:text-amber-400">{t('geo.noteNoIpv6')}</li>}
      {database.build_date && <li>{t('geo.buildDate', { date: database.build_date })}</li>}
    </ul>
  )
}

// GeoCard filters by country, and says so when the database is missing.
function GeoCard({ database, geoMode, geoCountries, busy, onGeoMode, onGeoCountries, onSubmit }: {
  database: DatabaseStatus | null
  geoMode: GeoMode
  geoCountries: string[]
  busy: boolean
  onGeoMode: (mode: GeoMode) => void
  onGeoCountries: (countries: string[]) => void
  onSubmit: () => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <form onSubmit={event => { event.preventDefault(); onSubmit() }} className={`${CARD_CLASS} mt-5`}>
      <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('geo.title')}</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('geo.description')}</p>

      {!database?.available ? (
        <div className="px-3 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200">
          {database?.configured ? t('geo.notDownloaded') : t('geo.notConfigured')}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
            {(['off', 'allow', 'deny'] as GeoMode[]).map(item => (
              <ChoiceButton key={item} active={geoMode === item} disabled={busy}
                label={t(`geo.modes.${item}.label`)} description={t(`geo.modes.${item}.description`)}
                onClick={() => onGeoMode(item)} />
            ))}
          </div>

          {geoMode !== 'off' && (
            <CountryPicker
              available={database.countries}
              selected={geoCountries}
              disabled={busy}
              max={MAX_COUNTRIES}
              onChange={onGeoCountries}
              labels={{
                search: t('geo.search'),
                none: t('geo.noMatch'),
                selected: t('geo.selected', { n: geoCountries.length, max: MAX_COUNTRIES }),
                limit: t('geo.limitReached', { max: MAX_COUNTRIES }),
              }} />
          )}

          <GeoNotes database={database} />

          <button disabled={busy} className={`mt-3 ${PRIMARY_BUTTON_CLASS}`}>
            {busy ? t('geo.saving') : t('geo.save')}
          </button>
        </>
      )}
    </form>
  )
}

// RateCard picks the requests-per-second ceiling from the server's own ladder.
function RateCard({ rps, ladder, busy, onSelect }: {
  rps: number
  ladder: number[]
  busy: boolean
  onSelect: (value: number) => void
}) {
  const { t } = useTranslation('DomainAccessControlPage')
  return (
    <div className={`${CARD_CLASS} mt-5`}>
      <h3 className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-1">{t('rate.title')}</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('rate.description')}</p>
      <div className="flex flex-wrap gap-2">
        {[0, ...ladder].map(value => {
          const active = rps === value
          return (
            <button key={value} type="button" onClick={() => onSelect(value)} disabled={busy || active}
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
  )
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
      const nextHotlink = normalizeHotlink(hotlinkResponse.data)
      setHotlink(nextHotlink)
      setAllowedInput(nextHotlink.allowed.join('\n'))
      const nextRules = normalizeRules(rulesResponse.data)
      setMode(nextRules.mode)
      setRules(nextRules.rules)
      const nextGeo = normalizeGeo(geoResponse.data)
      setGeoMode(nextGeo.mode)
      setGeoCountries(nextGeo.countries)
      setDatabase(nextGeo.database)
      const nextRate = normalizeRate(rateResponse.data)
      setRps(nextRate.rps)
      setLadder(nextRate.ladder)
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

  async function saveHotlink(event: React.SubmitEvent) {
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

  async function addRule(event: React.SubmitEvent) {
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
          <HotlinkCard
            hotlink={hotlink} allowedInput={allowedInput} busy={busy}
            onHotlink={setHotlink} onAllowedInput={setAllowedInput} onSubmit={saveHotlink}
          />

          <IPModeCard mode={mode} busy={busy} onSelect={saveMode} />

          <NewRuleForm newRule={newRule} busy={busy} onNewRule={setNewRule} onSubmit={addRule} />

          <RulesCard rules={rules} busy={busy} onDelete={deleteRule} />

          <GeoCard
            database={database} geoMode={geoMode} geoCountries={geoCountries} busy={busy}
            onGeoMode={setGeoMode} onGeoCountries={setGeoCountries}
            onSubmit={() => saveGeo(geoMode, geoCountries)}
          />

          <RateCard rps={rps} ladder={ladder} busy={busy} onSelect={saveRate} />

          <div className="mt-4"><Link to={`/subscriptions/${id}`} className="text-sm text-brand-600 dark:text-brand-400">{t('back')}</Link></div>
        </>
      )}
    </div>
  )
}
