import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError, apiReason } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import { countryFlag, countryNamer, sortByName } from '@/lib/countries'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Rule = {
  id: number; type: 'ban' | 'whitelist' | 'close'; ip: string; port: number
  protocol: string; description: string; enabled: boolean; created_at: string
}
type ListResponse = { rules: Rule[]; protected_ports: number[] }

type DatabaseStatus = {
  configured: boolean
  account_id?: string
  available: boolean
  build_date?: string
  updated_at?: string
  last_error?: string
  countries: string[]
  ipv6: boolean
}

type GeoResponse = { countries: string[]; database: DatabaseStatus }

// Presets for closing commonly exposed ports with one click. Text is resolved via i18n.
const TEMPLATES = [
  { key: 'close_mysql', icon: ICON.database, ports: '3306' },
  { key: 'close_ftp', icon: ICON.folder, ports: '21' },
  { key: 'close_mail', icon: ICON.mail, ports: '25, 465, 587, 110, 143' },
  { key: 'close_rpc', icon: ICON.link, ports: '111, 2049' },
] as const

// Manual rule modes; icons and colors are structural, text is resolved via i18n.
const MODES = {
  ban: { icon: ICON.ban, activeColor: 'bg-red-600 border-red-600' },
  whitelist: { icon: ICON.check, activeColor: 'bg-emerald-600 border-emerald-600' },
  close: { icon: ICON.lock, activeColor: 'bg-amber-600 border-amber-600' },
} as const

export default function FirewallPage() {
  const { t, i18n } = useTranslation('FirewallPage')
  const { confirm } = useDialog()
  const [rules, setRules] = useState<Rule[]>([])
  const [protectedPorts, setProtectedPorts] = useState<number[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const [database, setDatabase] = useState<DatabaseStatus | null>(null)
  const [blocked, setBlocked] = useState<string[]>([])
  const [newCountry, setNewCountry] = useState('')
  const [accountId, setAccountId] = useState('')
  const [licenseKey, setLicenseKey] = useState('')

  // Country names come from the browser in the reader's language; the panel
  // ships codes only.
  const nameOf = useMemo(() => countryNamer(i18n.language), [i18n.language])
  const selectable = useMemo(
    () => sortByName((database?.countries || []).filter(code => !blocked.includes(code)), nameOf),
    [database, blocked, nameOf])

  const [type, setType] = useState<'ban' | 'whitelist' | 'close'>('ban')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState<'tcp' | 'udp'>('tcp')
  const [description, setDescription] = useState('')

  // Split so the mount effect never writes state synchronously: fetchRules
  // settles only through promise callbacks, and load() adds the spinner for the
  // refresh button and the refreshes that follow a write.
  const fetchRules = useCallback(() => {
    Promise.all([
      api.get<ListResponse>('/firewall'),
      api.get<GeoResponse>('/firewall/geo'),
    ])
      .then(([listResponse, geoResponse]) => {
        setRules(listResponse.data.rules || [])
        setProtectedPorts(listResponse.data.protected_ports || [])
        setBlocked(geoResponse.data.countries || [])
        setDatabase(geoResponse.data.database || null)
        setAccountId(geoResponse.data.database?.account_id || '')
      })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    fetchRules()
  }, [fetchRules])

  useEffect(() => { fetchRules() }, [fetchRules])

  async function applyTemplate(template: typeof TEMPLATES[number]) {
    const templateName = t(`templates.${template.key}.name`)
    if (!(await confirm({ message: t('confirm.applyTemplate', { name: templateName, ports: template.ports }) }))) return
    setError(null); setSuccess(null); setBusy('template:' + template.key)
    try {
      const { data } = await api.post('/firewall/template', { template: template.key })
      setSuccess(data.added > 0
        ? t('success.templateApplied', { name: templateName, count: data.added })
        : t('success.templateAlreadyApplied', { name: templateName }))
      load()
    } catch (caughtError) { setError(apiError(caughtError, t('error.applyTemplate'))) }
    finally { setBusy(null) }
  }

  async function add(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setBusy('manual')
    try {
      await api.post('/firewall', {
        type, ip: type === 'close' ? '' : ip.trim(),
        port: port.trim() ? parseInt(port, 10) : 0, protocol, description: description.trim(),
      })
      setSuccess(t('success.ruleAdded'))
      setIp(''); setPort(''); setDescription('')
      load()
    } catch (caughtError) { setError(apiError(caughtError, t('error.addRule'))) }
    finally { setBusy(null) }
  }

  async function remove(rule: Rule) {
    const typeLabel = t(`modes.${rule.type}.name`)
    const summary = rule.type === 'close'
      ? t('confirm.removeClose', { port: rule.port })
      : rule.port
        ? t('confirm.removeOtherWithPort', { ip: rule.ip, port: rule.port, type: typeLabel })
        : t('confirm.removeOther', { ip: rule.ip, type: typeLabel })
    if (!(await confirm({ message: t('confirm.remove', { summary }), dangerous: true }))) return
    setError(null); setSuccess(null); setBusy('remove:' + rule.id)
    try { await api.delete(`/firewall/${rule.id}`); load() }
    catch (caughtError) { setError(apiError(caughtError, t('error.deleteRule'))) }
    finally { setBusy(null) }
  }

  async function saveCredentials(event: React.FormEvent) {
    event.preventDefault()
    setError(null); setSuccess(null); setBusy('credentials')
    try {
      await api.put('/system/geoip/credentials', { account_id: accountId.trim(), license_key: licenseKey.trim() })
      // The key is never read back, so the field is cleared rather than left
      // holding a value the panel would not return on the next load.
      setLicenseKey('')
      setSuccess(accountId.trim() ? t('geo.success.credentialsSaved') : t('geo.success.credentialsCleared'))
      load()
    } catch (caught) { setError(apiError(caught, t('geo.error.credentials'))) }
    finally { setBusy(null) }
  }

  async function updateDatabase() {
    setError(null); setSuccess(null); setBusy('update')
    try {
      const { data } = await api.post<DatabaseStatus>('/system/geoip/update', {})
      setDatabase(data)
      setSuccess(t('geo.success.updated', { date: data.build_date || '-' }))
      load()
    } catch (caught) { setError(apiError(caught, t('geo.error.update'))) }
    finally { setBusy(null) }
  }

  async function blockCountry(event: React.FormEvent) {
    event.preventDefault()
    const code = newCountry
    if (!code) return
    if (!(await confirm({ message: t('geo.confirm.block', { country: nameOf(code) }), dangerous: true }))) return
    setError(null); setSuccess(null); setBusy('geo:add')
    try {
      await api.post('/firewall/geo', { country: code })
      setNewCountry('')
      setSuccess(t('geo.success.blocked', { country: nameOf(code) }))
      load()
    } catch (caught) {
      const reason = apiReason(caught)
      setError(reason ? t(`geo.reasons.${reason}`) : apiError(caught, t('geo.error.block')))
    }
    finally { setBusy(null) }
  }

  async function unblockCountry(code: string) {
    if (!(await confirm({ message: t('geo.confirm.unblock', { country: nameOf(code) }) }))) return
    setError(null); setSuccess(null); setBusy('geo:' + code)
    try {
      await api.delete(`/firewall/geo/${code}`)
      setSuccess(t('geo.success.unblocked', { country: nameOf(code) }))
      load()
    } catch (caught) { setError(apiError(caught, t('geo.error.unblock'))) }
    finally { setBusy(null) }
  }

  const ipRequired = type !== 'close'
  const protectedPortsText = useMemo(() => protectedPorts.slice().sort((a, b) => a - b).join(', '), [protectedPorts])

  // Generate the live preview sentence.
  const preview = useMemo(() => {
    if (type === 'close') return port ? t('preview.closeReady', { port }) : t('preview.closeEmpty')
    const address = ip.trim() || t('preview.enterIp')
    if (type === 'ban') {
      return port ? t('preview.banPort', { address, port }) : t('preview.banAll', { address })
    }
    // Allowlist mode.
    if (port) return t('preview.whitelistPort', { port, address })
    return t('preview.whitelistAll', { address })
  }, [type, ip, port, t])

  // Warn about dynamic IP addresses when a port-specific allowlist is active.
  const restrictionWarning = type === 'whitelist' && port.trim() !== ''

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.firewall') }]} />
      <div className="flex items-center gap-3 mb-1">
        <span className="text-brand-600 dark:text-brand-400"><Icon d={ICON.shield} className="h-6 w-6" /></span>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
        {t('subtitle.pre')}<strong>{t('subtitle.bold')}</strong>{t('subtitle.post')}
      </p>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      <div className="mb-5 flex items-start gap-1.5 px-4 py-2.5 rounded-lg bg-sky-50 dark:bg-sky-900/20 border border-sky-200 dark:border-sky-800 text-xs text-sky-800 dark:text-sky-200">
        <Icon d={ICON.info} className="mt-0.5 h-3.5 w-3.5 shrink-0" /><span>{t('info.pre')}<strong>{t('info.bold')}</strong>{t('info.mid')}<span className="font-mono">{protectedPortsText || t('protectedPortsFallback')}</span>{t('info.post')}</span>
      </div>

      {/* ---------- PRESETS ---------- */}
      <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2 flex items-center gap-2"><Icon d={ICON.bolt} className="h-4 w-4" /> {t('templates.sectionTitle')} <span className="text-xs font-normal text-slate-400">{t('templates.sectionHint')}</span></h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
        {TEMPLATES.map(s => (
          <div key={s.key} className="flex items-start gap-3 p-4 rounded-2xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60">
            <div className="w-10 h-10 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-300 shrink-0"><Icon d={s.icon} className="h-5 w-5" /></div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-slate-800 dark:text-slate-100">{t(`templates.${s.key}.name`)}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t(`templates.${s.key}.description`)}</div>
              <div className="text-[11px] font-mono text-slate-400 mt-1">{t('templates.portLabel', { ports: s.ports })}</div>
            </div>
            <button onClick={() => applyTemplate(s)} disabled={!!busy}
              className="shrink-0 self-center px-3 py-1.5 text-xs font-medium bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 rounded-lg disabled:opacity-50">
              {busy === 'template:' + s.key ? t('templates.applying') : t('templates.apply')}
            </button>
          </div>
        ))}
      </div>

      {/* ---------- MANUAL RULE ---------- */}
      <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2 flex items-center gap-2"><Icon d={ICON.pencil} className="h-4 w-4" /> {t('form.sectionTitle')}</h2>
      <form onSubmit={add} className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-6">
        {/* Step 1: choose an action. */}
        <div className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-2">{t('form.step1')}</div>
        <div className="grid grid-cols-3 gap-2 mb-3">
          {(['ban', 'whitelist', 'close'] as const).map(mode => (
            <button key={mode} type="button" onClick={() => setType(mode)}
              className={`px-3 py-3 text-sm font-medium rounded-lg border text-center transition ${
                type === mode ? MODES[mode].activeColor + ' text-white'
                  : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
              }`}>
              <div className="mb-1 flex justify-center"><Icon d={MODES[mode].icon} className="h-5 w-5" /></div>
              {t(`modes.${mode}.name`)}
            </button>
          ))}
        </div>
        {/* Selected mode description */}
        <div className="mb-4 px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-900/40 text-xs text-slate-600 dark:text-slate-300">
          {t(`modes.${type}.description`)}<br /><span className="text-slate-400">{t(`modes.${type}.example`)}</span>
        </div>

        {/* Step 2: enter rule details. */}
        <div className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-2">{t('form.step2')}</div>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          {ipRequired && (
            <label className="block sm:col-span-2">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('form.ipLabel')}</span>
              <input value={ip} onChange={e => setIp(e.target.value)} required placeholder={t('form.ipPlaceholder')}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
          )}
          <label className="block">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('form.portLabel')} {ipRequired && <span className="text-slate-400">{t('form.portBlankHint')}</span>}</span>
            <input value={port} onChange={e => setPort(e.target.value.replace(/[^0-9]/g, ''))} required={type === 'close'} placeholder={type === 'close' ? t('form.portPlaceholderClose') : t('form.portPlaceholderOther')}
              className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
          </label>
          <label className="block">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('form.protocolLabel')}</span>
            <select value={protocol} onChange={e => setProtocol(e.target.value as 'tcp' | 'udp')}
              className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none">
              <option value="tcp">TCP</option><option value="udp">UDP</option>
            </select>
          </label>
          <label className="block sm:col-span-4">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('form.noteLabel')}</span>
            <input value={description} onChange={e => setDescription(e.target.value)} placeholder={t('form.notePlaceholder')}
              className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
          </label>
        </div>

        {/* Live preview */}
        <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-900/60 text-xs">
          <span className="text-slate-400">{t('form.previewLabel')}</span>
          <span className="font-medium text-slate-700 dark:text-slate-200">{preview}</span>
        </div>

        {/* Dynamic IP warning for an active allowlist restriction */}
        {restrictionWarning && (
          <div className="mt-2 flex items-start gap-1.5 px-3 py-2 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200">
            <Icon d={ICON.warning} className="mt-0.5 h-3.5 w-3.5 shrink-0" /><span>{t('warning.pre')}<strong>{t('warning.bold')}</strong>{t('warning.mid')}<strong>{t('warning.boldDynamic')}</strong>{t('warning.post')}</span>
          </div>
        )}

        <button disabled={busy === 'manual'} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
          {busy === 'manual' ? t('form.submitting') : t('form.submit')}
        </button>
      </form>

      {/* ---------- COUNTRY BLOCKING ---------- */}
      <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2 flex items-center gap-2"><Icon d={ICON.globe} className="h-4 w-4" /> {t('geo.sectionTitle')}</h2>
      <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl p-4 mb-6">
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('geo.sectionHint')}</p>

        <form onSubmit={saveCredentials} className="mb-4">
          <div className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-2">{t('geo.credentials.title')}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('geo.credentials.hint')}</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="block">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('geo.credentials.accountLabel')}</span>
              <input value={accountId} onChange={e => setAccountId(e.target.value.replace(/[^0-9]/g, ''))} inputMode="numeric" placeholder="123456"
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
            <label className="block sm:col-span-2">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('geo.credentials.keyLabel')}</span>
              <input type="password" autoComplete="off" value={licenseKey} onChange={e => setLicenseKey(e.target.value)}
                placeholder={database?.configured ? t('geo.credentials.keyStored') : t('geo.credentials.keyPlaceholder')}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
          </div>
          <button disabled={busy === 'credentials'} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {busy === 'credentials' ? t('geo.credentials.saving') : t('geo.credentials.save')}
          </button>
        </form>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/40 mb-3">
          <div>
            <div className="text-[11px] text-slate-400">{t('geo.status.database')}</div>
            <div className="text-sm font-medium text-slate-800 dark:text-slate-100">
              {database?.available ? t('geo.status.ready') : database?.configured ? t('geo.status.notDownloaded') : t('geo.status.notConfigured')}
            </div>
          </div>
          <div>
            <div className="text-[11px] text-slate-400">{t('geo.status.buildDate')}</div>
            <div className="text-sm font-mono text-slate-800 dark:text-slate-100">{database?.build_date || '-'}</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-400">{t('geo.status.updatedAt')}</div>
            <div className="text-sm font-mono text-slate-800 dark:text-slate-100">{database?.updated_at || '-'}</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-400">{t('geo.status.coverage')}</div>
            <div className="text-sm text-slate-800 dark:text-slate-100">
              {database?.available ? t('geo.status.countryCount', { n: database.countries.length }) : '-'}
              {database?.available && !database.ipv6 && <span className="ml-1 text-amber-600 dark:text-amber-400">{t('geo.status.ipv4Only')}</span>}
            </div>
          </div>
        </div>

        {database?.last_error && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-xs text-red-700 dark:text-red-300 break-all">
            {t('geo.status.lastError', { message: database.last_error })}
          </div>
        )}

        <button type="button" onClick={updateDatabase} disabled={!database?.configured || busy === 'update'}
          className="mb-4 px-3 py-1.5 text-xs font-medium border border-slate-200 dark:border-slate-700 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">
          {busy === 'update' ? t('geo.updating') : t('geo.updateNow')}
        </button>

        <div className="text-[11px] uppercase tracking-wide text-slate-400 font-semibold mb-2">{t('geo.blocked.title')}</div>
        <form onSubmit={blockCountry} className="flex flex-wrap items-end gap-2 mb-3">
          <label className="block flex-1 min-w-[220px]">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{t('geo.blocked.pickLabel')}</span>
            <select value={newCountry} onChange={e => setNewCountry(e.target.value)} disabled={!database?.available}
              className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-50">
              <option value="">{t('geo.blocked.pickPlaceholder')}</option>
              {selectable.map(code => <option key={code} value={code}>{nameOf(code)} ({code})</option>)}
            </select>
          </label>
          <button disabled={!newCountry || busy === 'geo:add'} className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg disabled:opacity-50">
            {busy === 'geo:add' ? t('geo.blocked.blocking') : t('geo.blocked.block')}
          </button>
        </form>

        {blocked.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('geo.blocked.empty')}</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {sortByName(blocked, nameOf).map(code => (
              <button key={code} type="button" onClick={() => unblockCountry(code)} disabled={!!busy}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-900/60 disabled:opacity-50">
                <span aria-hidden="true">{countryFlag(code)}</span>{nameOf(code)}<span className="text-red-400">×</span>
              </button>
            ))}
          </div>
        )}

        <ul className="mt-3 space-y-1 text-[11px] text-slate-500 dark:text-slate-400 list-disc list-inside">
          <li>{t('geo.noteAllPorts')}</li>
          <li>{t('geo.noteWhitelist')}</li>
          <li>{t('geo.noteApproximate')}</li>
        </ul>
      </div>

      {/* ---------- ACTIVE RULES ---------- */}
      <div className="bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('rules.title')} {!loading && <span className="text-slate-400 font-normal">{t('rules.count', { count: rules.length })}</span>}</h3>
          <button onClick={load} disabled={loading} className="text-xs px-2.5 py-1 border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50">{t('rules.refresh')}</button>
        </div>
        <div className={responsiveTableContainerClass}>
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="text-left font-medium px-4 py-2.5">{t('rules.colType')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('rules.colIp')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('rules.colPort')}</th>
                <th className="text-left font-medium px-4 py-2.5">{t('rules.colProto')}</th>
                <th className="text-left font-medium px-4 py-2.5 w-full">{t('rules.colNote')}</th>
                <th className="text-right font-medium px-4 py-2.5">{t('rules.colAction')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-400">{t('rules.loading')}</td></tr>
              ) : rules.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-10 text-center">
                  <div className="mb-1 flex justify-center text-slate-400"><Icon d={ICON.shield} className="h-6 w-6" /></div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{t('rules.emptyTitle')}</p>
                  <p className="text-xs text-slate-400 mt-1">{t('rules.emptyHint')}</p>
                </td></tr>
              ) : (
                rules.map(rule => (
                  <tr key={rule.id} className={responsiveTableRowClass}>
                    <td data-label={t('rules.colType')} className={responsiveTableCellClass}><TypeBadge type={rule.type} /></td>
                    <td data-label={t('rules.colIp')} className={responsiveTableCodeCellClass}>{rule.ip || <span className="text-slate-400">{t('rules.everyone')}</span>}</td>
                    <td data-label={t('rules.colPort')} className={responsiveTableCodeCellClass}>{rule.port || <span className="text-slate-400">{t('rules.allPorts')}</span>}</td>
                    <td data-label={t('rules.colProto')} className={`${responsiveTableCodeCellClass} uppercase`}>{rule.protocol}</td>
                    <td data-label={t('rules.colNote')} className={responsiveTableCellClass}>{rule.description || '-'}</td>
                    <td className={responsiveTableActionCellClass}>
                      <button disabled={!!busy} onClick={() => remove(rule)} className="text-xs px-2.5 py-1 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">{busy === 'remove:' + rule.id ? t('rules.deleting') : t('rules.delete')}</button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function TypeBadge({ type }: { type: Rule['type'] }) {
  const { t } = useTranslation('FirewallPage')
  const color = {
    ban: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300',
    whitelist: 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300',
    close: 'bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200',
  }[type]
  return <span className={`inline-block text-xs px-2 py-0.5 rounded-full font-medium ${color}`}>{t(`badge.${type}`)}</span>
}
