import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useAuth } from '@/store/auth'
import { getTheme, setTheme, type Theme } from '@/lib/theme'
import { api } from '@/lib/api'
import LanguageSwitcher from '@/components/LanguageSwitcher'

type TopBarProps = {
  onMenuClick?: () => void
}

type SearchEntry = {
  kind: 'page' | 'domain' | 'subdomain' | 'customer' | 'user'
  title: string
  subtitle: string
  path: string
  keywords?: string
}

type DomainRow = { id: number; domain_name: string; system_user?: string; status?: string }
type SubdomainRow = { id: number; fqdn: string; parent_id: number; parent_name?: string; system_user?: string }
type CustomerRow = { id: number; name: string; email?: string; status?: string }
type UserRow = { id: number; username: string; full_name?: string; email?: string; role?: string }

// Static navigation targets. `roles` limits an entry to those roles; when absent
// the entry is offered to every management session (admin and reseller). Paths
// mirror App.tsx exactly so a result always resolves to a real route. `tkey`
// resolves the display title/subtitle via the TopBar `pages` namespace.
const PAGES: ReadonlyArray<{ tkey: string; path: string; keywords: string; roles?: string[] }> = [
  { tkey: 'home', path: '/', keywords: 'dashboard' },
  { tkey: 'domains', path: '/domains', keywords: 'site hosting subscription' },
  { tkey: 'servicePlans', path: '/service-plans', keywords: 'package quota' },
  { tkey: 'customers', path: '/customers', keywords: 'contact billing' },
  { tkey: 'users', path: '/users', keywords: 'account reseller admin' },
  { tkey: 'dns', path: '/dns', keywords: 'zone nameserver ns' },
  { tkey: 'ssl', path: '/ssl', keywords: 'https lets encrypt tls' },
  { tkey: 'mail', path: '/mail', keywords: 'email mailbox' },
  { tkey: 'databases', path: '/databases', keywords: 'mysql db' },
  { tkey: 'wordpress', path: '/wordpress', keywords: 'wp application' },
  { tkey: 'serverStatus', path: '/server-status', keywords: 'cpu ram disk' },
  { tkey: 'profile', path: '/profile', keywords: 'password 2fa theme' },
  { tkey: 'accountTransfer', path: '/account-transfer', keywords: 'migration cpanel', roles: ['admin'] },
  { tkey: 'siteMigration', path: '/site-migration', keywords: 'migration plesk cpanel directadmin ssh', roles: ['admin'] },
  { tkey: 'toolsSettings', path: '/tools-settings', keywords: 'settings', roles: ['admin'] },
  { tkey: 'optimize', path: '/tools/optimize', keywords: 'performance tune', roles: ['admin'] },
  { tkey: 'statistics', path: '/statistics', keywords: 'graph traffic', roles: ['admin'] },
  { tkey: 'firewall', path: '/firewall', keywords: 'port ip block', roles: ['admin'] },
  { tkey: 'monitoring', path: '/monitoring', keywords: 'monitor log cpu ram', roles: ['admin'] },
  { tkey: 'auditLog', path: '/audit-log', keywords: 'audit event', roles: ['admin'] },
  { tkey: 'services', path: '/tools/services', keywords: 'systemd nginx mysql php', roles: ['admin'] },
  { tkey: 'phpVersions', path: '/tools/php-versions', keywords: 'fpm', roles: ['admin'] },
  { tkey: 'phpModules', path: '/system/php-modules', keywords: 'extension pecl', roles: ['admin'] },
  { tkey: 'packages', path: '/tools/packages', keywords: 'dnf rpm', roles: ['admin'] },
  { tkey: 'dnsTemplate', path: '/tools/dns-template', keywords: 'template zone', roles: ['admin'] },
  { tkey: 'bannedDomains', path: '/tools/banned-domains', keywords: 'phishing blacklist blocked hostname', roles: ['admin'] },
  { tkey: 'siteSecurity', path: '/site-security', keywords: 'cve vulnerability plugin dependency npm composer', roles: ['admin', 'reseller'] },
  { tkey: 'appCatalog', path: '/tools/app-catalog', keywords: 'installer joomla drupal grav matomo nextcloud prestashop mediawiki', roles: ['admin'] },
  { tkey: 'panelUpdate', path: '/tools/update', keywords: 'upgrade release', roles: ['admin'] },
]

// Domain-scoped tool pages, offered as results only while a domain is open.
// Each tuple is [path suffix, tkey]; the display title/subtitle resolve via the
// TopBar `domain` namespace.
const DOMAIN_PAGES: ReadonlyArray<readonly [string, string]> = [
  ['', 'overview'],
  ['/files', 'files'],
  ['/web-server', 'webServer'],
  ['/php', 'php'],
  ['/composer', 'composer'],
  ['/performance', 'performance'],
  ['/redis', 'redis'],
  ['/wordpress', 'wordpress'],
  ['/dns', 'dns'],
  ['/subdomains', 'subdomains'],
  ['/addon-domains', 'addonDomains'],
  ['/ssl', 'ssl'],
  ['/databases', 'databases'],
  ['/ftp', 'ftp'],
  ['/mail', 'mail'],
  ['/mail/reports', 'mailReports'],
  ['/backups', 'backups'],
  ['/copy', 'copy'],
  ['/git', 'git'],
  ['/laravel', 'laravel'],
  ['/cron', 'cron'],
  ['/apps', 'apps'],
  ['/ssh-access', 'ssh'],
  ['/logs', 'logs'],
  ['/waf', 'waf'],
  ['/access-control', 'accessControl'],
  ['/maintenance', 'maintenance'],
  ['/password-protection', 'passwordProtection'],
  ['/imunify', 'imunify'],
  ['/site-security', 'siteSecurity'],
  ['/app-installer', 'appInstaller'],
  ['/stats', 'stats'],
  ['/connection', 'connection'],
]

// Locale-neutral fold: lowercase + strip combining diacritics so "Örnek"
// matches "ornek". Good enough for both English and Turkish target text.
function normalize(s: string): string {
  return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
}

function copyToClipboard(text: string): boolean {
  if (navigator.clipboard && window.isSecureContext) {
    // Silent on purpose: the caller falls back to a manual copy prompt when
    // this returns false, so a rejected clipboard write is already handled.
    navigator.clipboard.writeText(text).catch(() => {})
    return true
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    return true
  } catch {
    return false
  }
}

export default function TopBar({ onMenuClick }: TopBarProps) {
  const { t } = useTranslation('TopBar')
  const username = useAuth((s) => s.username)
  const logout = useAuth((s) => s.logout)
  const isCustomer = useAuth((s) => s.isCustomer)
  const navigate = useNavigate()
  const location = useLocation()
  const searchRef = useRef<HTMLInputElement>(null)
  const searchBoxRef = useRef<HTMLDivElement>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setCurrentTheme] = useState<Theme>(getTheme())
  const [serverIp, setServerIp] = useState<string | null>(null)
  const [ipCopied, setIpCopied] = useState(false)
  const [query, setQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchLoading, setSearchLoading] = useState(false)
  const [selected, setSelected] = useState(0)
  const [records, setRecords] = useState<SearchEntry[]>([])
  const [recordsLoaded, setRecordsLoaded] = useState(false)

  const role = username?.role || 'user'
  // Global search targets management data (domains/customers/users) and admin
  // pages; a customer portal session has none of these, so it is never shown.
  const canSearch = !isCustomer && (role === 'admin' || role === 'reseller')
  const openDomainID = location.pathname.match(/^\/subscriptions\/(\d+)/)?.[1]

  const results = useMemo(() => {
    const q = normalize(query.trim())
    if (!q) return []
    const pages: SearchEntry[] = PAGES
      .filter((p) => !p.roles || p.roles.includes(role))
      .map((p) => ({
        kind: 'page' as const, title: t(`pages.${p.tkey}.title`), subtitle: t(`pages.${p.tkey}.subtitle`),
        path: p.path, keywords: p.keywords,
      }))
    const domainPages: SearchEntry[] = openDomainID
      ? DOMAIN_PAGES.map(([suffix, tkey]) => ({
          kind: 'page' as const, title: t(`domain.${tkey}.title`),
          subtitle: `${t(`domain.${tkey}.subtitle`)} · ${t('openDomain')}`,
          path: `/subscriptions/${openDomainID}${suffix}`, keywords: 'domain site subscription',
        }))
      : []
    return [...pages, ...domainPages, ...records]
      .map((entry) => {
        const text = normalize(`${entry.title} ${entry.subtitle} ${entry.keywords || ''}`)
        const rank = normalize(entry.title).startsWith(q) ? 0 : text.includes(q) ? 1 : 2
        return { entry, rank }
      })
      .filter((x) => x.rank < 2)
      .sort((a, b) => a.rank - b.rank || a.entry.title.localeCompare(b.entry.title))
      .slice(0, 12)
      .map((x) => x.entry)
  }, [query, openDomainID, records, role, t])

  async function loadSearchData() {
    if (!canSearch || recordsLoaded || searchLoading) return
    setSearchLoading(true)
    try {
      const requests: Array<Promise<SearchEntry[]>> = [
        api.get<DomainRow[]>('/domains').then((r) => (Array.isArray(r.data) ? r.data : []).map((d) => ({
          kind: 'domain' as const, title: d.domain_name,
          subtitle: `Domain${d.system_user ? ` · ${d.system_user}` : ''}${d.status ? ` · ${d.status}` : ''}`,
          path: `/subscriptions/${d.id}`, keywords: `site hosting ${d.system_user || ''}`,
        }))).catch(() => []),
        // Scoped server-side, so a reseller gets only its own subdomains.
        api.get<SubdomainRow[]>('/subdomains').then((r) => (Array.isArray(r.data) ? r.data : []).map((s) => ({
          kind: 'subdomain' as const, title: s.fqdn,
          subtitle: `Subdomain${s.parent_name ? ` · ${s.parent_name}` : ''}`,
          path: `/domains/${s.parent_id}/subdomain/${s.id}`,
          keywords: `${s.parent_name || ''} ${s.system_user || ''}`,
        }))).catch(() => []),
        api.get<CustomerRow[]>('/customers').then((r) => (Array.isArray(r.data) ? r.data : []).map((c) => ({
          kind: 'customer' as const, title: c.name, subtitle: `Customer${c.email ? ` · ${c.email}` : ''}`,
          path: `/customers?q=${encodeURIComponent(c.email || c.name)}`, keywords: c.email || '',
        }))).catch(() => []),
        api.get<UserRow[]>('/users').then((r) => (Array.isArray(r.data) ? r.data : []).map((u) => ({
          kind: 'user' as const, title: u.full_name || u.username,
          subtitle: `User · ${u.username}${u.email ? ` · ${u.email}` : ''}`,
          path: `/users?q=${encodeURIComponent(u.username)}`, keywords: `${u.email || ''} ${u.role || ''}`,
        }))).catch(() => []),
      ]
      const loaded = await Promise.all(requests)
      setRecords(loaded.flat())
      setRecordsLoaded(true)
    } finally {
      setSearchLoading(false)
    }
  }

  function goToResult(entry: SearchEntry) {
    setQuery('')
    setSearchOpen(false)
    navigate(entry.path)
  }

  useEffect(() => {
    const handler = (event: Event) => setCurrentTheme((event as CustomEvent<Theme>).detail)
    window.addEventListener('servika:theme-change', handler)
    return () => window.removeEventListener('servika:theme-change', handler)
  }, [])

  // Moving the highlight back to the first hit is a reaction to the query
  // changing, so it is adjusted during render; an effect would paint one frame
  // with the highlight still on a row from the previous result set.
  const [highlightedForQuery, setHighlightedForQuery] = useState(query)
  if (highlightedForQuery !== query) {
    setHighlightedForQuery(query)
    setSelected(0)
  }

  useEffect(() => {
    if (!canSearch) return
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchRef.current?.focus()
        setSearchOpen(true)
        void loadSearchData()
      }
      if (event.key === 'Escape') {
        setSearchOpen(false)
        searchRef.current?.blur()
      }
    }
    function onClickOutside(event: MouseEvent) {
      if (!searchBoxRef.current?.contains(event.target as Node)) setSearchOpen(false)
    }
    window.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClickOutside)
    return () => {
      window.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClickOutside)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canSearch])

  useEffect(() => {
    // The /system/panel-domain endpoint is admin-only; customer sessions would
    // always get a 403, so skip the request entirely for them.
    if (isCustomer) return
    api.get<{ server_ipv4: string }>('/system/panel-domain')
      .then((response) => setServerIp(response.data.server_ipv4 || null))
      // Silent on purpose: a reseller still gets a 403 here, and the server IP
      // is a convenience line in the menu, not something the user asked to see.
      .catch(() => {})
  }, [isCustomer])

  function handleCopyIp() {
    if (!serverIp) return
    copyToClipboard(serverIp)
    setIpCopied(true)
    setTimeout(() => setIpCopied(false), 1800)
  }

  function cycleTheme() {
    const nextTheme: Theme = theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light'
    setTheme(nextTheme)
    setCurrentTheme(nextTheme)
  }

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="h-14 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center px-3 sm:px-4 sticky top-0 z-30 gap-3">
      <button
        type="button"
        onClick={onMenuClick}
        className="lg:hidden p-2 rounded-md text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
        aria-label={t('openNav')}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {canSearch ? (
        <div className="flex-1 min-w-0 max-w-xl" ref={searchBoxRef}>
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              ref={searchRef}
              type="search"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setSearchOpen(true) }}
              onFocus={() => { setSearchOpen(true); void loadSearchData() }}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown') { e.preventDefault(); setSelected((i) => Math.max(0, Math.min(i + 1, results.length - 1))) }
                if (e.key === 'ArrowUp') { e.preventDefault(); setSelected((i) => Math.max(i - 1, 0)) }
                if (e.key === 'Enter' && results[selected]) { e.preventDefault(); goToResult(results[selected]) }
              }}
              placeholder={t('searchPlaceholder')}
              aria-label={t('searchPlaceholder')}
              aria-expanded={searchOpen && !!query.trim()}
              aria-controls="global-search-results"
              className="w-full pl-9 pr-16 py-1.5 text-sm bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg focus:bg-white dark:focus:bg-slate-800 focus:border-brand-400 focus:ring-2 focus:ring-brand-500/15 outline-none transition"
            />
            <span className="hidden sm:block absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-slate-400 dark:text-slate-500 border border-slate-200 dark:border-slate-700 rounded px-1.5 py-0.5 pointer-events-none">Ctrl K</span>
            {searchOpen && query.trim() && (
              <div id="global-search-results" role="listbox" className="absolute top-full left-0 right-0 mt-2 max-h-[min(70vh,32rem)] overflow-y-auto bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl z-50 p-1.5">
                {results.map((entry, i) => (
                  <button
                    key={`${entry.kind}-${entry.path}-${entry.title}`}
                    type="button"
                    role="option"
                    aria-selected={i === selected}
                    onMouseEnter={() => setSelected(i)}
                    onClick={() => goToResult(entry)}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition ${i === selected ? 'bg-brand-50 dark:bg-brand-900/25' : 'hover:bg-slate-50 dark:hover:bg-slate-800'}`}
                  >
                    <span className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 text-sm font-semibold ${
                      entry.kind === 'domain' ? 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300'
                      : entry.kind === 'subdomain' ? 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300'
                      : entry.kind === 'customer' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                      : entry.kind === 'user' ? 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300'
                      : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
                    }`}>{entry.kind === 'domain' ? 'D' : entry.kind === 'subdomain' ? 'S' : entry.kind === 'customer' ? 'C' : entry.kind === 'user' ? 'U' : '↗'}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{entry.title}</span>
                      <span className="block text-xs text-slate-500 dark:text-slate-400 truncate">{entry.subtitle}</span>
                    </span>
                    <span className="text-[10px] uppercase tracking-wide text-slate-400 dark:text-slate-500">{entry.kind}</span>
                  </button>
                ))}
                {searchLoading && <div className="px-3 py-3 text-sm text-slate-500">{t('loadingRecords')}</div>}
                {!searchLoading && results.length === 0 && (
                  <div className="px-3 py-6 text-center text-sm text-slate-500">{t('noResults')}</div>
                )}
              </div>
            )}
          </div>
        </div>
      ) : null}

      <div className="flex-1" />

      <div className="flex items-center justify-end gap-1">
        {serverIp && (
          <button
            onClick={handleCopyIp}
            title={t('copyIp')}
            className="hidden sm:inline-flex items-center gap-1.5 px-2 py-1.5 text-xs font-mono text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition"
          >
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
            {ipCopied ? (
              <span className="text-emerald-600 dark:text-emerald-400 font-sans font-medium">{t('copied')}</span>
            ) : (
              <span>{serverIp}</span>
            )}
          </button>
        )}
        <button onClick={cycleTheme}
          className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition"
          title={t('themeToggle', { theme })}>
          {theme === 'dark' ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
            </svg>
          ) : theme === 'light' ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          )}
        </button>
        <LanguageSwitcher />
        <button className="hidden sm:inline-flex p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition" title={t('notifications')}>
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
        </button>

        <div className="relative">
          <button
            onClick={() => setMenuOpen((value) => !value)}
            aria-label={t('accountMenu')}
            className="flex items-center gap-2 px-1.5 sm:px-2 py-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition"
          >
            <div className="w-7 h-7 rounded-full bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 font-semibold text-xs flex items-center justify-center">
              {(username?.full_name || username?.name || '?').slice(0, 1).toUpperCase()}
            </div>
            <span className="hidden sm:inline text-sm font-medium text-slate-700 dark:text-slate-300 max-w-[180px] truncate">{username?.full_name || username?.name}</span>
            <svg className="w-4 h-4 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {menuOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setMenuOpen(false)} />
              <div className="absolute right-0 mt-1 w-56 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg z-50 py-1">
                <div className="px-3 py-2 border-b border-slate-100 dark:border-slate-800">
                  <div className="text-sm font-medium text-slate-900 dark:text-slate-100">{username?.full_name || username?.name}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-500 capitalize">{username?.role}</div>
                </div>
                <button
                  onClick={() => { setMenuOpen(false); navigate('/profile') }}
                  className="w-full text-left px-3 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  {t('profileMenu')}
                </button>
                <div className="border-t border-slate-100 dark:border-slate-800 my-1"></div>
                <button
                  onClick={handleLogout}
                  className="w-full text-left px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30"
                >
                  {t('logout')}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
