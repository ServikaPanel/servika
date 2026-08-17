import { Suspense, useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import MobileNavBar from './MobileNavBar'
import ErrorSurface from './ErrorSurface'
import TopBar from './TopBar'
import DomainPicker from './DomainPicker'
import { api } from '@/lib/api'
import { useAuth } from '@/store/auth'

type VersionFooter = { current?: string; build_date?: string }

// `labelKey`/`titleKey` are stable identifiers resolved to display text via the
// DashboardLayout namespace. `titleKey` also serves as the openGroups state key,
// so collapse state survives a language switch.
type NavItem = { to: string; labelKey: string; icon: string }
type NavGroup = { titleKey?: string; items: NavItem[] }

const ICONS = {
  home:        'M3 12l2-2 7-7 7 7 2 2v8a2 2 0 01-2 2h-3v-7H10v7H7a2 2 0 01-2-2v-8z',
  customer:    'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
  reseller:    'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z',
  domain:      'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  subscription: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
  plan:        'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  tools:     'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.827 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.99.601 2.295.247 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z',
  stats:  'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  extensions:  'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
  wp:          'M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 18a8 8 0 110-16 8 8 0 010 16z',
  monitoring:      'M3 12l3-3 3 6 4-9 3 6h5',
  profile:      'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
  lock:        'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  firewall:    'M9 12l2 2 4-4m3 2c0 6-8 10-8 10S4 18 4 12V5l8-3 8 3v7z',
  update:      'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  optimize:    'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4',
  mail:        'M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
  database:    'M4 7v10c0 2 4 3 8 3s8-1 8-3V7M4 7c0 2 4 3 8 3s8-1 8-3M4 7c0-2 4-3 8-3s8 1 8 3',
  audit:       'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  transfer:    'M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0 0l-4-4m4 4l4-4',
}

const NAV: NavGroup[] = [
  { items: [{ to: '/', labelKey: 'home', icon: ICONS.home }] },
  { titleKey: 'hostingServices', items: [
    { to: '/domains',           labelKey: 'domains',        icon: ICONS.domain },
    { to: '/service-plans',     labelKey: 'servicePlans',  icon: ICONS.plan },
    { to: '/customers',         labelKey: 'customers',      icon: ICONS.customer },
    { to: '/account-transfer',  labelKey: 'accountTransfer', icon: ICONS.transfer },
    { to: '/site-migration',    labelKey: 'siteMigration',   icon: ICONS.transfer },
  ]},
  { titleKey: 'serverOverview', items: [
    { to: '/dns',              labelKey: 'dns',   icon: ICONS.domain },
    { to: '/ssl',              labelKey: 'ssl', icon: ICONS.lock },
    { to: '/mail',             labelKey: 'mail',   icon: ICONS.mail },
    { to: '/databases',        labelKey: 'databases',        icon: ICONS.database },
  ]},
  { titleKey: 'serverManagement', items: [
    { to: '/tools-settings',     labelKey: 'toolsSettings', icon: ICONS.tools },
    { to: '/tools/optimize',   labelKey: 'optimize',      icon: ICONS.optimize },
    { to: '/tools/server-ips', labelKey: 'serverIPs',     icon: ICONS.monitoring },
    { to: '/tools/panel-port', labelKey: 'panelPort',     icon: ICONS.tools },
    { to: '/statistics',       labelKey: 'statistics',      icon: ICONS.stats },
    { to: '/extensions',          labelKey: 'extensions',         icon: ICONS.extensions },
    { to: '/wordpress',           labelKey: 'wordpress',          icon: ICONS.wp },
    { to: '/firewall',            labelKey: 'firewall',    icon: ICONS.firewall },
    { to: '/monitoring',              labelKey: 'monitoring',             icon: ICONS.monitoring },
    { to: '/users',                   labelKey: 'users',                  icon: ICONS.reseller },
    { to: '/audit-log',               labelKey: 'auditLog',           icon: ICONS.audit },
  ]},
  { titleKey: 'myProfile', items: [
    { to: '/profile',              labelKey: 'profile', icon: ICONS.profile },
  ]},
]

// Reseller menu — ONLY the places a reseller can actually reach.
//
// Every link here maps to an endpoint a reseller is now authorized for: its own
// accounts and customer records, the server-wide hosting lists (scoped to its
// own customers by ScopeSQL), plus read-only server status. Nothing here 403s
// for a reseller; admin-only screens stay out of the list.
const RESELLER_NAV: NavGroup[] = [
  { items: [{ to: '/', labelKey: 'home', icon: ICONS.home }] },
  { titleKey: 'myAccounts', items: [
    { to: '/users',      labelKey: 'customerAccounts', icon: ICONS.customer },
    { to: '/customers',  labelKey: 'customerRecords',  icon: ICONS.subscription },
  ]},
  { titleKey: 'hosting', items: [
    { to: '/domains',    labelKey: 'domains',           icon: ICONS.domain },
    { to: '/dns',        labelKey: 'dns',     icon: ICONS.domain },
    { to: '/ssl',        labelKey: 'ssl',   icon: ICONS.lock },
    { to: '/mail',       labelKey: 'mail',     icon: ICONS.mail },
    { to: '/databases',  labelKey: 'databases',          icon: ICONS.database },
    { to: '/wordpress',  labelKey: 'wordpress',          icon: ICONS.wp },
  ]},
  { titleKey: 'server', items: [
    { to: '/server-status',  labelKey: 'serverStatus',  icon: ICONS.monitoring },
    { to: '/service-plans',  labelKey: 'servicePlans',  icon: ICONS.plan },
  ]},
]

// Domain-mode menu — when an admin is under /subscriptions/:id/* the whole
// sidebar becomes that domain's tool menu, topped by the DomainPicker so the
// same screen can be compared across domains in one click.
function domainNav(id: string): NavGroup[] {
  const s = (sub = '') => `/subscriptions/${id}${sub}`
  return [
    { items: [{ to: s(), labelKey: 'overview', icon: ICONS.home }] },
    { titleKey: 'domain', items: [
      { to: s('/files'), labelKey: 'fileManager', icon: ICONS.domain },
      { to: s('/databases'), labelKey: 'databases', icon: ICONS.plan },
      { to: s('/ftp'), labelKey: 'ftp', icon: ICONS.reseller },
      { to: s('/php'), labelKey: 'php', icon: ICONS.tools },
      { to: s('/web-server'), labelKey: 'webServer', icon: ICONS.tools },
      { to: s('/dns'), labelKey: 'dnsSettings', icon: ICONS.domain },
      { to: s('/ssl'), labelKey: 'sslTls', icon: ICONS.lock },
      { to: s('/mail'), labelKey: 'email', icon: ICONS.mail },
      { to: s('/mail/reports'), labelKey: 'mailReports', icon: ICONS.stats },
      { to: s('/cron'), labelKey: 'scheduledTasks', icon: ICONS.monitoring },
      { to: s('/apps'), labelKey: 'applications', icon: ICONS.extensions },
      { to: s('/git'), labelKey: 'gitDeploy', icon: ICONS.extensions },
      { to: s('/laravel'), labelKey: 'laravel', icon: ICONS.extensions },
      { to: s('/logs'), labelKey: 'logs', icon: ICONS.stats },
      { to: s('/backups'), labelKey: 'backups', icon: ICONS.tools },
      { to: s('/import'), labelKey: 'siteImport', icon: ICONS.tools },
    ]},
  ]
}

function SidebarNav({ groups, openGroups, onToggle, onNavigate, topSlot, t }: {
  groups: NavGroup[]
  openGroups: Record<string, boolean>
  onToggle: (title: string) => void
  onNavigate?: () => void
  topSlot?: ReactNode
  t: TFunction
}) {
  return (
    <>
      <div className="h-14 flex items-center px-5 border-b border-slate-200 dark:border-slate-800">
        <div className="w-8 h-8 rounded-md bg-brand-600 flex items-center justify-center mr-2.5 shadow-sm shadow-brand-600/40">
          <svg viewBox="0 0 32 32" className="w-4 h-4 text-white" fill="currentColor">
            <path d="M9 10h14v3H9zM9 15h14v3H9zM9 20h9v3H9z" />
          </svg>
        </div>
        <span className="text-base font-semibold text-slate-900 dark:text-slate-100">Servika</span>
      </div>

      {topSlot}

      <nav className="flex-1 px-2 py-3 overflow-y-auto">
        {groups.map((group, groupIndex) => (
          <div key={groupIndex} className="mb-2">
            {group.titleKey && (
              <button
                onClick={() => onToggle(group.titleKey!)}
                className="w-full flex items-center justify-between px-3 py-1.5 mt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition"
              >
                <span>{t(`groups.${group.titleKey}`)}</span>
                <svg
                  className={`w-3 h-3 transition-transform ${openGroups[group.titleKey] ? '' : '-rotate-90'}`}
                  fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
            )}
            {(!group.titleKey || openGroups[group.titleKey]) && (
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const hasParentPath = group.items.some(
                    (other) => other.to !== item.to && other.to.startsWith(item.to + '/')
                  )
                  return (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        end={item.to === '/' || hasParentPath}
                        onClick={onNavigate}
                        className={({ isActive }) =>
                          `group relative flex items-center px-3 py-2 lg:py-1.5 rounded-lg text-sm transition-all duration-150 ${
                            isActive
                              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 font-medium shadow-sm dark:shadow-none'
                              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-slate-100'
                          }`
                        }
                      >
                        {({ isActive }) => (
                          <>
                            {isActive && (
                              <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-slate-900 dark:bg-white" aria-hidden />
                            )}
                            <svg className={`w-4 h-4 mr-2.5 flex-shrink-0 transition ${
                              isActive ? 'text-brand-600 dark:text-brand-400' : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:group-hover:text-slate-300'
                            }`} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}>
                              <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                            </svg>
                            <span className="truncate">{t(`nav.${item.labelKey}`)}</span>
                          </>
                        )}
                      </NavLink>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        ))}
      </nav>
    </>
  )
}

export default function DashboardLayout() {
  const { t } = useTranslation('DashboardLayout')
  const isCustomer = useAuth((s) => s.isCustomer)
  const customerDomainID = useAuth((s) => s.customerDomainID)
  const role = useAuth((s) => s.username?.role)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [footer, setFooter] = useState<VersionFooter | null>(null)
  const location = useLocation()

  // /system/version rather than /system/version-check: the latter is
  // ResellerOrAbove, so a customer only ever received a 403 and the footer named
  // the panel with no version after it. The open endpoint answers every signed-in
  // account and carries only this installation's version and build date, never
  // the update state or the announcement, which stay behind the guarded one.
  useEffect(() => {
    api.get<VersionFooter>('/system/version')
      .then((response) => setFooter(response.data))
      // Silent on purpose: the footer version string is decorative. HomePage
      // reports the guarded endpoint, where a failure actually costs the user
      // the update notice.
      .catch(() => {})
  }, [])

  // Keyed by the stable NavGroup.titleKey so collapse state survives a language
  // switch (the visible label changes, the key does not).
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    hostingServices: true,
    serverOverview: true,
    serverManagement: true,
    myProfile: true,
    myDomain: true,
    domain: true,
    myAccounts: true,
    hosting: true,
    server: true,
  })

  // Closing the drawer on navigation is a reaction to a changed value, not a
  // side effect, so it is adjusted during render: an effect would paint one
  // frame of the new route with the drawer still covering it.
  const [drawerPath, setDrawerPath] = useState(location.pathname)
  if (drawerPath !== location.pathname) {
    setDrawerPath(location.pathname)
    setMobileOpen(false)
  }

  useEffect(() => {
    if (!mobileOpen) return
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setMobileOpen(false)
    }
    window.addEventListener('keydown', onKey)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = previousOverflow
    }
  }, [mobileOpen])

  const customerNav: NavGroup[] = [
    { titleKey: 'myDomain', items: [
      { to: `/subscriptions/${customerDomainID}`, labelKey: 'overview', icon: ICONS.home },
      { to: `/subscriptions/${customerDomainID}/files`, labelKey: 'fileManager', icon: ICONS.domain },
      { to: `/subscriptions/${customerDomainID}/databases`, labelKey: 'databases', icon: ICONS.plan },
      { to: `/subscriptions/${customerDomainID}/ftp`, labelKey: 'ftp', icon: ICONS.reseller },
      { to: `/subscriptions/${customerDomainID}/php`, labelKey: 'php', icon: ICONS.tools },
      { to: `/subscriptions/${customerDomainID}/web-server`, labelKey: 'webServer', icon: ICONS.tools },
      { to: `/subscriptions/${customerDomainID}/dns`, labelKey: 'dnsSettings', icon: ICONS.domain },
      { to: `/subscriptions/${customerDomainID}/ssl`, labelKey: 'sslTls', icon: ICONS.lock },
      { to: `/subscriptions/${customerDomainID}/cron`, labelKey: 'scheduledTasks', icon: ICONS.monitoring },
      { to: `/subscriptions/${customerDomainID}/apps`, labelKey: 'applications', icon: ICONS.extensions },
      { to: `/subscriptions/${customerDomainID}/git`, labelKey: 'gitDeploy', icon: ICONS.extensions },
      { to: `/subscriptions/${customerDomainID}/laravel`, labelKey: 'laravel', icon: ICONS.extensions },
      { to: `/subscriptions/${customerDomainID}/logs`, labelKey: 'logs', icon: ICONS.stats },
      { to: `/subscriptions/${customerDomainID}/backups`, labelKey: 'backups', icon: ICONS.tools },
    ]},
  ]

  // Domain mode: while an admin is under /subscriptions/:id/* the sidebar shows
  // that domain's tool menu. Customer sessions keep their fixed single-domain nav.
  const domainMatch = location.pathname.match(/^\/subscriptions\/(\d+)/)
  const activeDomainID = domainMatch ? domainMatch[1] : ''
  const domainMode = !isCustomer && activeDomainID !== ''

  // The menu is derived from the role. isCustomer marks a session opened through
  // the customer portal (/cp); such a session is always role='user', so the two
  // conditions agree and both land on the customer menu. A reseller may also
  // enter domain mode (its own customer's domain); only the customer stays on
  // its fixed menu.
  const activeNav = isCustomer || role === 'user'
    ? customerNav
    : domainMode
    ? domainNav(activeDomainID)
    : role === 'reseller'
    ? RESELLER_NAV
    : NAV
  const mobileItems = isCustomer
    ? [
        { to: `/subscriptions/${customerDomainID}`, label: t('mobile.overview'), icon: ICONS.home, end: true },
        { to: `/subscriptions/${customerDomainID}/files`, label: t('mobile.files'), icon: ICONS.domain },
        { to: `/subscriptions/${customerDomainID}/databases`, label: t('mobile.db'), icon: ICONS.plan },
        { to: `/subscriptions/${customerDomainID}/backups`, label: t('mobile.backups'), icon: ICONS.tools },
      ]
    : [
        { to: '/', label: t('mobile.home'), icon: ICONS.home, end: true },
        { to: '/domains', label: t('mobile.domains'), icon: ICONS.domain },
        { to: '/tools-settings', label: t('mobile.tools'), icon: ICONS.tools },
        { to: '/profile', label: t('mobile.profile'), icon: ICONS.profile },
      ]

  function toggle(title: string) {
    setOpenGroups((state) => ({ ...state, [title]: !state[title] }))
  }

  return (
    <div className="min-h-screen flex items-start bg-slate-50 dark:bg-slate-900">
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden
        />
      )}

      <aside className={`fixed inset-y-0 left-0 z-50 w-72 max-w-[85vw] bg-white dark:bg-slate-950 border-r border-slate-200 dark:border-slate-800 flex flex-col transition-transform duration-200 lg:sticky lg:top-0 lg:h-screen lg:w-56 lg:translate-x-0 lg:flex-shrink-0 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <SidebarNav
          groups={activeNav}
          openGroups={openGroups}
          onToggle={toggle}
          onNavigate={() => setMobileOpen(false)}
          topSlot={domainMode ? <DomainPicker activeID={activeDomainID} /> : undefined}
          t={t}
        />
      </aside>

      <div className="flex-1 flex flex-col min-w-0 pb-16 lg:pb-0">
        <TopBar onMenuClick={() => setMobileOpen(true)} />
        <main className="flex-1 min-w-0 flex flex-col">
          <div className="flex-1 min-w-0">
            <Suspense fallback={
              <div className="px-6 py-10 text-sm text-slate-400 dark:text-slate-500" role="status">
                {t('loadingPage')}
              </div>
            }>
              <Outlet />
            </Suspense>
          </div>
          <footer className="py-4 text-center text-xs text-slate-400 dark:text-slate-600">
            Servika{footer?.current ? ` v${footer.current}` : ''}
            {footer?.build_date ? ` · Build: ${footer.build_date}` : ''}
          </footer>
        </main>
      </div>

      <MobileNavBar items={mobileItems} />
      <ErrorSurface />
    </div>
  )
}
