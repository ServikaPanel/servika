import { lazy } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router'
import { useAuth } from '@/store/auth'
import LoginPage from '@/pages/LoginPage'
import DashboardLayout from '@/components/DashboardLayout'
import ErrorBoundary from '@/components/ErrorBoundary'
import CustomerLoginPage from '@/pages/CustomerLoginPage'

// The login shell is small and needed on the first screen; every panel page is
// downloaded only when its route opens. This keeps heavy dependencies (file
// manager, code editor, charts) out of the initial panel bundle.
const HomePage = lazy(() => import('@/pages/HomePage'))
const DomainsPage = lazy(() => import('@/pages/DomainsPage'))
const SubscriptionDetailPage = lazy(() => import('@/pages/SubscriptionDetailPage'))
const ServicePlansPage = lazy(() => import('@/pages/ServicePlansPage'))
const SettingsPage = lazy(() => import('@/pages/SettingsPage'))
const ToolPage = lazy(() => import('@/pages/ToolPage'))
const DomainFilesPage = lazy(() => import('@/pages/DomainFilesPage'))
const DomainSSLPage = lazy(() => import('@/pages/DomainSSLPage'))
const DomainSSHPage = lazy(() => import('@/pages/DomainSSHPage'))
const DomainStatsPage = lazy(() => import('@/pages/DomainStatsPage'))
const DomainPerformancePage = lazy(() => import('@/pages/DomainPerformancePage'))
const DomainComposerPage = lazy(() => import('@/pages/DomainComposerPage'))
const DomainPasswordProtectPage = lazy(() => import('@/pages/DomainPasswordProtectPage'))
const DomainAntivirusPage = lazy(() => import('@/pages/DomainAntivirusPage'))
const DomainCopyPage = lazy(() => import('@/pages/DomainCopyPage'))
const DomainImportPage = lazy(() => import('@/pages/DomainImportPage'))
const DomainCronPage = lazy(() => import('@/pages/DomainCronPage'))
const DomainAppsPage = lazy(() => import('@/pages/DomainAppsPage'))
const DomainLogsPage = lazy(() => import('@/pages/DomainLogsPage'))
const DomainDNSPage = lazy(() => import('@/pages/DomainDNSPage'))
const RedisPage = lazy(() => import('@/pages/RedisPage'))
const DomainConnectionPage = lazy(() => import('@/pages/DomainConnectionPage'))
const DomainDatabasesPage = lazy(() => import('@/pages/DomainDatabasesPage'))
const DomainDatabaseDetailPage = lazy(() => import('@/pages/DomainDatabaseDetailPage'))
const DomainFTPPage = lazy(() => import('@/pages/DomainFTPPage'))
const DomainMailPage = lazy(() => import('@/pages/DomainMailPage'))
const DomainMailboxPage = lazy(() => import('@/pages/DomainMailboxPage'))
const DomainMailReportsPage = lazy(() => import('@/pages/DomainMailReportsPage'))
const DomainPHPPage = lazy(() => import('@/pages/DomainPHPPage'))
const DomainBackupsPage = lazy(() => import('@/pages/DomainBackupsPage'))
const DomainGitPage = lazy(() => import('@/pages/DomainGitPage'))
const DomainWebServerPage = lazy(() => import('@/pages/DomainWebServerPage'))
const DomainLaravelPage = lazy(() => import('@/pages/DomainLaravelPage'))
const DomainWafPage = lazy(() => import('@/pages/DomainWafPage'))
const PHPExtensionsPage = lazy(() => import('@/pages/PHPExtensionsPage'))
const PackagesPage = lazy(() => import('@/pages/PackagesPage'))
const PackageDetailPage = lazy(() => import('@/pages/PackageDetailPage'))
const PHPVersionsPage = lazy(() => import('@/pages/PHPVersionsPage'))
const RuntimeVersionsPage = lazy(() => import('@/pages/RuntimeVersionsPage'))
const ToolsSettingsPage = lazy(() => import('@/pages/ToolsSettingsPage'))
const PanelUpdatePage = lazy(() => import('@/pages/PanelUpdatePage'))
const ServerOptimizePage = lazy(() => import('@/pages/ServerOptimizePage'))
const ServerIPsPage = lazy(() => import('@/pages/ServerIPsPage'))
const PanelPortPage = lazy(() => import('@/pages/PanelPortPage'))
const HostAppsPage = lazy(() => import('@/pages/HostAppsPage'))
const DNSTemplatePage = lazy(() => import('@/pages/DNSTemplatePage'))
const BannedDomainsPage = lazy(() => import('@/pages/BannedDomainsPage'))
const WebsiteSecurityPage = lazy(() => import('@/pages/WebsiteSecurityPage'))
const MalwareScanPage = lazy(() => import('@/pages/MalwareScanPage'))
const AttackChainsPage = lazy(() => import('@/pages/AttackChainsPage'))
const NotificationsPage = lazy(() => import('@/pages/NotificationsPage'))
const DomainSiteSecurityPage = lazy(() => import('@/pages/DomainSiteSecurityPage'))
const AdminDomainSecurityPage = lazy(() => import('@/pages/AdminDomainSecurityPage'))
const DomainAppInstallerPage = lazy(() => import('@/pages/DomainAppInstallerPage'))
const AppCatalogPage = lazy(() => import('@/pages/AppCatalogPage'))
const WordPressPage = lazy(() => import('@/pages/WordPressPage'))
const FirewallPage = lazy(() => import('@/pages/FirewallPage'))
const BackupManagementPage = lazy(() => import('@/pages/BackupManagementPage'))
const BackupJobDetailPage = lazy(() => import('@/pages/BackupJobDetailPage'))
const DomainWordPressPage = lazy(() => import('@/pages/DomainWordPressPage'))
const DomainSubdomainsPage = lazy(() => import('@/pages/DomainSubdomainsPage'))
const DomainSubdomainPage = lazy(() => import('@/pages/DomainSubdomainPage'))
const DomainAddonDomainsPage = lazy(() => import('@/pages/DomainAddonDomainsPage'))
const DomainAccessControlPage = lazy(() => import('@/pages/DomainAccessControlPage'))
const DomainMaintenancePage = lazy(() => import('@/pages/DomainMaintenancePage'))
const StatisticsPage = lazy(() => import('@/pages/StatisticsPage'))
const MonitoringPage = lazy(() => import('@/pages/MonitoringPage'))
const DnsOverviewPage = lazy(() => import('@/pages/DnsOverviewPage'))
const SslOverviewPage = lazy(() => import('@/pages/SslOverviewPage'))
const MailOverviewPage = lazy(() => import('@/pages/MailOverviewPage'))
const DatabasesOverviewPage = lazy(() => import('@/pages/DatabasesOverviewPage'))
const CustomersPage = lazy(() => import('@/pages/CustomersPage'))
const AccountTransferPage = lazy(() => import('@/pages/AccountTransferPage'))
const SiteMigrationPage = lazy(() => import('@/pages/SiteMigrationPage'))
const AuditLogPage = lazy(() => import('@/pages/AuditLogPage'))
const UsersPage = lazy(() => import('@/pages/UsersPage'))
const ServerStatusPage = lazy(() => import('@/pages/ServerStatusPage'))
const ServicesPage = lazy(() => import('@/pages/ServicesPage'))
const ComingSoonPage = lazy(() => import('@/pages/ComingSoonPage'))

function GuardedRoute({ children }: { children: React.ReactNode }) {
  // The token is in an HttpOnly cookie the SPA cannot read; a stored non-expired
  // user (set at login) is the synchronous "authenticated" signal. If the cookie
  // is actually gone, the first API call 401s and the interceptor logs out.
  const username = useAuth((s) => s.username)
  const location = useLocation()
  if (!username) {
    // Carry the page that was asked for, so signing in lands there instead of on
    // the dashboard. A bookmark or a shared deep link is otherwise lost the
    // moment the session is gone.
    const wanted = location.pathname + location.search
    const next = wanted && wanted !== '/' ? `?next=${encodeURIComponent(wanted)}` : ''
    return <Navigate to={`/login${next}`} replace />
  }
  return <>{children}</>
}

export default function App() {
  return (
    <ErrorBoundary>
    <Routes>
      <Route path="/login" element={<LoginPage />} />
        <Route path="/cp/login" element={<CustomerLoginPage />} />
        <Route path="/cp" element={<CustomerLoginPage />} />
      <Route
        path="/"
        element={
          <GuardedRoute>
            <DashboardLayout />
          </GuardedRoute>
        }
      >
        <Route index                       element={<HomePage />} />
        <Route path="domains"            element={<DomainsPage />} />
        <Route path="subscriptions"          element={<Navigate to="/domains" replace />} />
        <Route path="subscriptions/:id"      element={<SubscriptionDetailPage />} />
        <Route path="subscriptions/:id/connection"      element={<DomainConnectionPage />} />
        <Route path="subscriptions/:id/files"      element={<DomainFilesPage />} />
        <Route path="subscriptions/:id/databases" element={<DomainDatabasesPage />} />
        <Route path="subscriptions/:id/databases/:dbid" element={<DomainDatabaseDetailPage />} />
        <Route path="subscriptions/:id/ftp"           element={<DomainFTPPage />} />
        <Route path="subscriptions/:id/php"           element={<DomainPHPPage />} />
        <Route path="subscriptions/:id/ssl"           element={<DomainSSLPage />} />
        <Route path="subscriptions/:id/ssh-access"    element={<DomainSSHPage />} />
        <Route path="subscriptions/:id/stats"    element={<DomainStatsPage />} />
        <Route path="subscriptions/:id/performance"    element={<DomainPerformancePage />} />
        <Route path="subscriptions/:id/composer"      element={<DomainComposerPage />} />
        <Route path="subscriptions/:id/password-protection"  element={<DomainPasswordProtectPage />} />
        <Route path="subscriptions/:id/imunify"       element={<DomainAntivirusPage />} />
        <Route path="subscriptions/:id/site-security" element={<DomainSiteSecurityPage />} />
        <Route path="subscriptions/:id/app-installer" element={<DomainAppInstallerPage />} />
        <Route path="subscriptions/:id/copy"       element={<DomainCopyPage />} />
        <Route path="subscriptions/:id/import"     element={<DomainImportPage />} />
        <Route path="subscriptions/:id/wordpress"     element={<DomainWordPressPage />} />
        <Route path="subscriptions/:id/subdomains"  element={<DomainSubdomainsPage />} />
        <Route path="subscriptions/:id/addon-domains" element={<DomainAddonDomainsPage />} />
        {/* Subdomain-scoped tools. The :sid segment switches useResourceScope to the
            subdomain's own document root, so each page reuses the domain component. */}
        <Route path="domains/:id/subdomain/:sid"              element={<DomainSubdomainPage />} />
        <Route path="domains/:id/subdomain/:sid/wordpress"    element={<DomainWordPressPage />} />
        <Route path="domains/:id/subdomain/:sid/logs"         element={<DomainLogsPage />} />
        <Route path="domains/:id/subdomain/:sid/composer"     element={<DomainComposerPage />} />
        <Route path="domains/:id/subdomain/:sid/protection"   element={<DomainPasswordProtectPage />} />
        <Route path="domains/:id/subdomain/:sid/statistics"   element={<DomainStatsPage />} />
        <Route path="domains/:id/subdomain/:sid/php"          element={<DomainPHPPage />} />
        <Route path="domains/:id/subdomain/:sid/web-server"   element={<DomainWebServerPage />} />
        <Route path="subscriptions/:id/access-control" element={<DomainAccessControlPage />} />
        <Route path="subscriptions/:id/maintenance" element={<DomainMaintenancePage />} />
        <Route path="subscriptions/:id/cron"          element={<DomainCronPage />} />
        <Route path="subscriptions/:id/apps"          element={<DomainAppsPage />} />
        <Route path="subscriptions/:id/logs"     element={<DomainLogsPage />} />
        <Route path="subscriptions/:id/dns"           element={<DomainDNSPage />} />
        <Route path="subscriptions/:id/redis"         element={<RedisPage />} />
        <Route path="subscriptions/:id/mail"          element={<DomainMailPage />} />
        <Route path="subscriptions/:id/mail/reports"  element={<DomainMailReportsPage />} />
        <Route path="subscriptions/:id/mail/:mid"     element={<DomainMailboxPage />} />
        <Route path="subscriptions/:id/backups"      element={<DomainBackupsPage />} />
        <Route path="subscriptions/:id/git"           element={<DomainGitPage />} />
        <Route path="subscriptions/:id/laravel"       element={<DomainLaravelPage />} />
        <Route path="subscriptions/:id/web-server"    element={<DomainWebServerPage />} />
        <Route path="subscriptions/:id/waf"           element={<DomainWafPage />} />
        <Route path="system/php-modules"           element={<PHPExtensionsPage />} />
        <Route path="tools/packages"               element={<PackagesPage />} />
        <Route path="tools/packages/:id"           element={<PackageDetailPage />} />
        <Route path="tools/php-versions"           element={<PHPVersionsPage />} />
        <Route path="tools/app-runtimes"           element={<RuntimeVersionsPage />} />
        <Route path="tools/services"               element={<ServicesPage />} />
        <Route path="tools/dns-template"           element={<DNSTemplatePage />} />
        <Route path="tools/banned-domains"           element={<BannedDomainsPage />} />
        <Route path="site-security"                  element={<WebsiteSecurityPage />} />
        <Route path="site-security/domain/:id"        element={<AdminDomainSecurityPage />} />
        <Route path="malware-scan"                   element={<MalwareScanPage />} />
        <Route path="attack-chains"                  element={<AttackChainsPage />} />
        <Route path="notifications"                  element={<NotificationsPage />} />
        <Route path="tools/app-catalog"               element={<AppCatalogPage />} />
        <Route path="subscriptions/:id/:slug" element={<ToolPage />} />
        <Route path="service-plans"      element={<ServicePlansPage />} />

        <Route path="tools-settings" element={<ToolsSettingsPage />} />
        <Route path="tools/update" element={<PanelUpdatePage />} />
        <Route path="tools/optimize" element={<ServerOptimizePage />} />
        <Route path="tools/server-ips" element={<ServerIPsPage />} />
        <Route path="tools/panel-port" element={<PanelPortPage />} />
        <Route path="tools/host-apps" element={<HostAppsPage />} />
        <Route path="statistics" element={<StatisticsPage />} />
        <Route path="extensions" element={<ComingSoonPage title="Extensions" icon="🧩" description="Third-party extension management for the panel" features={["Browse the marketplace", "One-click install and removal", "Version updates", "API integration", "Developer SDK"]} />} />
        <Route path="wordpress" element={<WordPressPage />} />
        <Route path="firewall" element={<FirewallPage />} />
        <Route path="backup-management" element={<BackupManagementPage />} />
        <Route path="backup-management/job/:jid" element={<BackupJobDetailPage />} />
        <Route path="monitoring" element={<MonitoringPage />} />

        <Route path="dns"        element={<DnsOverviewPage />} />
        <Route path="ssl"        element={<SslOverviewPage />} />
        <Route path="mail"       element={<MailOverviewPage />} />
        <Route path="databases"  element={<DatabasesOverviewPage />} />
        <Route path="customers"  element={<CustomersPage />} />
        <Route path="account-transfer" element={<AccountTransferPage />} />
        <Route path="site-migration" element={<SiteMigrationPage />} />
        <Route path="audit-log"  element={<AuditLogPage />} />
        <Route path="users"         element={<UsersPage />} />
        <Route path="server-status" element={<ServerStatusPage />} />

        <Route path="profile"          element={<SettingsPage />} />
        <Route path="change-password" element={<Navigate to="/profile" replace />} />
        <Route path="settings"         element={<Navigate to="/profile" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
    </ErrorBoundary>
  )
}
