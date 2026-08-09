import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { Domain } from './DomainList'
import { sslState } from '@/lib/ssl'
import ToolCard from './ToolCard'

const ICONS = {
  connection:  'M13.828 10.172a4 4 0 015.656 5.656l-3 3a4 4 0 01-5.656-5.656m.172-5.172a4 4 0 00-5.656 5.656l-3 3a4 4 0 005.656 5.656',
  files:  'M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z',
  db:        'M4 7c0-1.657 3.582-3 8-3s8 1.343 8 3-3.582 3-8 3-8-1.343-8-3zm0 0v10c0 1.657 3.582 3 8 3s8-1.343 8-3V7M4 12c0 1.657 3.582 3 8 3s8-1.343 8-3',
  ftp:       'M3 16V8a2 2 0 012-2h6l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2zM9 12l3-3 3 3M12 9v6',
  backup:    'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1M16 12l-4 4-4-4M12 16V4',
  copy:      'M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z',
  php:       'M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z',
  log:       'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  cron:      'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  apps:      'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2',
  navigateTo:       'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1',
  composer:  'M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3v6M9 12h6',
  service:   'M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4',
  ssl:       'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  lock:      'M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3',
  stats:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  imunify:   'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622',
  ssh:       'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
  wordpress: 'M12 21a9 9 0 100-18 9 9 0 000 18zm0 0c2.5-2.5 3-6 3-9s-.5-6.5-3-9m0 18c-2.5-2.5-3-6-3-9s.5-6.5 3-9M3.6 9h16.8M3.6 15h16.8',
  laravel:   'M12 3l8 4v10l-8 4-8-4V7l8-4zm0 2.2L6 8.2v7.6l6 3 6-3V8.2l-6-3zM8 9h2v5h4v2H8V9z',
  subdomain: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064',
  addonDomain: 'M4 5a2 2 0 012-2h5l2 2h5a2 2 0 012 2v3M4 5v12a2 2 0 002 2h5m9-9v7a2 2 0 01-2 2h-5m0 0l3-3m-3 3l3 3',
  accessControl: 'M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z',
  dns:       'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
  redis:     'M13 10V3L4 14h7v7l9-11h-7z',
  mail:      'M3 8l9 6 9-6m-9 6V4m0 0v16',
  maintenance: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5 last:mb-0">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-500 mb-2">{title}</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">{children}</div>
    </section>
  )
}

export default function DomainDashboard({ domain }: { domain: Domain }) {
  const navigate = useNavigate()
  const { t } = useTranslation('DomainDashboard')
  const navigateTo = (slug: string) => () => navigate(`/subscriptions/${domain.id}/${slug}`)
  return (
    <div>
      <Group title={t('groups.applications')}>
        <ToolCard label={t('wordpress.label')} description={t('wordpress.desc')} icon={ICONS.wordpress} color="sky" onClick={navigateTo('wordpress')} />
        <ToolCard label={t('laravel.label')} description={t('laravel.desc')} icon={ICONS.laravel} color="emerald" onClick={navigateTo('laravel')} />
      </Group>

      <Group title={t('groups.domainAndDns')}>
        <ToolCard label={t('dns.label')}          description={t('dns.desc')} icon={ICONS.dns}       color="sky"  onClick={navigateTo('dns')} />
        <ToolCard label={t('subdomains.label')}          description={t('subdomains.desc')}   icon={ICONS.subdomain} color="teal" onClick={navigateTo('subdomains')} />
        <ToolCard label={t('addonDomains.label')} description={t('addonDomains.desc')} icon={ICONS.addonDomain} color="indigo" onClick={navigateTo('addon-domains')} />
      </Group>

      <Group title={t('groups.email')}>
        <ToolCard label={t('mail.label')} description={t('mail.desc')} icon={ICONS.mail} color="indigo" onClick={navigateTo('mail')} />
        <ToolCard label={t('mailReports.label')} description={t('mailReports.desc')} icon={ICONS.stats} color="sky" onClick={navigateTo('mail/reports')} />
      </Group>

      <Group title={t('groups.filesAndDatabases')}>
        <ToolCard label={t('connection.label')}      description={t('connection.desc')}  icon={ICONS.connection} color="emerald" onClick={navigateTo('connection')} />
        <ToolCard label={t('files.label')}              description={t('files.desc')}  icon={ICONS.files} color="amber"   phase="F6"  onClick={navigateTo('files')} />
        <ToolCard label={t('databases.label')}         description={domain.db_name}     icon={ICONS.db}       color="violet"  phase="F5"  onClick={navigateTo('databases')} />
        <ToolCard label={t('ftp.label')}                   description={t('ftp.desc')}     icon={ICONS.ftp}      color="sky"     phase="F4"  onClick={navigateTo('ftp')} />
        <ToolCard label={t('backups.label')} description={t('backups.desc')}    icon={ICONS.backup}    color="rose"    phase="F12" onClick={navigateTo('backups')} />
        <ToolCard label={t('copy.label')}  description={t('copy.desc')}          icon={ICONS.copy}    color="sky"     onClick={navigateTo('copy')} />
      </Group>

      <Group title={t('groups.developmentTools')}>
        <ToolCard label={t('php.label')}                   description={t('php.desc', { version: domain.php_version })} icon={ICONS.php}      color="indigo" phase="F3" onClick={navigateTo('php')} />
        <ToolCard label={t('logs.label')}             description={t('logs.desc')}  icon={ICONS.log}      color="slate"  phase="F10" onClick={navigateTo('logs')} />
        <ToolCard label={t('cron.label')}  description={t('cron.desc')}            icon={ICONS.cron}     color="teal"   phase="F8"  onClick={navigateTo('cron')} />
        <ToolCard label={t('apps.label')}  description={t('apps.desc')}            icon={ICONS.apps}     color="violet" onClick={navigateTo('apps')} />
        <ToolCard label={t('git.label')}                   description={t('git.desc')} icon={ICONS.navigateTo}    color="orange" phase="F9"  onClick={navigateTo('git')} />
        <ToolCard label={t('composer.label')}          description={t('composer.desc')}  icon={ICONS.composer} color="amber" phase="F3"  onClick={navigateTo('composer')} />
        <ToolCard label={t('performance.label')}            description={t('performance.desc')}   icon={ICONS.service} color="emerald" onClick={navigateTo('performance')} />
        <ToolCard label={t('redis.label')}           description={t('redis.desc')} icon={ICONS.redis} color="rose" onClick={navigateTo('redis')} />
      </Group>

      <Group title={t('groups.security')}>
        {/* The self-signed fail-safe gets its own state rather than the green
            a real CA earns: it encrypts and still leaves every visitor on a
            browser warning page, so it carries a warning of its own here. */}
        <ToolCard
          label={t('ssl.label')}
          description={sslState(domain.ssl, domain.ssl_source) === 'trusted'
            ? t('ssl.expires', { expiry: domain.ssl_expiry || '—' })
            : sslState(domain.ssl, domain.ssl_source) === 'selfSigned'
              ? t('ssl.selfSigned')
              : t('ssl.letsEncrypt')}
          icon={ICONS.ssl}
          color={sslState(domain.ssl, domain.ssl_source) === 'trusted' ? 'emerald'
            : sslState(domain.ssl, domain.ssl_source) === 'selfSigned' ? 'amber' : 'rose'}
          phase="F7"
          warning={sslState(domain.ssl, domain.ssl_source) === 'none' ? t('ssl.warning')
            : sslState(domain.ssl, domain.ssl_source) === 'selfSigned' ? t('ssl.selfSignedWarning') : undefined}
          onClick={navigateTo('ssl')}
        />
        <ToolCard label={t('passwordProtection.label')} description={t('passwordProtection.desc')}       icon={ICONS.lock}      color="amber" phase="F7" onClick={navigateTo('password-protection')} />
        <ToolCard label={t('stats.label')}            description={t('stats.desc')}  icon={ICONS.stats} color="indigo" phase="F10" onClick={navigateTo('stats')} />
        <ToolCard label={t('accessControl.label')} description={t('accessControl.desc')} icon={ICONS.accessControl} color="rose" onClick={navigateTo('access-control')} />
        <ToolCard
          label={t('maintenance.label')}
          description={domain.maintenance_enabled ? t('maintenance.on') : t('maintenance.desc')}
          icon={ICONS.maintenance}
          color={domain.maintenance_enabled ? 'amber' : 'slate'}
          warning={domain.maintenance_enabled ? t('maintenance.warning') : undefined}
          onClick={navigateTo('maintenance')}
        />
        <ToolCard label={t('imunify.label')}                  description={t('imunify.desc')}        icon={ICONS.imunify}    color="emerald" onClick={navigateTo('imunify')} />
        <ToolCard
          label={t('ssh.label')}
          description={domain.ssh_access ? t('ssh.enabled') : t('ssh.disabled')}
          icon={ICONS.ssh}
          color={domain.ssh_access ? 'emerald' : 'slate'}
          onClick={navigateTo('ssh-access')}
        />
      </Group>
    </div>
  )
}