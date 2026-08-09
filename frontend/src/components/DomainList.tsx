// The domain list component that lived here was removed with its only consumer.
// The Domain shape stays because DomainDashboard and SubscriptionDetailPage type
// their domain props with it.

export type Domain = {
  id: number
  domain_name: string
  php_version: string
  ssl: boolean
  ssl_expiry?: string
  ssl_source?: string
  status: 'active' | 'passive' | string
  suspended?: boolean
  system_user: string
  size_kb: number
  traffic_kb: number
  created_at: string
  ipv4: string
  ftp_host: string
  ftp_user: string
  db_host: string
  db_user: string
  db_name: string
  web_root: string
  notes?: string
  ssh_access?: boolean
  /** True while the site deliberately answers 503 behind a maintenance page. */
  maintenance_enabled?: boolean
}
