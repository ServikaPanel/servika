// Shared database row shape and size formatter, used by the domain database
// list and each database's detail page. They live here rather than on the list
// page so neither page mixes a component export with a value export, which the
// react-refresh lint rule forbids.

export type DB = {
  id: number; domain_id: number; db_name: string; db_user: string;
  db_host: string; db_pass: string; created_at: string; size: number
}

// Human-readable byte size. An unknown size (0, or a size query that failed on
// the server) renders as a dash rather than "0 B".
export function formatBytes(b: number): string {
  if (!b || b <= 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = b
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}
