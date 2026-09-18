// One application's live consumption, as either backend reports it.
//
// `uptime_seconds` is a NUMBER rather than a formatted duration, because the
// panel renders twelve languages and a duration written in Go is translated in
// none of them. The formatting lives here.
export type AppMetrics = {
  unit: string
  cgroup?: string
  memory_bytes: number
  memory_peak_bytes: number
  cpu_micros: number
  cpu_percent: number
  tasks: number
  tasks_max: number
  disk_bytes: number
  active_state: string
  sub_state: string
  uptime_seconds: number
  restarts: number
  at: string
}

// One row of the server-wide answer, named by the application it belongs to.
export type HostAppMetrics = AppMetrics & { app_id: number; code: string }

// UNLIMITED is what the backend reports when the cgroup says `max`.
export const UNLIMITED = -1

const UNITS = ['KB', 'MB', 'GB', 'TB']

// formatBytes reads a size the way an operator sizes a disk.
export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${UNITS[unit]}`
}

// formatUptime turns seconds into the largest two units that carry information.
// It takes the unit words from the caller, so the sentence is composed in the
// reader's language rather than here.
export function formatUptime(seconds: number, words: { d: string; h: string; m: string; s: string }): string {
  if (!seconds || seconds < 0) return ''
  if (seconds < 60) return `${seconds}${words.s}`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}${words.m}`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}${words.h} ${minutes - hours * 60}${words.m}`
  const days = Math.floor(hours / 24)
  return `${days}${words.d} ${hours - days * 24}${words.h}`
}

// formatTasks shows the ceiling only when there is one.
export function formatTasks(tasks: number, max: number, unlimited: string): string {
  if (max === UNLIMITED || max <= 0) return `${tasks} / ${unlimited}`
  return `${tasks} / ${max}`
}

// formatPercent keeps one decimal, because an application at 0.4% and one at
// 0% are not the same thing on a shared server.
export function formatPercent(value: number): string {
  if (!value || value < 0) return '0%'
  return `${value.toFixed(1)}%`
}
