// Which detector produced a finding, and what the screen may offer for it.
//
// Containment is a copy out of the tenant home followed by a removal, so a
// finding whose subject is not a file has nothing to act on and the server
// refuses it with `av_finding_is_not_a_file`. A screen that drew the button
// anyway would offer an action that can only fail, which is worse than not
// offering it: the operator reads the failure as a fault on their server.
//
// The value mirrors `antivirus.EngineDatabase` in Go. It is written once here
// rather than inline on each page, because the same question is asked on the
// admin screen and on the per-domain one.
export const ENGINE_DATABASE = 'database'

export function containable(engine: string): boolean {
  return engine !== ENGINE_DATABASE
}
