// The failure line and the success line a settings card draws above its
// controls. Both are drawn in the same place in every card, so they live here:
// a card that inlined them carried two more branches of its own, and the
// complexity gate counts every one of them.

export function FormAlerts({ error, message }: { error?: string; message?: string }) {
  return (
    <>
      {error && <div className="text-sm px-3 py-2 rounded-lg border bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 mb-3">{error}</div>}
      {message && <div className="text-sm px-3 py-2 rounded-lg border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 mb-3">{message}</div>}
    </>
  )
}
