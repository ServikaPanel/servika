// Context and hook for the themed dialogs. The provider that draws them is
// components/DialogProvider.tsx; they live apart so that file exports only a
// component and Fast Refresh keeps working.
import { createContext, useContext } from 'react'
import type { ReactNode } from 'react'

interface ConfirmOptions {
  /** Defaults to a generic "Are you sure?" so a bare confirm(message) converts unchanged. */
  title?: string
  message?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  dangerous?: boolean
}

export interface AskOptions extends ConfirmOptions {
  defaultValue?: string
  placeholder?: string
  type?: 'text' | 'password'
}

export interface NotifyOptions {
  title?: string
  message?: ReactNode
  tone?: 'info' | 'error'
}

export interface DialogAPI {
  confirm: (options: ConfirmOptions) => Promise<boolean>
  ask: (options: AskOptions) => Promise<string | null>
  notify: (options: NotifyOptions) => Promise<void>
}

export const DialogContext = createContext<DialogAPI | null>(null)

/**
 * Returns the dialog API. Throws when no provider is mounted.
 *
 * Falling back to the native boxes here would defeat the whole point: they are
 * what this replaces, and a silent fallback would also hide the missing
 * provider. The throw lands in ErrorBoundary, which says so on screen.
 */
export function useDialog(): DialogAPI {
  const api = useContext(DialogContext)
  if (!api) throw new Error('useDialog was called outside DialogProvider')
  return api
}
