import axios, { AxiosError } from 'axios'
import { useAuth } from '@/store/auth'

const baseURL = (import.meta.env.VITE_API_BASE as string) || '/api/v1'

export const api = axios.create({
  baseURL,
  timeout: 30_000,
  // The session is carried by the HttpOnly servika_session cookie; send it on
  // every request (same-origin in production, proxied same-origin in dev).
  withCredentials: true,
})

api.interceptors.response.use(
  (r) => r,
  (err: AxiosError<{ error?: string }>) => {
    if (err.response?.status === 401) {
      const s = useAuth.getState()
      if (s.username) s.logout()
    }
    return Promise.reject(err)
  },
)

export function apiError(err: unknown, fallback = 'An unexpected error occurred'): string {
  const error = err as AxiosError<{ error?: string }>
  if (error?.response?.data?.error) return error.response.data.error
  if (error?.message) return error.message
  return fallback
}

/**
 * Returns the stable reason CODE some endpoints send beside the message.
 *
 * The message is English because the API is; the code is what a screen maps to
 * a sentence in the reader's own language. A screen that renders `apiError`
 * alone shows English to a Japanese reader, which is why this exists.
 */
export function apiReason(err: unknown): string {
  const error = err as AxiosError<{ reason?: string }>
  return error?.response?.data?.reason || ''
}
