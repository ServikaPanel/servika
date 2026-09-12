import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'
import LanguageSwitcher from '@/components/LanguageSwitcher'

type LoginResponse = {
  // No token here: it is delivered via the HttpOnly servika_session cookie.
  expires_at?: number
  user?: { id: number; name: string; role: 'admin' | 'reseller' | 'user'; full_name?: string }
  two_factor_required?: boolean
}

// internalPath keeps the post-login redirect inside this panel.
//
// The value arrives from the query string, so it is attacker-supplied: anything
// that is not a single-slash absolute path could send someone who just typed
// their password to another site. `//host` and `/\host` are both read as
// protocol-relative by browsers, so neither counts as internal.
function internalPath(next: string | null): string {
  if (!next || !next.startsWith('/')) return '/'
  if (next.startsWith('//') || next.startsWith('/\\')) return '/'
  return next
}

export default function LoginPage() {
  const { t } = useTranslation('LoginPage')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const login = useAuth((state) => state.login)
  const [version, setVersion] = useState('')

  // The footer must never spell a version out. This screen is shown before any
  // session exists, so it cannot use the authenticated version endpoint; it
  // reads /healthz, which needs no auth and reports main.version, the panel's
  // one version source. A literal here (or in the translations) goes stale at
  // the first release nobody remembers to edit, which is exactly what happened.
  useEffect(() => {
    fetch('/healthz', { credentials: 'include' })
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => { if (typeof body?.version === 'string') setVersion(body.version) })
      .catch(() => { /* the footer is decorative; a failed probe just hides it */ })
  }, [])

  // The code is passed in rather than read from state so the auto-submit below
  // can send the digit the visitor just typed instead of waiting a render for
  // the state to catch up.
  async function signIn(submittedCode: string) {
    setError(null); setLoading(true)
    try {
      const { data } = await api.post<LoginResponse>('/auth/login', { username, password, code: submittedCode })
      if (data.two_factor_required) {
        setRequiresTwoFactor(true); setLoading(false)
        return
      }
      login(data.user!, data.expires_at!)
      navigate(internalPath(searchParams.get('next')), { replace: true })
    } catch (caughtError) {
      setError(apiError(caughtError, t('error.loginFailed')))
    } finally {
      setLoading(false)
    }
  }

  function onSubmit(event: React.SubmitEvent) {
    event.preventDefault()
    void signIn(code)
  }

  // A TOTP code is exactly six digits, so the last one is also the visitor's
  // way of saying "go" and pressing the button afterwards adds nothing.
  //
  // This fires from the change handler and NOT from an effect watching the
  // code. An effect would run twice per commit under StrictMode and send the
  // same code twice, and the server accepts a code once: it records the
  // accepted step for replay protection, so the second request comes back as
  // "invalid or reused 2FA code" and a visitor who typed the right code is
  // told it was wrong.
  function onCodeChange(raw: string) {
    const next = raw.replace(/\D/g, '').slice(0, 6)
    setCode(next)
    if (next.length === 6 && !loading) void signIn(next)
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-orange-50 dark:from-slate-950 dark:to-slate-900 px-4">
      {/* The panel opens in whatever the admin set as the server default, and
          before signing in there is no account preference to override it. Without
          a switcher here, someone whose language is not that default has to read
          the sign-in form in a language they may not know in order to reach the
          one inside. */}
      <div className="absolute top-4 right-4">
        <LanguageSwitcher />
      </div>
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-brand-600 flex items-center justify-center shadow-lg shadow-brand-600/30">
            <svg viewBox="0 0 32 32" className="w-7 h-7 text-white" fill="currentColor">
              <path d="M9 10h14v3H9zM9 15h14v3H9zM9 20h9v3H9z" />
            </svg>
          </div>
          <div className="ml-3">
            <div className="text-xl font-semibold text-slate-900 dark:text-slate-100">Servika</div>
            <div className="text-xs text-slate-500 dark:text-slate-500">{t('brand.subtitle')}</div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-700/60 p-8">
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('heading')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">{t('subtitle')}</p>

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('field.username')}</label>
              <input
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                autoFocus
                required
                className="w-full px-3.5 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none transition"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('field.password')}</label>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
                readOnly={requiresTwoFactor}
                className="w-full px-3.5 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none transition disabled:opacity-60"
              />
            </div>

            {requiresTwoFactor && (
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{t('field.twoFactorCode')}</label>
                <input
                  type="text"
                  inputMode="numeric"
                  value={code}
                  onChange={(event) => onCodeChange(event.target.value)}
                  autoFocus
                  placeholder="000000"
                  className="w-full px-3.5 py-2.5 text-center text-lg font-mono tracking-[0.4em] border border-slate-300 dark:border-slate-600 rounded-lg focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none transition"
                />
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-1.5">{t('twoFactorHint')}</p>
              </div>
            )}

            {error && (
              <div className="px-3.5 py-2.5 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 font-medium py-2.5 rounded-lg transition shadow-lg shadow-brand-600/20 disabled:shadow-none"
            >
              {loading ? t('button.signingIn') : requiresTwoFactor ? t('button.verify') : t('button.signIn')}
            </button>
          </form>
        </div>

        {version && (
          <p className="text-center text-xs text-slate-400 dark:text-slate-500 mt-6">
            {t('footer', { version })}
          </p>
        )}
      </div>
    </div>
  )
}
