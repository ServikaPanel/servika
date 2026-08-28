import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { apiError as apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'
import LanguageSwitcher from '@/components/LanguageSwitcher'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import axios from 'axios'

export default function CustomerLoginPage() {
  const { t } = useTranslation('CustomerLoginPage')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function signIn(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setError(null)
    try {
      // withCredentials lets the browser store the Set-Cookie session cookie.
      const r = await axios.post('/api/v1/customer/login', { username, password }, { withCredentials: true })
      const { expires_at, domain_id, domain_name } = r.data
      // Token lives in the HttpOnly cookie; store only the customer session flags.
      useAuth.getState().loginCustomer(expires_at, domain_id, domain_name, username)
      navigate('/subscriptions/' + domain_id, { replace: true })
      setTimeout(() => window.location.reload(), 100)
    } catch (e) {
      setError(apiError(e, t('error.loginFailed')))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-brand-50 px-4">
      {/* Same reason as the panel sign-in: this is the last screen before any
          account preference exists, so it is the only place the visitor can pick
          a language they can read. */}
      <div className="absolute top-4 right-4">
        <LanguageSwitcher />
      </div>
      <div className="w-full max-w-md bg-white dark:bg-slate-800 rounded-2xl shadow-xl p-7">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 mb-3"><Icon d={ICON.globe} className="h-6 w-6" /></div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">{t('heading')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-500 mt-1">{t('subtitle')}</p>
        </div>

        {error && (
          <div className="mb-4 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>
        )}

        <form onSubmit={signIn} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('field.username')}</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)}
              autoComplete="username" required autoFocus
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm focus:border-brand-500 outline-none" />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('field.password')}</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="current-password" required
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm focus:border-brand-500 outline-none" />
          </div>
          <button type="submit" disabled={loading || !username || !password}
            className="w-full px-4 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 font-medium rounded-md">
            {loading ? t('button.signingIn') : t('button.signIn')}
          </button>
        </form>
      </div>
    </div>
  )
}