import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import PanelDomain from '@/components/PanelDomain'
import HostnameSetting from '@/components/HostnameSetting'
import NameserverSetting from '@/components/NameserverSetting'
import ServerRebootButton from '@/components/ServerRebootButton'
import SessionIdleSetting from '@/components/SessionIdleSetting'
import Breadcrumb from '@/components/Breadcrumb'
import { useAuth } from '@/store/auth'
import { setTheme as applyThemePreference, type Theme } from '@/lib/theme'
import { setLang, LANGS, LANG_NAMES, type Lang } from '@/lib/i18n'

type CurrentUser = {
  id: number; name: string; role: string; email: string; full_name: string
  status: string; two_fa: boolean; pref_theme: string; pref_lang: string
}

function Card({ title, description, icon, children }: { title: string; description?: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-6 shadow-sm">
      <div className="flex items-start gap-3 mb-5">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 flex items-center justify-center shrink-0">{icon}</div>
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          {description && <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{description}</p>}
        </div>
      </div>
      {children}
    </section>
  )
}

function Input({ label, ...props }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{label}</span>
      <input {...props} className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none disabled:opacity-60 disabled:bg-slate-100 dark:disabled:bg-slate-800" />
    </label>
  )
}

function Alert({ type, message }: { type: 'ok' | 'err'; message: string }) {
  if (!message) return null
  const colorClasses = type === 'ok'
    ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300'
    : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300'
  return <div className={`text-sm px-3 py-2 rounded-lg border ${colorClasses}`}>{message}</div>
}

export default function SettingsPage() {
  const { t } = useTranslation('SettingsPage')
  const updateName = useAuth((state) => state.updateName)
  const logout = useAuth((state) => state.logout)
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null)
  const [loadError, setLoadError] = useState('')

  const [fullName, setFullName] = useState(''); const [email, setEmail] = useState('')
  const [profileSuccess, setProfileSuccess] = useState(''); const [profileError, setProfileError] = useState(''); const [isProfileLoading, setIsProfileLoading] = useState(false)

  const [currentPassword, setCurrentPassword] = useState(''); const [newPassword, setNewPassword] = useState(''); const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordSuccess, setPasswordSuccess] = useState(''); const [passwordError, setPasswordError] = useState(''); const [isPasswordLoading, setIsPasswordLoading] = useState(false)

  const [twoFactorSetup, setTwoFactorSetup] = useState<{ secret: string; otpauth: string; otpauth_uri?: string; qr_data_uri?: string } | null>(null)
  const [twoFactorCode, setTwoFactorCode] = useState(''); const [twoFactorError, setTwoFactorError] = useState(''); const [isTwoFactorLoading, setIsTwoFactorLoading] = useState(false)
  const [isDisablingTwoFactor, setIsDisablingTwoFactor] = useState(false); const [disableCode, setDisableCode] = useState('')

  const [theme, setThemePreference] = useState<Theme>('system'); const [language, setLanguage] = useState('en')
  const [preferenceSuccess, setPreferenceSuccess] = useState(''); const [isPreferenceLoading, setIsPreferenceLoading] = useState(false)

  function load() {
    api.get<CurrentUser>('/me').then(response => {
      setCurrentUser(response.data); setFullName(response.data.full_name || ''); setEmail(response.data.email || '')
      setThemePreference((response.data.pref_theme as Theme) || 'system'); setLanguage(response.data.pref_lang || 'en')
    }).catch(error => setLoadError(apiError(error)))
  }
  useEffect(load, [])

  async function saveProfile(event: React.FormEvent) {
    event.preventDefault(); setProfileSuccess(''); setProfileError(''); setIsProfileLoading(true)
    try {
      await api.put('/me', { full_name: fullName, email })
      updateName(fullName) // Keep the top-right bar in sync.
      setProfileSuccess(t('account.saved')); setTimeout(() => setProfileSuccess(''), 3000); load()
    } catch (error) { setProfileError(apiError(error, t('account.saveFailed'))) } finally { setIsProfileLoading(false) }
  }

  async function changePassword(event: React.FormEvent) {
    event.preventDefault(); setPasswordSuccess(''); setPasswordError('')
    if (newPassword.length < 8) { setPasswordError(t('password.tooShort')); return }
    if (newPassword !== confirmPassword) { setPasswordError(t('password.mismatch')); return }
    setIsPasswordLoading(true)
    try {
      await api.post('/me/password', { current: currentPassword, new: newPassword })
      setPasswordSuccess(t('password.changed'))
      setCurrentPassword(''); setNewPassword(''); setConfirmPassword(''); setTimeout(() => setPasswordSuccess(''), 5000)
    } catch (error) { setPasswordError(apiError(error, t('password.changeFailed'))) } finally { setIsPasswordLoading(false) }
  }

  const revokeSessions = async () => {
    setPasswordError(''); setPasswordSuccess('')
    try {
      await api.post('/me/sessions/revoke')
      logout()
    } catch (error) { setPasswordError(apiError(error, t('password.signOutFailed'))) }
  }

  async function startTwoFactorSetup() {
    setTwoFactorError(''); setTwoFactorCode('')
    try { const response = await api.get<{ secret: string; otpauth: string; otpauth_uri?: string; qr_data_uri?: string }>('/me/2fa/setup'); setTwoFactorSetup(response.data) }
    catch (error) { setTwoFactorError(apiError(error)) }
  }
  async function enableTwoFactor(event: React.FormEvent) {
    event.preventDefault(); setTwoFactorError(''); setIsTwoFactorLoading(true)
    try {
      await api.post('/me/2fa/enable', { secret: twoFactorSetup!.secret, code: twoFactorCode })
      setTwoFactorSetup(null); setTwoFactorCode(''); load()
    } catch (error) { setTwoFactorError(apiError(error, t('twoFa.verifyFailed'))) } finally { setIsTwoFactorLoading(false) }
  }
  async function confirmDisableTwoFactor(event: React.FormEvent) {
    event.preventDefault(); setTwoFactorError(''); setIsTwoFactorLoading(true)
    try { await api.post('/me/2fa/disable', { code: disableCode }); setIsDisablingTwoFactor(false); setDisableCode(''); load() }
    catch (error) { setTwoFactorError(apiError(error, t('twoFa.verifyFailed'))) } finally { setIsTwoFactorLoading(false) }
  }

  async function savePreferences() {
    setPreferenceSuccess(''); setIsPreferenceLoading(true)
    try {
      await api.put('/me', { full_name: fullName, email, pref_theme: theme, pref_lang: language })
      applyThemePreference(theme)
      setLang(((LANGS as readonly string[]).includes(language) ? language : 'en') as Lang)
      setPreferenceSuccess(t('preferences.saved')); setTimeout(() => setPreferenceSuccess(''), 3000)
    } catch { setPreferenceSuccess('') } finally { setIsPreferenceLoading(false) }
  }

  const buttonClasses = 'px-4 py-2 text-sm font-medium rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-50 inline-flex items-center gap-2'
  const groupedSecret = twoFactorSetup ? (twoFactorSetup.secret.match(/.{1,4}/g) || []).join(' ') : ''

  return (
    <div className="px-6 md:px-8 py-6">
      <Breadcrumb items={[{ label: t('breadcrumbHome'), href: '/' }, { label: t('pageTitle') }]} />
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('pageTitle')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-500 mb-6">{t('pageSubtitle')}</p>
      {loadError && <div className="mb-4"><Alert type="err" message={loadError} /></div>}

      <div className="space-y-5">
        <PanelDomain />
        <HostnameSetting />
        {/* Resellers only: the admin pair lives under Tools & Settings, which is
            where the admin menu's Settings entry goes and which a reseller
            never sees. */}
        <NameserverSetting audience="reseller" />
        <SessionIdleSetting />
        <ServerRebootButton />

        {/* 1. Account information */}
        <Card title={t('account.title')} description={t('account.description')}
          icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>}
        >
            <form onSubmit={saveProfile} className="space-y-4">
              <div className="grid sm:grid-cols-2 gap-4">
                <Input label={t('account.username')} value={currentUser?.name || 'root'} disabled />
                <div>
                  <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('account.roleStatus')}</span>
                  <div className="flex gap-2 pt-1.5">
                    <span className="text-[11px] uppercase tracking-wider px-2 py-1 rounded bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 font-semibold">{currentUser?.role || 'admin'}</span>
                    <span className="text-[11px] uppercase tracking-wider px-2 py-1 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 font-semibold">{currentUser?.status || 'active'}</span>
                  </div>
                </div>
                <Input label={t('account.fullName')} value={fullName} onChange={event => setFullName(event.target.value)} placeholder={t('account.fullNamePlaceholder')} />
                <Input label={t('account.email')} type="email" value={email} onChange={event => setEmail(event.target.value)} placeholder="example@site.com" />
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <button type="submit" disabled={isProfileLoading} className={buttonClasses}>{isProfileLoading ? t('account.saving') : t('account.save')}</button>
                <Alert type="ok" message={profileSuccess} /><Alert type="err" message={profileError} />
              </div>
            </form>
        </Card>

        {/* 2. Password */}
        <Card title={t('password.title')} description={t('password.description')}
          icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>}
        >
            <form onSubmit={changePassword} className="space-y-4">
              <Input label={t('password.current')} type="password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} autoComplete="current-password" />
              <div className="grid sm:grid-cols-2 gap-4">
                <Input label={t('password.new')} type="password" value={newPassword} onChange={event => setNewPassword(event.target.value)} autoComplete="new-password" />
                <Input label={t('password.confirm')} type="password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} autoComplete="new-password" />
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <button type="submit" disabled={isPasswordLoading || !currentPassword || !newPassword} className={buttonClasses}>{isPasswordLoading ? t('password.changing') : t('password.change')}</button>
                <button type="button" onClick={revokeSessions} className="px-4 py-2 text-sm font-medium rounded-lg border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20">{t('password.signOutAll')}</button>
                <Alert type="ok" message={passwordSuccess} /><Alert type="err" message={passwordError} />
              </div>
            </form>
        </Card>

        {/* 3. Two-factor authentication */}
        <Card title={t('twoFa.title')} description={t('twoFa.description')}
          icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>}
        >
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="text-sm text-slate-600 dark:text-slate-400">{t('twoFa.status')}</span>
                {currentUser?.two_fa
                  ? <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300">{t('twoFa.active')}</span>
                  : <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">{t('twoFa.disabled')}</span>}
              </div>

              {!currentUser?.two_fa && !twoFactorSetup && (
                <button onClick={startTwoFactorSetup} className={buttonClasses}>{t('twoFa.enable')}</button>
              )}

              {!currentUser?.two_fa && twoFactorSetup && (
                <form onSubmit={enableTwoFactor} className="space-y-3 border border-slate-200 dark:border-slate-700 rounded-2xl p-4 bg-slate-50 dark:bg-slate-900">
                  <p className="text-sm text-slate-700 dark:text-slate-300">{t('twoFa.step1')}</p>
                  {twoFactorSetup.qr_data_uri && (
                    <div className="flex flex-col items-center gap-2 py-1">
                      <img src={twoFactorSetup.qr_data_uri} alt={t('twoFa.qrAlt')} width={256} height={256}
                        className="w-64 h-64 rounded-2xl bg-white p-3 border border-slate-200 dark:border-slate-700 shadow-sm" />
                      <p className="text-xs text-slate-500 dark:text-slate-500">{t('twoFa.scanHint')}</p>
                    </div>
                  )}
                  <p className="text-xs text-slate-500 dark:text-slate-500">{t('twoFa.manualHint')}</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="font-mono text-sm px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-100 tracking-widest select-all">{groupedSecret}</code>
                    <button type="button" onClick={() => { navigator.clipboard?.writeText(twoFactorSetup.secret) }} className="text-xs px-2.5 py-1.5 rounded border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700">{t('twoFa.copy')}</button>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-500 break-all">{t('twoFa.orLink')} <span className="font-mono">{twoFactorSetup.otpauth}</span></p>
                  <p className="text-sm text-slate-700 dark:text-slate-300">{t('twoFa.step2')}</p>
                  <div className="flex items-center gap-3 flex-wrap">
                    <input value={twoFactorCode} onChange={event => setTwoFactorCode(event.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" inputMode="numeric"
                      className="w-32 px-3 py-2 text-center text-lg font-mono tracking-[0.3em] bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 focus:border-brand-500 outline-none" />
                    <button type="submit" disabled={isTwoFactorLoading || twoFactorCode.length !== 6} className={buttonClasses}>{isTwoFactorLoading ? t('twoFa.verifying') : t('twoFa.verifyEnable')}</button>
                    <button type="button" onClick={() => setTwoFactorSetup(null)} className="text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">{t('twoFa.cancel')}</button>
                  </div>
                  <Alert type="err" message={twoFactorError} />
                </form>
              )}

              {currentUser?.two_fa && !isDisablingTwoFactor && (
                <button onClick={() => { setIsDisablingTwoFactor(true); setTwoFactorError('') }} className="px-4 py-2 text-sm font-medium rounded-lg border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20">{t('twoFa.disable')}</button>
              )}
              {currentUser?.two_fa && isDisablingTwoFactor && (
                <form onSubmit={confirmDisableTwoFactor} className="space-y-3 border border-red-200 dark:border-red-800 rounded-2xl p-4 bg-red-50 dark:bg-red-900/10">
                  <p className="text-sm text-slate-700 dark:text-slate-300">{t('twoFa.disablePrompt')}</p>
                  <div className="flex items-center gap-3 flex-wrap">
                    <input value={disableCode} onChange={event => setDisableCode(event.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" inputMode="numeric"
                      className="w-32 px-3 py-2 text-center text-lg font-mono tracking-[0.3em] bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 outline-none" />
                    <button type="submit" disabled={isTwoFactorLoading || disableCode.length !== 6} className="px-4 py-2 text-sm font-medium rounded-lg bg-red-600 hover:bg-red-700 text-white disabled:opacity-50">{t('twoFa.disableConfirm')}</button>
                    <button type="button" onClick={() => setIsDisablingTwoFactor(false)} className="text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">{t('twoFa.cancel')}</button>
                  </div>
                  <Alert type="err" message={twoFactorError} />
                </form>
              )}
            </div>
        </Card>

        {/* 4. Preferences */}
        <Card title={t('preferences.title')} description={t('preferences.description')}
          icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>}
        >
            <div className="space-y-4">
              <div className="grid sm:grid-cols-2 gap-4">
                <label className="block">
                  <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('preferences.theme')}</span>
                  <select value={theme} onChange={event => setThemePreference(event.target.value as Theme)} className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 outline-none">
                    <option value="system">{t('preferences.system')}</option><option value="light">{t('preferences.light')}</option><option value="dark">{t('preferences.dark')}</option>
                  </select>
                </label>
                <label className="block">
                  <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('preferences.language')}</span>
                  <select value={language} onChange={event => setLanguage(event.target.value)} className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-800 dark:text-slate-100 outline-none">
                    {LANGS.map(code => <option key={code} value={code}>{LANG_NAMES[code]}</option>)}
                  </select>
                </label>
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <button onClick={savePreferences} disabled={isPreferenceLoading} className={buttonClasses}>{isPreferenceLoading ? t('preferences.saving') : t('preferences.save')}</button>
                <Alert type="ok" message={preferenceSuccess} />
              </div>
            </div>
        </Card>
      </div>
    </div>
  )
}
