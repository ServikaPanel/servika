import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import { useResourceScope } from '@/lib/scope'

type Protection = { id: number; path: string; username: string; created_at: string }

export default function DomainPasswordProtectPage() {
  const { t } = useTranslation('DomainPasswordProtectPage')
  const { confirm } = useDialog()
  const { id, base, backHref, backLabel } = useResourceScope()
  const [protections, setProtections] = useState<Protection[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [path, setPath] = useState('/private')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchProtections
  // settles only through promise callbacks, and load() adds the spinner for the
  // refreshes that follow a write.
  const fetchProtections = useCallback(() => {
    if (!id) return
    api.get<Protection[]>(`${base}/protection`)
      .then(r => setProtections(r.data || [])).catch(e => setError(apiError(e))).finally(() => setLoading(false))
  }, [id, base])

  const load = useCallback(() => {
    setLoading(true)
    fetchProtections()
  }, [fetchProtections])

  useEffect(() => { fetchProtections() }, [fetchProtections])

  async function add(e: React.FormEvent) {
    e.preventDefault()
    setError(null); setSuccess(null); setIsSaving(true)
    try {
      await api.post(`${base}/protection`, { path, username, password })
      setSuccess(t('addSuccess', { path, username }))
      setPassword('')
      load()
    } catch (err) {
      setError(apiError(err, t('errors.addFailed')))
    } finally { setIsSaving(false) }
  }

  async function remove(k: Protection) {
    if (!(await confirm({ message: t('confirmRemove', { username: k.username, path: k.path }), dangerous: true }))) return
    setError(null); setSuccess(null)
    try {
      await api.delete(`${base}/protection/${k.id}`)
      load()
    } catch (err) { setError(apiError(err, t('errors.removeFailed'))) }
  }

  // Group users by their protected path.
  const groups = protections.reduce<Record<string, Protection[]>>((a, k) => { (a[k.path] ||= []).push(k); return a }, {})

  return (
    <div className="px-6 py-5">
      <div>
        <Breadcrumb items={[
          { label: t('breadcrumb.home'), href: '/' },
          { label: t('breadcrumb.domains'), href: '/domains' },
          { label: t('breadcrumb.passwordProtected') },
        ]} />
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('subtitle.pre')}<span className="font-mono">.htpasswd</span>{t('subtitle.post')}
        </p>

        {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">{error}</div>}
        {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

        {/* Add-protection form */}
        <form onSubmit={add} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('addForm.title')}</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('addForm.pathLabel')}</span>
              <input value={path} onChange={e => setPath(e.target.value)} required placeholder={t('addForm.pathPlaceholder')}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('addForm.usernameLabel')}</span>
              <input value={username} onChange={e => setUsername(e.target.value)} required placeholder={t('addForm.usernamePlaceholder')}
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('addForm.passwordLabel')}</span>
              <input value={password} onChange={e => setPassword(e.target.value)} required type="password" placeholder="••••••••"
                className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 dark:bg-slate-900 rounded-lg text-sm focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none" />
            </label>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">{t('addForm.hint.pre')}<span className="font-mono">{t('addForm.hint.slash')}</span>{t('addForm.hint.mid')}<span className="font-mono">{t('addForm.hint.example1')}</span>{t('addForm.hint.or')}<span className="font-mono">{t('addForm.hint.example2')}</span>{t('addForm.hint.post')}</p>
          <button disabled={isSaving} className="mt-3 px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded-lg disabled:opacity-50">
            {isSaving ? t('addForm.submitting') : t('addForm.submit')}
          </button>
        </form>

        {/* Existing protections */}
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('list.title')}</h3>
          {loading ? (
            <div className="text-sm text-slate-400">{t('list.loading')}</div>
          ) : protections.length === 0 ? (
            <div className="text-center py-8">
              <div className="mb-2 flex justify-center text-slate-400"><Icon d={ICON.lock} className="h-8 w-8" /></div>
              <p className="text-sm text-slate-500 dark:text-slate-400">{t('list.empty')}</p>
            </div>
          ) : (
            <div className="space-y-4">
              {Object.entries(groups).map(([g, ks]) => (
                <div key={g} className="border border-slate-100 dark:border-slate-700 rounded-lg overflow-hidden">
                  <div className="flex items-center gap-2 px-3 py-2 bg-slate-50 dark:bg-slate-900/40">
                    <span className="text-slate-500 dark:text-slate-400"><Icon d={ICON.lock} className="h-4 w-4" /></span>
                    <span className="font-mono text-sm text-slate-700 dark:text-slate-200">{g}</span>
                    <span className="text-xs text-slate-400">{t('list.userCount', { count: ks.length })}</span>
                  </div>
                  <ul className="divide-y divide-slate-50 dark:divide-slate-700/50">
                    {ks.map(k => (
                      <li key={k.id} className="flex items-center justify-between px-3 py-2">
                        <span className="text-sm text-slate-600 dark:text-slate-300">{k.username}</span>
                        <button onClick={() => remove(k)} className="text-xs text-red-600 dark:text-red-400 hover:underline">{t('list.remove')}</button>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="mt-4"><Link to={backHref} className="text-sm text-brand-600 dark:text-brand-400">{backLabel}</Link></div>
      </div>
    </div>
  )
}
