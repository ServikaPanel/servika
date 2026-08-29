// Resets a database user's password. Shared by the domain-scoped database page
// and the server-wide database list, which both call PUT /databases/:id/password
// and both have to show the generated value once, because nothing can read it
// back afterwards.
//
// The row shape differs between those two pages, so this takes only the three
// fields it actually needs rather than either page's own type.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Modal from './Modal'

type DBTarget = { id: number; db_name: string; db_user: string }

export default function DBPasswordResetModal({ db, onClose, onDone }: {
  db: DBTarget
  onClose: () => void
  onDone: () => void
}) {
  const { t } = useTranslation('DBPasswordResetModal')
  const [customPassword, setCustomPassword] = useState('')
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState<string | null>(null)
  // A database with no user: this happens for a database restored from a backup,
  // whose archive carries schema and data but no MySQL account. The panel assumed
  // every database had a user, so there was no way to create one and the site
  // could not connect. This modal creates it.
  const noUser = !db.db_user
  const [newUser, setNewUser] = useState('')

  async function reset(random: boolean) {
    if (!random && customPassword.length < 6) {
      setError(t('errors.tooShort'))
      return
    }
    if (noUser && !newUser.trim()) {
      setError(t('errors.userRequired'))
      return
    }
    setProcessing(true); setError(null)
    try {
      const body: Record<string, string> = random ? {} : { password: customPassword }
      if (noUser) body.user = newUser.trim()
      const { data } = await api.put(`/databases/${db.id}/password`, body)
      setNewPassword(data.db_pass)
    } catch (e) {
      setError(apiError(e, t('errors.resetFailed')))
    } finally {
      setProcessing(false)
    }
  }

  return (
    <Modal open={true} title={t(noUser ? 'createTitle' : 'title', { name: db.db_name })} onClose={newPassword ? onDone : onClose} width="md">
      {!newPassword ? (
        <div className="space-y-4">
          {noUser ? (
            <>
              <div className="text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg px-3 py-2">
                {t('noUserWarning')}
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" htmlFor="db-new-user">{t('userLabel')}</label>
                <input
                  id="db-new-user"
                  type="text"
                  value={newUser}
                  onChange={e => setNewUser(e.target.value)}
                  placeholder={t('userPlaceholder')}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none dark:bg-slate-900/40 text-slate-900 dark:text-slate-100"
                />
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('userHint')}</p>
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-600 dark:text-slate-400 dark:text-slate-500">
              <strong className="font-mono">{db.db_user}</strong>{t('introPre')}
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('customLabel')}</label>
            <input
              type="text"
              value={customPassword}
              onChange={e => setCustomPassword(e.target.value)}
              placeholder={t('customPlaceholder')}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none"
            />
          </div>
          {error && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-300">{error}</div>}
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={processing} className="px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-md text-sm">{t('cancel')}</button>
            <button onClick={() => reset(false)} disabled={processing || !customPassword} className="px-4 py-2 bg-white dark:bg-slate-800 border border-brand-600 text-brand-700 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-900/30 dark:bg-brand-900/20 disabled:opacity-50 rounded-md text-sm">{t('useThis')}</button>
            <button onClick={() => reset(true)} disabled={processing} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">{processing ? t('resetting') : t('generateRandom')}</button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md p-4">
            <p className="text-sm text-emerald-800 dark:text-emerald-200 font-medium mb-2">{t('updated')}</p>
            <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-2">{t('saveHint')}</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-white dark:bg-slate-800 px-3 py-2 font-mono text-sm text-slate-900 dark:text-slate-100 rounded border border-emerald-200 dark:border-emerald-800 break-all">{newPassword}</code>
              <button onClick={() => navigator.clipboard.writeText(newPassword)} className="px-3 py-2 bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 text-emerald-800 dark:text-emerald-200 text-xs rounded">{t('copy')}</button>
            </div>
          </div>
          <div className="flex justify-end">
            <button onClick={onDone} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded-md">{t('done')}</button>
          </div>
        </div>
      )}
    </Modal>
  )
}
