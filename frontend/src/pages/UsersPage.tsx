// Panel accounts (admin / reseller / customer) — the UI for the /users CRUD.
//
// Scope is enforced server-side (see internal/users): a reseller sees only the
// accounts beneath itself and may create customer accounts only. The role
// restrictions here mirror those rules for the UI; they are not a security
// boundary.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import { useAuth } from '@/store/auth'
import Breadcrumb from '@/components/Breadcrumb'
import EmptyState from '@/components/EmptyState'
import ListToolbar from '@/components/ListToolbar'
import Modal from '@/components/Modal'
import ConfirmDialog from '@/components/ConfirmDialog'

type User = {
  id: number
  username: string
  email: string
  full_name: string
  role: 'admin' | 'reseller' | 'user'
  status: 'active' | 'suspended'
  reseller_id: number | null
  two_fa: boolean
  last_login: string
  last_login_ip: string
  created_at: string
  // passwordless: the account has no password and cannot log in until one is
  // assigned (a customer produced by the backfill starts this way).
  passwordless: boolean
}

const ROLE_LABEL: Record<string, string> = {
  admin: 'Administrator',
  reseller: 'Reseller',
  user: 'Customer',
}
const ROLE_STYLE: Record<string, string> = {
  admin: 'bg-violet-50 text-violet-700 dark:bg-violet-900/20 dark:text-violet-300',
  reseller: 'bg-sky-50 text-sky-700 dark:bg-sky-900/20 dark:text-sky-300',
  user: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
}

type NewAccount = { username: string; password: string; email: string; full_name: string; role: string }
const EMPTY: NewAccount = { username: '', password: '', email: '', full_name: '', role: 'user' }

type ResellerLimit = {
  user_id: number
  max_customer: number
  max_domain: number
  disk_quota_mb: number
  traffic_quota_mb: number
  defined: boolean
  current_customer: number
  current_domain: number
  current_disk_mb: number
  current_traffic_mb: number
}

/** Every piece of state this screen owns, so each block below is a component. */
function useUsersPage() {
  const { t } = useTranslation('UsersPage')
  const myRole = useAuth((s) => s.username?.role)
  const myID = useAuth((s) => s.username?.id)
  const isAdmin = myRole === 'admin'

  // Global search (TopBar) deep-links here with ?q=<username>; seed the filter
  // from it and keep it in sync when the param changes without a remount.
  const [searchParams] = useSearchParams()
  const [list, setList] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const queryParam = searchParams.get('q') || ''
  const [query, setQuery] = useState(queryParam)
  // Adjusted during render rather than in an effect: a deep link that only
  // changes ?q= must filter on the very first painted frame, not one frame
  // later with the previous query still applied.
  const [appliedQueryParam, setAppliedQueryParam] = useState(queryParam)
  if (queryParam !== appliedQueryParam) {
    setAppliedQueryParam(queryParam)
    setQuery(queryParam)
  }

  const [creating, setCreating] = useState<NewAccount | null>(null)
  const [saving, setSaving] = useState(false)
  const [pwTarget, setPwTarget] = useState<User | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [toDelete, setToDelete] = useState<User | null>(null)
  const [limitTarget, setLimitTarget] = useState<User | null>(null)
  const [limit, setLimit] = useState<ResellerLimit | null>(null)
  const [limitLoading, setLimitLoading] = useState(false)

  // Promise callbacks rather than await/try: this is what the mount effect
  // calls, and writes in an awaited body still count as the effect's own
  // continuation. The spinner belongs to reload(), used by the write paths.
  const fetchList = useCallback(() =>
    api.get<User[]>('/users')
      .then((r) => { setList(Array.isArray(r.data) ? r.data : []); setError(null) })
      .catch((e) => setError(apiError(e, t('errors.loadFailed'))))
      .finally(() => setLoading(false)),
  [t])

  const reload = useCallback(() => { setLoading(true); return fetchList() }, [fetchList])

  useEffect(() => { fetchList() }, [fetchList])

  const filtered = useMemo(() => {
    const t = query.trim().toLowerCase()
    if (!t) return list
    return list.filter((k) => `${k.username} ${k.email} ${k.full_name}`.toLowerCase().includes(t))
  }, [list, query])

  async function create() {
    if (!creating) return
    setSaving(true)
    setError(null)
    try {
      await api.post('/users', creating)
      setSuccess(t('toast.created', { username: creating.username }))
      setCreating(null)
      await reload()
    } catch (e) {
      setError(apiError(e, t('errors.createFailed')))
    } finally {
      setSaving(false)
    }
  }

  async function resetPassword() {
    if (!pwTarget) return
    setSaving(true)
    setError(null)
    try {
      await api.post(`/users/${pwTarget.id}/password`, { new: newPassword })
      setSuccess(t('toast.passwordUpdated', { username: pwTarget.username }))
      setPwTarget(null)
      setNewPassword('')
    } catch (e) {
      setError(apiError(e, t('errors.resetFailed')))
    } finally {
      setSaving(false)
    }
  }

  async function openLimits(k: User) {
    setLimitTarget(k)
    setLimit(null)
    setLimitLoading(true)
    setError(null)
    try {
      const r = await api.get<ResellerLimit>(`/users/${k.id}/limits`)
      setLimit(r.data)
    } catch (e) {
      setError(apiError(e, t('errors.loadLimitsFailed')))
      setLimitTarget(null)
    } finally {
      setLimitLoading(false)
    }
  }

  async function saveLimits() {
    if (!limitTarget || !limit) return
    setSaving(true)
    setError(null)
    try {
      await api.put(`/users/${limitTarget.id}/limits`, {
        max_customer: limit.max_customer,
        max_domain: limit.max_domain,
        disk_quota_mb: limit.disk_quota_mb,
        traffic_quota_mb: limit.traffic_quota_mb,
      })
      setSuccess(t('toast.limitsUpdated', { username: limitTarget.username }))
      setLimitTarget(null)
      setLimit(null)
    } catch (e) {
      setError(apiError(e, t('errors.saveLimitsFailed')))
    } finally {
      setSaving(false)
    }
  }

  async function toggleStatus(k: User) {
    const target = k.status === 'active' ? 'suspended' : 'active'
    setError(null)
    try {
      await api.post(`/users/${k.id}/status`, { status: target })
      setSuccess(target === 'active' ? t('toast.enabled', { username: k.username }) : t('toast.suspended', { username: k.username }))
      await reload()
    } catch (e) {
      setError(apiError(e, t('errors.statusFailed')))
    }
  }

  async function remove() {
    if (!toDelete) return
    try {
      await api.delete(`/users/${toDelete.id}`)
      setSuccess(t('toast.deleted', { username: toDelete.username }))
      setToDelete(null)
      await reload()
    } catch (e) {
      setError(apiError(e, t('errors.deleteFailed')))
      setToDelete(null)
    }
  }

  // No destructive action on root or your own account — the server rejects it
  // too; hiding the button avoids a pointless error message.
  const protectedRow = (k: User) => k.id === 1 || k.id === myID

  return {
    appliedQueryParam, create, creating, error, fetchList, filtered, isAdmin, limit, limitLoading, limitTarget, list, loading, myID, myRole, newPassword, openLimits, protectedRow, pwTarget, query, queryParam, reload, remove, resetPassword, saveLimits, saving, setAppliedQueryParam, setCreating, setError, setLimit, setLimitLoading, setLimitTarget, setList, setLoading, setNewPassword, setPwTarget, setQuery, setSaving, setSuccess, setToDelete, success, toDelete, toggleStatus,
  }
}

export default function UsersPage() {
  const { t } = useTranslation('UsersPage')
  const ctx = useUsersPage()

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[{ label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.users') }]} />
      <UsersHeader ctx={ctx} />

      <UsersTable ctx={ctx} />

      <CreateModal ctx={ctx} />

      <PasswordModal ctx={ctx} />

      <LimitsModal ctx={ctx} />

      <DeleteConfirm ctx={ctx} />

    </div>
  )
}

type UsersCtx = ReturnType<typeof useUsersPage>

function UsersHeader({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { error, isAdmin, query, setCreating, setQuery, success } = ctx
  return (
    <>

      <div className="mb-5">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {isAdmin ? t('subtitleAdmin') : t('subtitleReseller')}
        </p>
      </div>

      <ListToolbar
        primary={{ label: isAdmin ? t('newAccount') : t('newCustomer'), onClick: () => setCreating({ ...EMPTY, role: isAdmin ? 'reseller' : 'user' }) }}
        search={query}
        onSearchChange={setQuery}
      />

      {error && <div className="mb-4 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm">{error}</div>}
      {success && <div className="mb-4 px-3 py-2 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 text-sm">{success}</div>}
    </>
  )
}

function RowActions({ k, ctx }: { k: User; ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { isAdmin, openLimits, protectedRow, setNewPassword, setPwTarget, setToDelete, toggleStatus } = ctx
  if (k.id === 1) return <span className="text-xs text-slate-400">{t('systemAccount')}</span>
  return (
    <>
      <button onClick={() => { setPwTarget(k); setNewPassword('') }} className="text-xs text-brand-600 dark:text-brand-400 hover:underline mr-3">
        {t('actions.password')}
      </button>
      {/* Quota is meaningful only for resellers and only admins manage it. */}
      {isAdmin && k.role === 'reseller' && (
        <button onClick={() => openLimits(k)} className="text-xs text-sky-600 dark:text-sky-400 hover:underline mr-3">
          {t('actions.limits')}
        </button>
      )}
      {!protectedRow(k) && (
        <>
          <button onClick={() => toggleStatus(k)} className="text-xs text-amber-600 dark:text-amber-400 hover:underline mr-3">
            {k.status === 'active' ? t('actions.suspend') : t('actions.enable')}
          </button>
          <button onClick={() => setToDelete(k)} className="text-xs text-red-600 dark:text-red-400 hover:underline">
            {t('actions.delete')}
          </button>
        </>
      )}
    </>
  )
}

function UserRow({ k, ctx }: { k: User; ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  return (
                <tr key={k.id} className="hover:bg-slate-50 dark:hover:bg-slate-900/60 transition">
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <span className="font-mono text-slate-900 dark:text-slate-100">{k.username}</span>
                    {k.id === 1 && <span className="ml-1.5 text-[10px] text-slate-400">{t('system')}</span>}
                  </td>
                  <td className="px-3 py-2.5 text-slate-600 dark:text-slate-400 whitespace-nowrap">{k.full_name || '—'}</td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-xs ${ROLE_STYLE[k.role]}`}>{t(`roles.${k.role}`, { defaultValue: ROLE_LABEL[k.role] ?? k.role })}</span>
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {k.status === 'active'
                      ? <span className="px-2 py-0.5 rounded text-xs bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300">{t('status.active')}</span>
                      : <span className="px-2 py-0.5 rounded text-xs bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">{t('status.suspended')}</span>}
                    {k.passwordless && (
                      <span
                        title={t('noPasswordTitle')}
                        className="ml-1.5 px-2 py-0.5 rounded text-xs bg-rose-50 text-rose-700 dark:bg-rose-900/20 dark:text-rose-300"
                      >
                        {t('noPassword')}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap text-xs">
                    {k.two_fa ? <span className="text-emerald-600 dark:text-emerald-400">{t('twoFaOn')}</span> : <span className="text-slate-400">{t('twoFaOff')}</span>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap text-xs text-slate-500">
                    {k.last_login || '—'}
                    {k.last_login_ip && <span className="ml-1 opacity-60">({k.last_login_ip})</span>}
                  </td>
                  <td className="px-3 py-2.5 text-right whitespace-nowrap"><RowActions k={k} ctx={ctx} /></td>
                </tr>
  )
}

function UsersTable({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { filtered, isAdmin, list, loading, setCreating } = ctx
  return (
    <>
      {loading ? (
        <div className="py-16 text-center text-sm text-slate-400">{t('loading')}</div>
      ) : list.length === 0 ? (
        <EmptyState
          title={isAdmin ? t('empty.titleAdmin') : t('empty.titleReseller')}
          description={t('empty.description')}
          button={{ label: t('newAccount'), onClick: () => setCreating({ ...EMPTY, role: isAdmin ? 'reseller' : 'user' }) }}
        />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-sm text-slate-400">{t('noMatch')}</div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60">
              <tr>
                {[t('columns.user'), t('columns.fullName'), t('columns.role'), t('columns.status'), t('columns.twoFa'), t('columns.lastLogin'), ''].map((b, i) => (
                  <th key={i} className="px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 whitespace-nowrap">{b}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-950">
              {filtered.map((k) => <UserRow key={k.id} k={k} ctx={ctx} />)}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

function CreateModal({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { create, creating, isAdmin, saving, setCreating } = ctx
  return (
    <>
      {/* New account */}
      <Modal open={creating !== null} title={isAdmin ? t('createModal.titleAdmin') : t('createModal.titleReseller')} onClose={() => setCreating(null)}>
        {creating && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{t('createModal.username')}</label>
              <input
                value={creating.username}
                onChange={(e) => setCreating({ ...creating, username: e.target.value })}
                placeholder={t('createModal.usernamePlaceholder')}
                className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <p className="mt-1 text-[11px] text-slate-400">{t('createModal.usernameHint')}</p>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{t('createModal.password')}</label>
              <input
                type="text"
                value={creating.password}
                onChange={(e) => setCreating({ ...creating, password: e.target.value })}
                className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <p className="mt-1 text-[11px] text-slate-400">{t('createModal.passwordHint')}</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{t('createModal.role')}</label>
                <select
                  value={creating.role}
                  onChange={(e) => setCreating({ ...creating, role: e.target.value })}
                  disabled={!isAdmin}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 disabled:opacity-60 focus:outline-none focus:ring-1 focus:ring-brand-500"
                >
                  {isAdmin && <option value="admin">{t('roles.admin')}</option>}
                  {isAdmin && <option value="reseller">{t('roles.reseller')}</option>}
                  <option value="user">{t('roles.user')}</option>
                </select>
                {!isAdmin && <p className="mt-1 text-[11px] text-slate-400">{t('createModal.resellerOnlyCustomers')}</p>}
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{t('createModal.email')}</label>
                <input
                  type="email"
                  value={creating.email}
                  onChange={(e) => setCreating({ ...creating, email: e.target.value })}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{t('createModal.fullName')}</label>
              <input
                value={creating.full_name}
                onChange={(e) => setCreating({ ...creating, full_name: e.target.value })}
                className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setCreating(null)} className="px-3.5 py-2 text-sm rounded-full text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition">{t('createModal.cancel')}</button>
              <button onClick={create} disabled={saving} className="px-3.5 py-2 text-sm font-medium rounded-full bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 transition">
                {saving ? t('createModal.creating') : t('createModal.create')}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  )
}

function PasswordModal({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { newPassword, pwTarget, resetPassword, saving, setNewPassword, setPwTarget } = ctx
  return (
    <>
      {/* Password reset */}
      <Modal open={pwTarget !== null} title={t('passwordModal.title')} onClose={() => setPwTarget(null)}>
        {pwTarget && (
          <div className="space-y-3">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              {t('passwordModal.newFor')}<span className="font-mono">{pwTarget.username}</span>.
              {pwTarget.role === 'user' && (
                <span className="block mt-1.5 text-xs text-slate-500">
                  {t('passwordModal.customerNote')}
                </span>
              )}
            </p>
            <input
              type="text"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder={t('passwordModal.placeholder')}
              className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setPwTarget(null)} className="px-3.5 py-2 text-sm rounded-full text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition">{t('passwordModal.cancel')}</button>
              <button onClick={resetPassword} disabled={saving || newPassword.length < 8} className="px-3.5 py-2 text-sm font-medium rounded-full bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 transition">
                {saving ? t('passwordModal.saving') : t('passwordModal.setPassword')}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  )
}

function LimitFields({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { limit, setLimit } = ctx
  if (!limit) return null
  return (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                  {t('limitsModal.maxCustomers')}
                </label>
                <input
                  type="number"
                  min={0}
                  value={limit.max_customer}
                  onChange={(e) => setLimit({ ...limit, max_customer: Math.max(0, Number(e.target.value) || 0) })}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  {t('limitsModal.inUseNow', { count: limit.current_customer })}
                  {limit.max_customer > 0 && limit.current_customer > limit.max_customer && (
                    <span className="text-amber-600 dark:text-amber-400">{t('limitsModal.limitBelowUsage')}</span>
                  )}
                </p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                  {t('limitsModal.maxDomains')}
                </label>
                <input
                  type="number"
                  min={0}
                  value={limit.max_domain}
                  onChange={(e) => setLimit({ ...limit, max_domain: Math.max(0, Number(e.target.value) || 0) })}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  {t('limitsModal.inUseNow', { count: limit.current_domain })}
                  {limit.max_domain > 0 && limit.current_domain > limit.max_domain && (
                    <span className="text-amber-600 dark:text-amber-400">{t('limitsModal.limitBelowUsage')}</span>
                  )}
                </p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                  {t('limitsModal.diskQuota')}
                </label>
                <input
                  type="number"
                  min={0}
                  value={limit.disk_quota_mb}
                  onChange={(e) => setLimit({ ...limit, disk_quota_mb: Math.max(0, Number(e.target.value) || 0) })}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  {t('limitsModal.mbInUseNow', { count: limit.current_disk_mb })}
                  {limit.disk_quota_mb > 0 && limit.current_disk_mb > limit.disk_quota_mb && (
                    <span className="text-amber-600 dark:text-amber-400">{t('limitsModal.quotaBelowUsage')}</span>
                  )}
                </p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                  {t('limitsModal.trafficQuota')}
                </label>
                <input
                  type="number"
                  min={0}
                  value={limit.traffic_quota_mb}
                  onChange={(e) => setLimit({ ...limit, traffic_quota_mb: Math.max(0, Number(e.target.value) || 0) })}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  {t('limitsModal.mbUsedNow', { count: limit.current_traffic_mb })}
                  {limit.traffic_quota_mb > 0 && limit.current_traffic_mb > limit.traffic_quota_mb && (
                    <span className="text-amber-600 dark:text-amber-400">{t('limitsModal.quotaBelowUsage')}</span>
                  )}
                </p>
              </div>
            </div>
  )
}

function LimitsModal({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { limit, limitLoading, limitTarget, saveLimits, saving, setLimit, setLimitTarget } = ctx
  return (
    <>
      {/* Reseller limits */}
      <Modal open={limitTarget !== null} title={t('limitsModal.title')} onClose={() => { setLimitTarget(null); setLimit(null) }}>
        {limitLoading ? (
          <div className="py-8 text-center text-sm text-slate-400">{t('limitsModal.loading')}</div>
        ) : limit && limitTarget ? (
          <div className="space-y-4">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              {t('limitsModal.upperBounds')}<span className="font-mono">{limitTarget.username}</span>.
              <span className="block mt-1 text-xs text-slate-500">
                {t('limitsModal.unlimitedNote')}
              </span>
            </p>

            <LimitFields ctx={ctx} />
            {!limit.defined && (
              <div className="px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-900 text-xs text-slate-500 dark:text-slate-400">
                {t('limitsModal.noLimit')}
              </div>
            )}

            <p className="text-[11px] text-slate-400">
              {t('limitsModal.loweringNote')}
            </p>

            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => { setLimitTarget(null); setLimit(null) }} className="px-3.5 py-2 text-sm rounded-full text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition">
                {t('limitsModal.cancel')}
              </button>
              <button onClick={saveLimits} disabled={saving} className="px-3.5 py-2 text-sm font-medium rounded-full bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 transition">
                {saving ? t('limitsModal.saving') : t('limitsModal.save')}
              </button>
            </div>
          </div>
        ) : null}
      </Modal>
    </>
  )
}

function DeleteConfirm({ ctx }: { ctx: UsersCtx }) {
  const { t } = useTranslation('UsersPage')
  const { remove, setToDelete, toDelete } = ctx
  return (
    <>
      <ConfirmDialog
        open={toDelete !== null}
        title={t('delete.title')}
        message={t('delete.message', { username: toDelete?.username ?? '' }) + (toDelete?.role === 'reseller' ? t('delete.resellerNote') : '')}
        confirmText={t('delete.confirm')}
        dangerous
        onConfirm={remove}
        onCancel={() => setToDelete(null)}
      />
    </>
  )
}
