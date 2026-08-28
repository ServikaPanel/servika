import type { ReactNode } from 'react'
import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { api, apiError } from '@/lib/api'
import Breadcrumb from '@/components/Breadcrumb'
import ResourceNotice from '@/components/ResourceNotice'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'

type Mode = 'inherit' | 'off' | 'block' | 'detect'
type Settings = { mode: Mode; paranoia: number }
type PlanInfo = { active: boolean; mode: string; paranoia: number; name?: string }
type Effective = { active: boolean; engine: string; paranoia: number }
type Response = {
  domain_name: string
  settings: Settings
  plan: PlanInfo
  effective: Effective
  module_loaded: boolean
}

const MODES: { key: Mode; icon: string; color: string }[] = [
  { key: 'inherit', icon: '↩︎', color: 'slate' },
  { key: 'block', icon: ICON.shield, color: 'emerald' },
  { key: 'detect', icon: ICON.eye, color: 'indigo' },
  { key: 'off', icon: ICON.ban, color: 'rose' },
]

export default function DomainWafPage() {
  const { t } = useTranslation('DomainWafPage')
  const { id } = useParams()
  const [data, setData] = useState<Response | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Split so the mount effect never writes state synchronously: fetchWaf settles
  // only through promise callbacks, and load() adds the spinner for the reload
  // button and the post-save refresh.
  const fetchWaf = useCallback(() => {
    if (!id) return
    api.get<Response>(`/domains/${id}/waf`)
      .then(r => { setData(r.data); setSettings(r.data.settings) })
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchWaf()
  }, [fetchWaf])

  useEffect(() => { fetchWaf() }, [fetchWaf])

  async function save() {
    if (!settings) return
    setSaving(true); setError(null); setSuccess(null)
    try {
      const r = await api.put<{ effective: Effective; module_loaded: boolean }>(`/domains/${id}/waf`, { settings })
      const ef = r.data.effective
      setSuccess(ef.active
        ? (ef.engine === 'On'
          ? t('messages.appliedBlocking', { paranoia: ef.paranoia })
          : t('messages.appliedDetection', { paranoia: ef.paranoia }))
        : t('messages.savedPassive'))
      load()
    } catch (e) {
      setError(apiError(e, t('errors.saveFailed')))
    } finally {
      setSaving(false)
    }
  }

  // The level the server will actually run, which is what the cost warning is
  // about: a domain that inherits (mode inherit, or paranoia 0) takes the plan's
  // level, and nothing runs at all while the mode is off. This mirrors
  // provisioner.WAFEffective.
  const paranoiaInEffect =
    !settings || !data || settings.mode === 'off' ? 0
      : settings.mode === 'inherit' ? (data.plan.active ? data.plan.paranoia : 0)
        : settings.paranoia || data.plan.paranoia

  return (
    <div className="w-full px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' }, { label: t('breadcrumb.domains'), href: '/domains' },
        { label: data?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.waf') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {data && <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
        <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 font-medium">{data.domain_name}</Link>
        {t('subtitle')}
      </p>}

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap">{error}</div>}
      {success && <div className="mb-3 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-md text-sm text-emerald-700 dark:text-emerald-300">{success}</div>}

      {data && !data.module_loaded && (
        <div className="mb-5 px-3 py-2.5 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md text-xs text-amber-800 dark:text-amber-200">
          <strong>{t('moduleWarning.bold')}</strong>{t('moduleWarning.pre')}<code className="font-mono">servika-waf-setup</code>{t('moduleWarning.post')}
        </div>
      )}

      {loading || !settings || !data ? (
        <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
      ) : (
        <>
          {/* Effective status + plan info */}
          <div className="mb-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('effective.label')}</span>
              {data.effective.active ? (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                  data.effective.engine === 'On'
                    ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300'
                    : 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300'
                }`}>
                  {'●'} {data.effective.engine === 'On' ? t('effective.blocking') : t('effective.detection')} · {t('effective.paranoia', { level: data.effective.paranoia })}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">{'○'} {t('effective.passive')}</span>
              )}
              <span className="text-xs text-slate-400 dark:text-slate-500 ml-auto">
                {t('effective.planDefault', { name: data.plan.name || '—' })}
                {data.plan.active ? (data.plan.mode === 'detect' ? t('effective.planDetect', { paranoia: data.plan.paranoia }) : t('effective.planBlock', { paranoia: data.plan.paranoia })) : t('effective.planOff')}
              </span>
            </div>
          </div>

          {/* Mode selector */}
          <Card title={t('modeCard.title')}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {MODES.map(m => {
                const active = settings.mode === m.key
                const colors: Record<string, string> = {
                  slate:   active ? 'border-slate-500 bg-slate-100 dark:bg-slate-700/40 ring-2 ring-slate-400/20' : 'border-slate-200 dark:border-slate-700 hover:border-slate-400',
                  emerald: active ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 ring-2 ring-emerald-500/20' : 'border-slate-200 dark:border-slate-700 hover:border-emerald-300',
                  indigo:  active ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 ring-2 ring-indigo-500/20' : 'border-slate-200 dark:border-slate-700 hover:border-indigo-300',
                  rose:    active ? 'border-rose-500 bg-rose-50 dark:bg-rose-900/20 ring-2 ring-rose-500/20' : 'border-slate-200 dark:border-slate-700 hover:border-rose-300',
                }
                return (
                  <button key={m.key} type="button" onClick={() => setSettings({ ...settings, mode: m.key })}
                    className={`text-left p-4 border rounded-xl transition ${colors[m.color]}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-900 dark:text-slate-100"><Icon d={m.icon} className="h-4 w-4" /> {t(`modes.${m.key}.name`)}</span>
                      {active && <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">{'●'} {t('modeCard.selected')}</span>}
                    </div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">{t(`modes.${m.key}.description`)}</div>
                  </button>
                )
              })}
            </div>
          </Card>

          {/* Paranoia */}
          <Card title={t('paranoiaCard.title')}>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-3">
              {t('paranoiaCard.hint.pre')}<strong>{t('paranoiaCard.hint.block')}</strong>{t('paranoiaCard.hint.mid')}<strong>{t('paranoiaCard.hint.detect')}</strong>{t('paranoiaCard.hint.post')}
            </p>
            <div className="flex items-center gap-3">
              <select
                value={settings.paranoia}
                onChange={e => setSettings({ ...settings, paranoia: parseInt(e.target.value) })}
                disabled={settings.mode === 'inherit' || settings.mode === 'off'}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-800 rounded text-sm font-mono disabled:opacity-50">
                <option value={0}>{t('paranoiaCard.options.inherit')}</option>
                <option value={1}>{t('paranoiaCard.options.level1')}</option>
                <option value={2}>{t('paranoiaCard.options.level2')}</option>
                <option value={3}>{t('paranoiaCard.options.level3')}</option>
                <option value={4}>{t('paranoiaCard.options.level4')}</option>
              </select>
              <span className="text-xs text-slate-500 dark:text-slate-400">{t(`paranoiaDescription.${settings.paranoia}`)}</span>
            </div>
            {paranoiaInEffect >= 3 && (
              <div className="mt-3">
                <ResourceNotice>{t('paranoiaCard.highLevelWarning')}</ResourceNotice>
              </div>
            )}
          </Card>

          <div className="flex gap-3 mt-6">
            <button onClick={save} disabled={saving}
              className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm font-medium rounded-md">
              {saving ? t('actions.saving') : t('actions.save')}
            </button>
            <button onClick={load} disabled={saving}
              className="px-4 py-2.5 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm rounded-md">
              {t('actions.reload')}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-5 mb-4">
      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3 pb-2 border-b border-slate-100 dark:border-slate-800">{title}</h3>
      {children}
    </div>
  )
}
