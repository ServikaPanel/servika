import { useTranslation } from 'react-i18next'
import Breadcrumb from '@/components/Breadcrumb'
import ServerOptimizeCard from '@/components/ServerOptimizeCard'
import TuningProposals from '@/components/TuningProposals'

/*
 * Server Optimize — dedicated page (also linked from the sidebar).
 * The job runs via systemd-run transient unit in the background; survives
 * tab/browser close, status is read from the server (resume-on-reopen).
 * Below it, the parameter-by-parameter surface: one proposal at a time, with
 * what the host has now beside what would be written, and a history that can
 * put any single change back.
 */
export default function ServerOptimizePage() {
  const { t } = useTranslation('ServerOptimizePage')
  return (
    <div className="px-6 py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.toolsAndSettings'), href: '/tools-settings' },
        { label: t('breadcrumb.serverOptimize') },
      ]} />

      <div className="mb-5 max-w-3xl">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('title')}</h1>
        <p className="mt-1 text-sm leading-relaxed text-slate-500 dark:text-slate-400">
          {t('description')}
        </p>
      </div>

      <div className="max-w-3xl">
        <ServerOptimizeCard />
      </div>

      <div className="mt-6 max-w-5xl">
        <TuningProposals />
      </div>
    </div>
  )
}
