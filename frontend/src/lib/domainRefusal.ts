import { useTranslation } from 'react-i18next'
import { apiError } from '@/lib/api'

/**
 * Words the two refusals any hostname-creating screen can receive.
 *
 * The server answers with a stable CODE rather than a sentence, because the API
 * is English and the interface ships twelve languages. The wording is identical
 * on every one of these screens, so it lives once in the `common` namespace
 * rather than being repeated per page: four copies of the same sentence in
 * twelve files is four chances for one of them to say something else.
 *
 * Anything that is not one of these codes is passed through as the server wrote
 * it, so a new refusal is never swallowed.
 */
export function useDomainRefusal() {
  const { t } = useTranslation('common')
  return (cause: unknown, fallback: string): string => {
    switch (apiError(cause, '')) {
      case 'domain_name_is_blocked':
        return t('domainBlocked')
      case 'domain_block_list_unreadable':
        return t('domainBlockListUnreadable')
      default:
        return apiError(cause, fallback)
    }
  }
}
