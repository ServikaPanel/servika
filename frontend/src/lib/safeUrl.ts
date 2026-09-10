/**
 * Returns the value when a browser may navigate to it, and null otherwise.
 *
 * React escapes JSX text and attribute values, but it does NOT check the SCHEME
 * of an href, so a `javascript:` URI that reaches one runs in the panel origin
 * when somebody clicks it. Several of the URLs this panel displays are written
 * by a hosting customer (a WordPress `siteurl`) or by a third-party advisory
 * feed, so every full URL that comes from data rather than from a template
 * literal is passed through here before it becomes a link.
 *
 * The schemes are an ALLOWLIST. A list of refused schemes would have to name
 * `data:`, `vbscript:`, `blob:` and whatever a browser ships next; this way an
 * unknown scheme is refused by default.
 *
 * A relative path is refused too, because this is used only where the value is
 * a full URL. The panel's own relative links are built from template literals
 * and never reach here.
 */
export function safeHref(value: string | null | undefined): string | null {
  if (!value) return null
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return null
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? value : null
}
