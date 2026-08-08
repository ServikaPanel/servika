/**
 * Country names come from the browser, never from the panel's translation
 * files. There are roughly 250 ISO codes and twelve interface languages, so
 * carrying the names here would mean three thousand strings that the browser
 * already holds, already localizes and already keeps current.
 *
 * The resolver is built once per language and reused, because constructing an
 * Intl.DisplayNames per row is measurably slower than the list it renders.
 */
export function countryNamer(language: string): (code: string) => string {
  const display = new Intl.DisplayNames([language, 'en'], { type: 'region' })
  return code => (/^[A-Z]{2}$/.test(code) ? display.of(code) || code : code)
}

/**
 * The flag is derived from the code rather than shipped as an image: the two
 * regional indicator symbols for a country's letters ARE its flag in every
 * font that carries them, and a font that does not simply shows the letters.
 */
export function countryFlag(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return ''
  return String.fromCodePoint(...[...code].map(letter => 0x1f1e6 + letter.charCodeAt(0) - 65))
}

/** Sorts codes by their name in the reader's language, not by the code. */
export function sortByName(codes: string[], nameOf: (code: string) => string): string[] {
  return codes.slice().sort((left, right) => nameOf(left).localeCompare(nameOf(right)))
}
