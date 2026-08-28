// Shared SVG icon renderer — consistent line icons across the panel (instead of emoji).
// The path dictionary lives in ./iconPaths; import { ICON } from there.
// Usage: <Icon d={ICON.lock} /> · <Icon d={ICON.trash} className="h-5 w-5" />
// Multi-path glyphs separate their sub-paths with '|'.

export function Icon({ d, className = 'h-4 w-4' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      {d.split('|').map((p, i) => <path key={i} d={p} />)}
    </svg>
  )
}

export default Icon
