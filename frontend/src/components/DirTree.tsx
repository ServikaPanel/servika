import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/lib/api'

type Entry = { name: string; path: string; type: 'folder' | 'file' | 'symlink' }
type ListResp = { path: string; content: Entry[] }

interface Props {
  domainId: number | string
  selected: string
  onSelect: (path: string) => void
  refreshKey?: number // re-fetch when this counter changes (after new folder/delete)
}

export default function DirTree({ domainId, selected, onSelect, refreshKey }: Props) {
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-2 text-sm overflow-auto min-h-[400px]">
      <TreeNode
        domainId={domainId}
        path="/"
        name="~"
        selected={selected}
        onSelect={onSelect}
        initiallyOpen={true}
        depth={0}
        refreshKey={refreshKey}
      />
    </div>
  )
}

function TreeNode({
  domainId, path, name, selected, onSelect, initiallyOpen, depth, refreshKey
}: {
  domainId: number | string
  path: string
  name: string
  selected: string
  onSelect: (path: string) => void
  initiallyOpen: boolean
  depth: number
  refreshKey?: number
}) {
  const [open, setOpen] = useState(initiallyOpen)
  const [folders, setFolders] = useState<Entry[]>([])
  const [loaded, setLoaded] = useState(false)
  const rowRef = useRef<HTMLDivElement>(null)

  // No synchronous state write here, so the effects below can call it directly.
  // The former `loading` flag is gone: it was only read to show the placeholder
  // while the node had nothing yet, which is exactly `!loaded`.
  const fetchChildren = useCallback(() => {
    api.get<ListResp>(`/domains/${domainId}/files`, { params: { path } })
      .then(r => setFolders(r.data.content.filter(e => e.type === 'folder')))
      .catch(() => setFolders([]))
      .finally(() => setLoaded(true))
  }, [domainId, path])

  const { selectedNorm, onSelectedBranch } = nodePaths(path, selected)

  // When a folder is entered from the right-hand panel (selected changes), this
  // node auto-opens if it is on or above that path — otherwise the folder browsed
  // on the right would never appear in the tree (it stayed unfetched/closed).
  // Opening is a reaction to the new selection, so it is adjusted during render;
  // the fetch it implies is left to the effect below, since render must stay pure.
  const [autoOpenedFor, setAutoOpenedFor] = useState(selected)
  if (autoOpenedFor !== selected) {
    setAutoOpenedFor(selected)
    if (onSelectedBranch && !open) setOpen(true)
  }

  // One place decides that an open node without children needs them, whether it
  // was opened at mount, by the chevron, or by the selection above.
  useEffect(() => {
    if (open && !loaded) fetchChildren()
  }, [open, loaded, fetchChildren])

  // Re-fetch if the refresh counter changes and we already have data.
  useEffect(() => {
    if (loaded) fetchChildren()
    // Deliberately keyed on refreshKey alone: re-running on `loaded` would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey])

  // The target folder's own row scrolls into view so a folder entered from the
  // right does not stay off-screen in a deep tree.
  useEffect(() => {
    if (path === selectedNorm) rowRef.current?.scrollIntoView({ block: 'nearest' })
  }, [path, selectedNorm])

  function handleChevronClick(e: React.MouseEvent) {
    e.stopPropagation()
    setOpen(!open)
  }

  const hasChildren = !loaded || folders.length > 0

  return (
    <div>
      <NodeRow
        rowRef={rowRef}
        path={path}
        name={name}
        depth={depth}
        open={open}
        hasChildren={hasChildren}
        isSelected={isSelectedNode(path, selected)}
        onSelect={onSelect}
        onChevron={handleChevronClick}
      />

      <ChildNodes
        open={open}
        loaded={loaded}
        folders={folders}
        depth={depth}
        domainId={domainId}
        selected={selected}
        selectedNorm={selectedNorm}
        onSelect={onSelect}
        refreshKey={refreshKey}
      />
    </div>
  )
}

// nodePaths normalises the selection against this node's own path. An empty
// selection means the home directory, which the tree draws as "/".
function nodePaths(path: string, selected: string) {
  const selectedNorm = selected === '' ? '/' : selected
  const childPrefix = path === '/' ? '/' : path + '/'
  return {
    selectedNorm,
    onSelectedBranch: selectedNorm === path || selectedNorm.startsWith(childPrefix),
  }
}

// isSelectedNode reports whether this row is the selected folder. The home
// directory answers to three spellings, because the right-hand panel and the
// saved cookie do not write it the same way.
function isSelectedNode(path: string, selected: string): boolean {
  if (path === selected) return true
  return path === '/' && (selected === '' || selected === '/')
}

// NodeRow is one folder line: the chevron, the icon and the name.
function NodeRow({ rowRef, path, name, depth, open, hasChildren, isSelected, onSelect, onChevron }: {
  rowRef: React.RefObject<HTMLDivElement | null>
  path: string
  name: string
  depth: number
  open: boolean
  hasChildren: boolean
  isSelected: boolean
  onSelect: (path: string) => void
  onChevron: (e: React.MouseEvent) => void
}) {
  return (
    <div
      ref={rowRef}
      onClick={() => onSelect(path)}
      className={`flex items-center gap-1 px-2 py-1 rounded cursor-pointer transition ${
        isSelected ? 'bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300' : 'hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
      }`}
      style={{ paddingLeft: 8 + depth * 14 }}
      title={path}
    >
      {hasChildren ? (
        <button
          onClick={onChevron}
          className="w-4 h-4 flex items-center justify-center text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 dark:text-slate-300"
        >
          <svg
            className={`w-3 h-3 transition-transform ${open ? 'rotate-90' : ''}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      ) : (
        <span className="w-4" />
      )}
      <svg className="w-4 h-4 text-amber-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
        <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
      </svg>
      <span className="truncate text-sm">{name}</span>
    </div>
  )
}

// ChildNodes draws the sub-folders of an open node.
function ChildNodes({ open, loaded, folders, depth, domainId, selected, selectedNorm, onSelect, refreshKey }: {
  open: boolean
  loaded: boolean
  folders: Entry[]
  depth: number
  domainId: number | string
  selected: string
  selectedNorm: string
  onSelect: (path: string) => void
  refreshKey?: number
}) {
  if (!open) return null
  return (
    <div>
      {!loaded && folders.length === 0 && (
        <div className="px-3 py-1 text-xs text-slate-400 dark:text-slate-500" style={{ paddingLeft: 24 + depth * 14 }}>
          loading…
        </div>
      )}
      {folders.map(k => (
        <TreeNode
          key={k.path}
          domainId={domainId}
          path={k.path}
          name={k.name}
          selected={selected}
          onSelect={onSelect}
          // A child opens at mount when it is on (or is) the selected branch,
          // so a deep path restored from the saved cookie is expanded all the
          // way down on first render. The runtime auto-open in TreeNode handles
          // a selection that changes later; this handles the initial one, which
          // that logic (keyed on a change of `selected`) does not.
          initiallyOpen={selectedNorm === k.path || selectedNorm.startsWith(k.path + '/')}
          depth={depth + 1}
          refreshKey={refreshKey}
        />
      ))}
    </div>
  )
}