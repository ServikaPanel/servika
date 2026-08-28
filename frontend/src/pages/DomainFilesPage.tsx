import type { AxiosProgressEvent } from 'axios'
import { useCallback, useEffect, useLayoutEffect, useState, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams, Link } from 'react-router'
import { api, apiError as apiError } from '@/lib/api'
import { useReportError } from '@/lib/errors'
import { useDialog } from '@/lib/dialog'
import Breadcrumb from '@/components/Breadcrumb'
import DirTree from '@/components/DirTree'
import CodeEditor from '@/components/CodeEditor'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import {
  responsiveTableActionCellClass,
  responsiveTableBodyClass,
  responsiveTableCellClass,
  responsiveTableClass,
  responsiveTableCodeCellClass,
  responsiveTableContainerClass,
  responsiveTableHeadClass,
  responsiveTableRowClass,
} from '@/lib/table'

type Entry = {
  name: string
  path: string
  type: 'folder' | 'file' | 'symlink'
  size_b: number
  mode: string
  permissions: string
  owner: string
  group: string
  changed: string
}

type ListResp = { path: string; content: Entry[]; total: number }
type Domain = { id: number; domain_name: string; system_user: string }

type CtxItem =
  | { separator: true; key: string }
  | { separator?: false; key: string; label: string; icon: string; onClick: () => void; danger?: boolean }

const ARCHIVE_RX = /\.(zip|rar|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|gz)$/i


export default function DomainFilesPage() {
  const { t } = useTranslation('DomainFilesPage')
  const report = useReportError()
  // An action the user just triggered reports through the dialog, not through
  // `report`: that surface is throttled to one banner per context every 30s and
  // caps at four, which is right for background loads and wrong here, where
  // retrying a failing delete twice would drop the second failure on the floor.
  const { confirm, ask, notify } = useDialog()
  const { id } = useParams()
  const [domain, setDomain] = useState<Domain | null>(null)
  const [path, setPath] = useState<string>('/public_html')
  const [content, setContent] = useState<Entry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [editor, setEditor] = useState<{path: string; content: string} | null>(null)
  const [chmodFor, setChmodFor] = useState<Entry | null>(null)
  const [treeRefreshKey, setTreeRefreshKey] = useState(0)
  const [dragCounter, setDragCounter] = useState(0)
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set())
  const [bulkDeleteConfirmOpen, setBulkDeleteConfirmOpen] = useState(false)
  const [newMenuOpen, setNewMenuOpen] = useState(false)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entry: Entry } | null>(null)
  const longPressRef = useRef<number | undefined>(undefined)
  const longPressTriggeredRef = useRef(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<Entry[] | null>(null)
  const [copyMoveModal, setCopyModal] = useState<{ type: 'copy' | 'move'; paths: string[] } | null>(null)
  const [archiveModal, setArchiveModal] = useState(false)
  const [extractJob, setExtractJob] = useState<{ done: number; total: number } | null>(null)
  const [newFileModal, setNewFileModal] = useState(false)
  const [sizeResult, setSizeResult] = useState<{ path: string; size: number } | null>(null)
  const [bulkUpload, setBulkUpload] = useState<{
    completed: number
    total: number
    activeFile: string
    activeIndex: number
    uploadedBytes: number    // Current file.
    totalBytes: number      // Current file.
    speedBps: number          // Bytes per second.
    etaSeconds: number           // Seconds.
    percent: number
  } | null>(null)
  const [renameFor, setRenameFor] = useState<Entry | null>(null)

  useEffect(() => {
    if (!id) return
    api.get<Domain>(`/domains/${id}`).then(r => setDomain(r.data)).catch(report('subscription'))
  }, [id, report])

  // Split so the directory effect never writes state synchronously: fetchEntries
  // settles only through promise callbacks, and scan() adds the spinner for the
  // refreshes that follow a file operation.
  const fetchEntries = useCallback(() => {
    if (!id) return
    api.get<ListResp>(`/domains/${id}/files`, { params: { path } })
      .then(r => setContent(r.data.content))
      .catch(e => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [id, path])

  const scan = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchEntries()
  }, [fetchEntries])

  useEffect(() => { fetchEntries() }, [fetchEntries])

  // Cleared during render rather than in an effect: a selection that survives
  // into another directory would let a bulk action target paths that are no
  // longer on screen.
  const [selectionPath, setSelectionPath] = useState(path)
  if (path !== selectionPath) {
    setSelectionPath(path)
    setSelectedPaths(new Set())
  }

  function navigateTo(newPath: string) {
    setPath(newPath)
  }

  function goUp() {
    if (path === '/' || path === '') return
    const parts = path.split('/').filter(Boolean)
    parts.pop()
    setPath('/' + parts.join('/'))
  }

  async function remove(e: Entry) {
    if (!(await confirm({ message: t('prompt.deleteConfirm', { name: e.name }), dangerous: true }))) return
    try {
      await api.delete(`/domains/${id}/files`, { params: { path: e.path } })
      setTreeRefreshKey(x => x + 1)
      scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.deleteFailed')), tone: 'error' })
    }
  }

  async function createFolder() {
    const name = await ask({ message: t('prompt.newFolderName') })
    if (!name) return
    const target = (path === '/' ? '' : path) + '/' + name
    try {
      await api.post(`/domains/${id}/files/mkdir`, { path: target })
      setTreeRefreshKey(x => x + 1)
      scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.createFolderFailed')), tone: 'error' })
    }
  }

  async function openEditor(e: Entry) {
    if (e.type !== 'file') return
    try {
      const { data } = await api.get<{path: string; content: string}>(`/domains/${id}/files/read`, { params: { path: e.path } })
      setEditor({ path: e.path, content: data.content })
    } catch (err) {
      await notify({ message: apiError(err, t('errors.openFailed')), tone: 'error' })
    }
  }

  async function saveEditor() {
    if (!editor) return
    try {
      await api.post(`/domains/${id}/files/write`, { path: editor.path, content: editor.content })
      setEditor(null); scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.saveFailed')), tone: 'error' })
    }
  }

  async function rename(entry: Entry, newName: string) {
    if (!newName || newName === entry.name) return
    const parts = entry.path.split('/')
    parts[parts.length - 1] = newName
    const newPath = parts.join('/')
    try {
      await api.post(`/domains/${id}/files/rename`, { old: entry.path, new: newPath })
      setRenameFor(null); setTreeRefreshKey(x => x + 1); scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.renameFailed')), tone: 'error' })
    }
  }

  async function changePermissions(e: Entry, mode: string) {
    try {
      await api.post(`/domains/${id}/files/chmod`, { path: e.path, mode })
      setChmodFor(null); scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.chmodFailed')), tone: 'error' })
    }
  }

  // Upload one File object through the helper shared by drag and drop and the file input.
  async function uploadFileSingle(f: File, onProgress?: (loaded: number, total: number) => void): Promise<boolean> {
    const fd = new FormData()
    fd.append('file', f)
    try {
      await api.post(`/domains/${id}/files/upload`, fd, {
        timeout: 0, // large upload: disable client timeout (backend 30m ceiling)
        params: { path },
        onUploadProgress: (e: AxiosProgressEvent) => {
          if (onProgress && typeof e.loaded === 'number') {
            onProgress(e.loaded, e.total || f.size)
          }
        },
      })
      return true
    } catch (err) {
      console.error('upload error', f.name, err)
      return false
    }
  }

  async function uploadFiles(files: File[]) {
    if (!files.length) return
    setBulkUpload({
      completed: 0, total: files.length, activeFile: files[0].name, activeIndex: 0,
      uploadedBytes: 0, totalBytes: files[0].size,
      speedBps: 0, etaSeconds: 0, percent: 0,
    })
    let successful = 0
    for (let i = 0; i < files.length; i++) {
      const f = files[i]
      // Track the start time and previous sample for per-file transfer speed.
      const t0 = performance.now()
      let lastMeasurementTime = t0
      let latestByte = 0

      const ok = await uploadFileSingle(f, (loaded, total) => {
        const now = performance.now()
        const dt = (now - lastMeasurementTime) / 1000
        const db = loaded - latestByte
        let speed = 0
        if (dt > 0.05) {
          speed = db / dt
          lastMeasurementTime = now
          latestByte = loaded
        }
        // Smoothed overall speed.
        const totalDt = (now - t0) / 1000
        const averageSpeed = totalDt > 0.1 ? loaded / totalDt : 0
        const remainingBytes = Math.max(0, total - loaded)
        const eta = averageSpeed > 0 ? remainingBytes / averageSpeed : 0
        const percent = total > 0 ? (loaded / total) * 100 : 0
        setBulkUpload(prev => prev ? {
          ...prev,
          completed: i, activeFile: f.name, activeIndex: i,
          uploadedBytes: loaded, totalBytes: total,
          speedBps: speed > 0 ? speed : averageSpeed,
          etaSeconds: eta,
          percent,
        } : null)
      })
      if (ok) successful++
    }
    setBulkUpload(null)
    setTreeRefreshKey(x => x + 1)
    scan()
    if (successful < files.length) {
      await notify({ message: t('toast.uploadPartial', { success: successful, total: files.length }), tone: 'error' })
    }
  }


  function toggleSelection2(path: string) {
    setSelectedPaths(prev => {
      const nextSelectedPaths = new Set(prev)
      if (nextSelectedPaths.has(path)) nextSelectedPaths.delete(path); else nextSelectedPaths.add(path)
      return nextSelectedPaths
    })
  }
  function selectAllItems(selectAll: boolean) {
    if (selectAll) setSelectedPaths(new Set(content.map(e => e.path)))
    else setSelectedPaths(new Set())
  }

  async function bulkDelete() {
    setBulkDeleteConfirmOpen(false)
    const paths = Array.from(selectedPaths)
    let successful = 0
    for (const y of paths) {
      try {
        await api.delete(`/domains/${id}/files`, { params: { path: y } })
        successful++
      } catch (err) {
        console.error('remove error', y, err)
      }
    }
    setSelectedPaths(new Set())
    setTreeRefreshKey(x => x + 1)
    scan()
    if (successful < paths.length) {
      await notify({ message: t('toast.deletePartial', { success: successful, total: paths.length }), tone: 'error' })
    }
  }

  async function pollExtract(jobId: string) {
    try {
      const { data } = await api.get(`/domains/${id}/files/extract-progress`, { params: { job: jobId } })
      if (data.state === 'running') {
        setExtractJob({ done: data.done || 0, total: data.total || 0 })
        setTimeout(() => { pollExtract(jobId) }, 1000)
        return
      }
      setExtractJob(null)
      if (data.state === 'failed') {
        await notify({ message: t('errors.extractFailed'), tone: 'error' })
        return
      }
      setTreeRefreshKey(x => x + 1)
      scan()
    } catch (err) {
      setExtractJob(null)
      await notify({ message: apiError(err, t('errors.extractFailed')), tone: 'error' })
    }
  }

  async function extract(e: Entry) {
    try {
      const { data } = await api.post(`/domains/${id}/files/extract`, { path: e.path })
      // A multi-member archive extracts asynchronously and returns a job id to
      // poll; a single gzip file finishes synchronously with no job id.
      if (data?.job_id) {
        setExtractJob({ done: 0, total: 0 })
        pollExtract(data.job_id)
        return
      }
      setTreeRefreshKey(x => x + 1)
      scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.extractFailed')), tone: 'error' })
    }
  }

  async function search() {
    if (!searchQuery.trim()) { setSearchResults(null); return }
    try {
      const { data } = await api.get(`/domains/${id}/files/search`, { params: { q: searchQuery, path } })
      setSearchResults(data.content)
    } catch (err) {
      await notify({ message: apiError(err, t('errors.searchFailed')), tone: 'error' })
    }
  }

  // Context menu: right-click does NOT change selection; single-item actions use
  // ctxMenu.entry directly. Multi-select via checkboxes is preserved.
  function openContext(clientX: number, clientY: number, entry: Entry) {
    setContextMenu({ x: clientX, y: clientY, entry })
  }

  function rowContext(ev: React.MouseEvent, entry: Entry) {
    ev.preventDefault()
    openContext(ev.clientX, ev.clientY, entry)
  }

  function touchStart(ev: React.TouchEvent, entry: Entry) {
    if (ev.touches.length !== 1) return
    const t = ev.touches[0]
    const cx = t.clientX, cy = t.clientY
    longPressTriggeredRef.current = false
    longPressRef.current = window.setTimeout(() => {
      longPressTriggeredRef.current = true
      openContext(cx, cy, entry)
    }, 500)
  }

  function touchEnd(ev: React.TouchEvent) {
    if (longPressRef.current !== undefined) { clearTimeout(longPressRef.current); longPressRef.current = undefined }
    if (longPressTriggeredRef.current) { ev.preventDefault() }
  }

  function touchMove() {
    if (longPressRef.current !== undefined) { clearTimeout(longPressRef.current); longPressRef.current = undefined }
  }

  function buildCtxItems(): CtxItem[] {
    if (!contextMenu) return []
    const e = contextMenu.entry
    const multi = selectedPaths.has(e.path) && selectedPaths.size > 1
    const closeAfter = (fn: () => void) => () => { setContextMenu(null); fn() }
    const items: CtxItem[] = []

    if (!multi) {
      if (e.type === 'folder') {
        items.push({ key: 'open', label: t('context.open'), icon: ICON.folderOpen, onClick: closeAfter(() => navigateTo(e.path)) })
      } else {
        if (docrootRelativePath(e.path) !== null)
          items.push({ key: 'browse', label: t('context.browse'), icon: ICON.globe, onClick: closeAfter(() => openInBrowser(e)) })
        items.push({ key: 'edit', label: t('context.edit'), icon: ICON.pencil, onClick: closeAfter(() => openEditor(e)) })
      }
    }

    items.push({ key: 'download', label: t('context.download'), icon: ICON.download, onClick: closeAfter(() => download(e)) })
    items.push({ separator: true, key: 's1' })
    items.push({ key: 'rename', label: t('context.rename'), icon: ICON.text, onClick: closeAfter(() => setRenameFor(e)) })
    items.push({ key: 'perms', label: t('context.permissions'), icon: ICON.lock, onClick: closeAfter(() => setChmodFor(e)) })
    items.push({ key: 'size', label: t('context.calculateSize'), icon: ICON.ruler, onClick: closeAfter(() => calculateSize(e.path)) })

    if (e.type !== 'folder' && ARCHIVE_RX.test(e.name)) {
      items.push({ key: 'extract', label: t('context.extract'), icon: ICON.box, onClick: closeAfter(() => extract(e)) })
    }

    items.push({ separator: true, key: 's2' })
    items.push({ key: 'copy', label: t('context.copy'), icon: ICON.clipboard, onClick: closeAfter(() => {
      const paths = multi ? Array.from(selectedPaths) : [e.path]
      setCopyModal({ type: 'copy', paths })
    })})
    items.push({ key: 'move', label: t('context.move'), icon: ICON.move, onClick: closeAfter(() => {
      const paths = multi ? Array.from(selectedPaths) : [e.path]
      setCopyModal({ type: 'move', paths })
    })})
    items.push({ separator: true, key: 's3' })
    items.push({ key: 'delete', label: t('context.delete'), icon: ICON.trash, onClick: closeAfter(() => remove(e)), danger: true })

    return items
  }

  async function copyOrMove(target: string) {
    if (!copyMoveModal) return
    const url = copyMoveModal.type === 'copy' ? 'copy' : 'move'
    try {
      const { data } = await api.post(`/domains/${id}/files/${url}`, {
        sources: copyMoveModal.paths, target,
      })
      setCopyModal(null); setSelectedPaths(new Set())
      setTreeRefreshKey(x => x + 1); scan()
      if (data.errors?.length) {
        await notify({ message: t('toast.someErrors', { errors: data.errors.join('\n') }), tone: 'error' })
      }
    } catch (err) {
      await notify({
        message: apiError(err, copyMoveModal.type === 'copy' ? t('errors.copyFailed') : t('errors.moveFailed')),
        tone: 'error',
      })
    }
  }

  async function archive(outputName: string, format: 'zip' | 'tar.gz') {
    const paths = Array.from(selectedPaths)
    if (paths.length === 0) return
    const outputPath = (path === '/' ? '' : path) + '/' + outputName + (format === 'zip' ? '.zip' : '.tar.gz')
    try {
      await api.post(`/domains/${id}/files/archive`, { resources: paths, output_path: outputPath, format })
      setArchiveModal(false); setSelectedPaths(new Set())
      setTreeRefreshKey(x => x + 1); scan()
    } catch (err) {
      await notify({ message: apiError(err, t('errors.archiveFailed')), tone: 'error' })
    }
  }

  async function createNewFile(name: string) {
    const target = (path === '/' ? '' : path) + '/' + name
    try {
      await api.post(`/domains/${id}/files/new-file`, { path: target })
      setNewFileModal(false); scan()
      // Open the new file directly in the editor.
      const readResponse = await api.get(`/domains/${id}/files/read`, { params: { path: target } })
      setEditor({ path: target, content: readResponse.data.content })
    } catch (err) {
      await notify({ message: apiError(err, t('errors.createFailed')), tone: 'error' })
    }
  }

  async function calculateSize(itemPath: string) {
    try {
      const { data } = await api.get(`/domains/${id}/files/size`, { params: { path: itemPath } })
      setSizeResult({ path: itemPath, size: data.size_b })
    } catch (err) {
      await notify({ message: apiError(err, t('errors.sizeFailed')), tone: 'error' })
    }
  }

  function handleDragEnter(e: React.DragEvent) {
    if (!Array.from(e.dataTransfer.types).includes('Files')) return
    e.preventDefault()
    setDragCounter(x => x + 1)
  }
  function handleDragLeave(e: React.DragEvent) {
    if (!Array.from(e.dataTransfer.types).includes('Files')) return
    e.preventDefault()
    setDragCounter(x => Math.max(0, x - 1))
  }
  function handleDragOver(e: React.DragEvent) {
    if (!Array.from(e.dataTransfer.types).includes('Files')) return
    e.preventDefault()
    e.dataTransfer.dropEffect = 'copy'
  }
  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragCounter(0)
    const dt = e.dataTransfer
    if (!dt || dt.files.length === 0) return
    uploadFiles(Array.from(dt.files))
  }

  function download(e: Entry) {
    const url = `/api/v1/domains/${id}/files/download?path=${encodeURIComponent(e.path)}`
    // Use fetch + blob; auth via the HttpOnly session cookie (same-origin).
    fetch(url, { credentials: 'include' })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = e.name
        a.click()
        setTimeout(() => URL.revokeObjectURL(a.href), 1000)
      })
      .catch(err => notify({ message: t('toast.downloadFailed', { message: err.message }), tone: 'error' }))
  }

  function openInBrowser(entry: Entry) {
    if (!domain || entry.type !== 'file') return
    const relativePath = docrootRelativePath(entry.path)
    if (relativePath === null) return
    const encodedPath = relativePath.split('/').map(segment => encodeURIComponent(segment)).join('/')
    window.open(`https://${domain.domain_name}${encodedPath}`, '_blank', 'noopener,noreferrer')
  }

  const parts = path.split('/').filter(Boolean)

  return (
    <div className="px-4 py-4 sm:px-6 sm:py-5">
      <Breadcrumb items={[
        { label: t('breadcrumb.home'), href: '/' },
        { label: t('breadcrumb.domains'), href: '/domains' },
        { label: domain?.domain_name || '...', href: `/subscriptions/${id}` },
        { label: t('breadcrumb.files') },
      ]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mb-1">{t('title')}</h1>
      {domain && (
        <p className="text-sm text-slate-500 dark:text-slate-500 mb-5">
          <Link to={`/subscriptions/${id}`} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium">{domain.domain_name}</Link>
          {', '}
          <span className="font-mono text-slate-600 dark:text-slate-400 dark:text-slate-500">/home/{domain.system_user}</span>
        </p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[13rem_minmax(0,1fr)] gap-4">
        <aside>
          <DirTree domainId={id!} selected={path} onSelect={setPath} refreshKey={treeRefreshKey} />
        </aside>
        <section
          className={`relative min-w-0 ${dragCounter > 0 ? "ring-2 ring-brand-500 ring-offset-2 ring-offset-slate-50 rounded-lg" : ""}`}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
      {dragCounter > 0 && (
        <div className="absolute inset-0 z-30 border-2 border-dashed border-brand-500 bg-brand-50 dark:bg-brand-900/20 backdrop-blur-sm rounded-lg flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <svg className="w-14 h-14 mx-auto text-brand-600 dark:text-brand-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            <div className="text-lg font-semibold text-brand-700 dark:text-brand-300">{t('dropZone.title')}</div>
            <div className="text-sm text-brand-600 dark:text-brand-400/80 mt-1">{t('dropZone.targetDir')}<code className="font-mono bg-white dark:bg-slate-800/60 px-1.5 py-0.5 rounded">{path}</code></div>
          </div>
        </div>
      )}
      {selectedPaths.size > 0 && (
        <div className="mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-md flex items-center gap-3 flex-wrap">
          <span className="text-sm font-semibold text-amber-800 dark:text-amber-200">{t('selection.count', { count: selectedPaths.size })}</span>
          <span className="text-xs text-amber-700/80 dark:text-amber-300/80">{t('selection.rightClick')}</span>
          <button onClick={() => setBulkDeleteConfirmOpen(true)} className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">{t('selection.delete', { count: selectedPaths.size })}</button>
          <button onClick={() => setSelectedPaths(new Set())} className="text-xs px-3 py-1.5 border border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-200 hover:bg-amber-100 dark:bg-amber-900/30 rounded">{t('selection.clear')}</button>
        </div>
      )}
      {bulkUpload && (
        <div className="mb-3 px-3 py-2.5 bg-sky-50 dark:bg-sky-900/20 border border-sky-200 rounded-md text-sm text-sky-800">
          <div className="flex items-center gap-3 mb-1.5">
            <svg className="w-4 h-4 flex-shrink-0 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            <div className="flex-1 min-w-0">
              <div className="font-medium text-sm">
                {t('upload.uploading')} <span className="font-mono">{bulkUpload.activeIndex + 1} / {bulkUpload.total}</span>
              </div>
              <div className="text-xs text-sky-700/90 truncate">{bulkUpload.activeFile}</div>
            </div>
            <div className="flex-shrink-0 text-right">
              <div className="text-sm font-mono font-semibold">{bulkUpload.percent.toFixed(1)}%</div>
              <div className="text-[10px] text-sky-700/80">{formatBytes(bulkUpload.uploadedBytes)} / {formatBytes(bulkUpload.totalBytes)}</div>
            </div>
          </div>
          {/* Progress bar */}
          <div className="h-1.5 bg-sky-100 rounded overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-sky-500 to-sky-600 transition-all duration-100"
              style={{ width: `${Math.min(100, bulkUpload.percent)}%` }}
            />
          </div>
          {/* Speed and ETA */}
          <div className="flex items-center justify-between mt-1 text-[11px] font-mono text-sky-700/80">
            <span>{bulkUpload.speedBps > 0 ? formatSpeed(bulkUpload.speedBps) : '-'}</span>
            <span>{bulkUpload.etaSeconds > 0 ? t('upload.remaining', { eta: formatEta(bulkUpload.etaSeconds, t) }) : ''}</span>
          </div>
        </div>
      )}
      {extractJob && (
        <div className="mb-3 px-3 py-2.5 bg-sky-50 dark:bg-sky-900/20 border border-sky-200 rounded-md text-sm text-sky-800">
          <div className="flex items-center gap-3 mb-1.5">
            <svg className="w-4 h-4 flex-shrink-0 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            <div className="flex-1 min-w-0 font-medium text-sm">
              {t('extractProgress')}
              {extractJob.total > 0 && <span className="font-mono"> {extractJob.done} / {extractJob.total}</span>}
            </div>
          </div>
          <div className="h-1.5 bg-sky-100 rounded overflow-hidden">
            <div
              className={`h-full bg-gradient-to-r from-sky-500 to-sky-600 ${extractJob.total > 0 ? 'transition-all duration-300' : 'animate-pulse w-1/3'}`}
              style={extractJob.total > 0 ? { width: `${Math.min(100, Math.round((extractJob.done / extractJob.total) * 100))}%` } : undefined}
            />
          </div>
        </div>
      )}
      {/* Toolbar */}
      <div className="flex items-center gap-1.5 mb-3 flex-wrap relative">
        {/* Create and upload dropdown */}
        <div className="relative">
          <button onClick={() => setNewMenuOpen(value => !value)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium rounded shadow-sm">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
              <path d="M5.516 7.548c.436-.446 1.043-.481 1.576 0L10 10.405l2.908-2.857c.533-.481 1.141-.446 1.576 0 .436.445.408 1.197 0 1.615-.406.418-3.695 3.629-3.695 3.629a1.105 1.105 0 01-1.576 0S5.924 9.581 5.516 9.163c-.409-.418-.436-1.17 0-1.615z" />
            </svg>
          </button>
          {newMenuOpen && (
            <div className="absolute z-40 mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md shadow-lg min-w-[180px] py-1">
              <button onClick={() => { setNewMenuOpen(false); fileInputRef.current?.click() }} className="block w-full text-left px-3 py-1.5 text-sm hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800">{t('menu.uploadFiles')}</button>
              <button onClick={() => { setNewMenuOpen(false); createFolder() }} className="block w-full text-left px-3 py-1.5 text-sm hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800">{t('menu.newFolder')}</button>
              <button onClick={() => { setNewMenuOpen(false); setNewFileModal(true) }} className="block w-full text-left px-3 py-1.5 text-sm hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800">{t('menu.newFile')}</button>
            </div>
          )}
        </div>

        {/* Refresh */}
        <button onClick={scan}
          className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">
          {t('toolbar.refresh')}
        </button>

        {/* Bulk delete */}
        {selectedPaths.size > 1 && (
          <button onClick={() => setBulkDeleteConfirmOpen(true)}
            className="px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white text-sm rounded font-medium">
            {t('toolbar.delete', { count: selectedPaths.size })}
          </button>
        )}

        <div className="flex-1" />

        {/* Search */}
        <div className="relative">
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && search()}
            placeholder={t('toolbar.searchPlaceholder')}
            className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded text-sm w-56 focus:border-brand-500 outline-none"
          />
          {searchResults && (
            <button onClick={() => { setSearchQuery(''); setSearchResults(null) }}
              className="absolute right-1 top-1/2 -translate-y-1/2 px-1.5 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 dark:text-slate-300">×</button>
          )}
        </div>

        {/* Hidden upload input */}
        <input ref={fileInputRef} type="file" multiple onChange={e => { const list = Array.from(e.target.files || []); if (list.length) uploadFiles(list); e.target.value = ""; }} className="hidden" />

        <div className="ml-auto text-sm text-slate-500 dark:text-slate-500">{t('toolbar.itemCount', { count: content.length })}</div>
      </div>

      {/* Path breadcrumb */}
      <div className="flex items-center gap-1 mb-4 text-sm flex-wrap bg-slate-50 dark:bg-slate-900 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700">
        <button onClick={() => navigateTo('/')} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-mono">~</button>
        {parts.map((p, i) => {
          const pathHere = '/' + parts.slice(0, i + 1).join('/')
          return (
            <span key={i} className="flex items-center gap-1">
              <span className="text-slate-300">/</span>
              <button onClick={() => navigateTo(pathHere)} className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-mono">{p}</button>
            </span>
          )
        })}
      </div>

      {error && <div className="mb-3 px-3 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-sm text-red-700 dark:text-red-300">{error}</div>}

      {/* File table */}
      <div className={responsiveTableContainerClass}>
        {loading ? (
          <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('loading')}</div>
        ) : (
          <table className={responsiveTableClass}>
            <thead className={responsiveTableHeadClass}>
              <tr>
                <th className="px-3 py-2.5 w-10 text-center"><input type="checkbox" checked={content.length > 0 && selectedPaths.size === content.length} ref={ref => { if (ref) ref.indeterminate = selectedPaths.size > 0 && selectedPaths.size < content.length }} onChange={e => selectAllItems(e.target.checked)} className="cursor-pointer" /></th>
                <th className="text-left px-4 py-2.5">{t('columns.name')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.size')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.permissions')}</th>
                <th className="text-left px-4 py-2.5">{t('columns.modified')}</th>
                <th className="text-right px-4 py-2.5">{t('columns.actions')}</th>
              </tr>
            </thead>
            <tbody className={responsiveTableBodyClass}>
              {path !== '/' && (
                <tr className={responsiveTableRowClass} onClick={goUp}>
                  <td className="px-4 py-2.5 text-sm" colSpan={6}>
                    <span className="text-slate-500 dark:text-slate-500">{t('parentFolder')}</span>
                  </td>
                </tr>
              )}
              {content.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('empty')}</td>
                </tr>
              )}
              {(searchResults ?? content).map((e) => (
                <tr key={e.path}
                  onContextMenu={(ev) => rowContext(ev, e)}
                  onTouchStart={(ev) => touchStart(ev, e)}
                  onTouchEnd={touchEnd}
                  onTouchMove={touchMove}
                  className={`${responsiveTableRowClass} ${selectedPaths.has(e.path) ? 'bg-brand-50 dark:bg-brand-900/20' : ''}`}>
                  <td data-label={t('columns.select')} className={responsiveTableCellClass}>
                    <input type="checkbox" checked={selectedPaths.has(e.path)}
                      onChange={() => toggleSelection2(e.path)}
                      onClick={ev => ev.stopPropagation()}
                      className="cursor-pointer" />
                  </td>
                  <td data-label={t('columns.name')} className={responsiveTableCellClass}>
                    {e.type === 'folder' ? (
                      <button
                        onClick={() => navigateTo(e.path)}
                        className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-300 font-medium flex items-center gap-2"
                      >
                        <svg className="w-4 h-4 text-amber-500" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z" />
                        </svg>
                        {e.name}
                      </button>
                    ) : (
                      <span className="flex items-center gap-2 text-slate-800 dark:text-slate-200">
                        <svg className="w-4 h-4 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.7}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <span>{e.name}</span>
                      </span>
                    )}
                  </td>
                  <td data-label={t('columns.size')} className={responsiveTableCodeCellClass}>
                    {e.type === 'folder' ? '-' : formatSize(e.size_b)}
                  </td>
                  <td data-label={t('columns.permissions')} className={responsiveTableCodeCellClass}>
                    <div>{e.permissions || e.mode}</div>
                    {(e.owner || e.group) && <div className="text-xs text-slate-400 dark:text-slate-500">{e.owner}:{e.group}</div>}
                  </td>
                  <td data-label={t('columns.modified')} className={responsiveTableCellClass}>{formatDate(e.changed)}</td>
                  <td className={responsiveTableActionCellClass}>
                    <button
                      onClick={(ev) => { ev.stopPropagation(); openContext(ev.clientX, ev.clientY, e) }}
                      className="p-1.5 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 dark:hover:bg-slate-800 rounded transition"
                      title={t('actionsTitle')}>
                      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          items={buildCtxItems()}
          onClose={() => setContextMenu(null)} />
      )}
      {editor && (
        <CodeEditor path={editor.path} content={editor.content}
          onChange={s => setEditor({ ...editor, content: s })}
          onSave={saveEditor}
          onClose={() => setEditor(null)} />
      )}
      {renameFor && (
        <RenameModal entry={renameFor}
          onDone={name => rename(renameFor, name)}
          onCancel={() => setRenameFor(null)} />
      )}
      {chmodFor && (
        <ChmodModal entry={chmodFor}
          onDone={mod => changePermissions(chmodFor, mod)}
          onCancel={() => setChmodFor(null)} />
      )}
      {copyMoveModal && (
        <CopyMoveModal
          type={copyMoveModal.type}
          paths={copyMoveModal.paths}
          onDone={copyOrMove}
          onCancel={() => setCopyModal(null)} />
      )}
      {archiveModal && (
        <ArchiveModal
          itemCount={selectedPaths.size}
          onDone={archive}
          onCancel={() => setArchiveModal(false)} />
      )}
      {newFileModal && (
        <NewFileModal
          onDone={createNewFile}
          onCancel={() => setNewFileModal(false)} />
      )}
      {sizeResult && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setSizeResult(null)}>
          <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-2">{t('sizeModal.title')}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-3 font-mono">{sizeResult.path}</p>
            <div className="text-2xl font-bold text-brand-700 dark:text-brand-300 mb-2">
              {(() => {
                const b = sizeResult.size
                if (b < 1024) return b + ' B'
                if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB'
                if (b < 1024*1024*1024) return (b/1024/1024).toFixed(1) + ' MB'
                return (b/1024/1024/1024).toFixed(2) + ' GB'
              })()}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-500 font-mono">{t('sizeModal.bytes', { bytes: sizeResult.size.toLocaleString('en-US') })}</div>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setSizeResult(null)} className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded">{t('sizeModal.done')}</button>
            </div>
          </div>
        </div>
      )}
      {bulkDeleteConfirmOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={() => setBulkDeleteConfirmOpen(false)}>
          <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-red-700 dark:text-red-300 mb-2">{t('bulkDelete.title')}</h3>
            <p className="text-sm text-slate-700 dark:text-slate-300 mb-3">
              <span className="font-semibold">{t('bulkDelete.messageBold', { count: selectedPaths.size })}</span>{t('bulkDelete.messagePost')}
            </p>
            <ul className="text-xs font-mono text-slate-500 dark:text-slate-500 bg-slate-50 dark:bg-slate-900 rounded p-2 max-h-40 overflow-auto mb-4">
              {Array.from(selectedPaths).slice(0, 8).map(y => <li key={y} className="truncate">{y}</li>)}
              {selectedPaths.size > 8 && <li className="text-slate-400 dark:text-slate-500 italic">{t('bulkDelete.moreItems', { count: selectedPaths.size - 8 })}</li>}
            </ul>
            <div className="flex justify-end gap-2">
              <button onClick={() => setBulkDeleteConfirmOpen(false)} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('bulkDelete.cancel')}</button>
              <button onClick={bulkDelete} className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm rounded font-medium">{t('bulkDelete.confirm')}</button>
            </div>
          </div>
        </div>
      )}

        </section>
      </div>
    </div>
  )
}

function docrootRelativePath(path: string): string | null {
  const root = '/public_html'
  if (path === root) return '/'
  if (!path.startsWith(root + '/')) return null
  return path.slice(root.length)
}

function formatSize(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' })
  } catch {
    return iso
  }
}


// ===== Context Menu Component =====
function ContextMenu({ x, y, items, onClose }: { x: number; y: number; items: CtxItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })
  const [measured, setMeasured] = useState(false)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const vw = window.innerWidth, vh = window.innerHeight
    let nx = x, ny = y
    if (x + r.width > vw - 8) nx = Math.max(8, vw - r.width - 8)
    if (y + r.height > vh - 8) ny = Math.max(8, vh - r.height - 8)
    setPos({ x: nx, y: ny })
    setMeasured(true)
  }, [x, y])

  useEffect(() => {
    function onDown(ev: MouseEvent) { if (ref.current && !ref.current.contains(ev.target as Node)) onClose() }
    function onKey(ev: KeyboardEvent) { if (ev.key === 'Escape') onClose() }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [onClose])

  function menuKey(ev: React.KeyboardEvent) {
    const el = ref.current
    if (!el) return
    const mis = Array.from(el.querySelectorAll<HTMLElement>('[data-mi]'))
    if (!mis.length) return
    const idx = mis.indexOf(document.activeElement as HTMLElement)
    if (ev.key === 'ArrowDown') { ev.preventDefault(); mis[(idx + 1 + mis.length) % mis.length].focus() }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); mis[(idx - 1 + mis.length) % mis.length].focus() }
    else if (ev.key === 'Home') { ev.preventDefault(); mis[0].focus() }
    else if (ev.key === 'End') { ev.preventDefault(); mis[mis.length - 1].focus() }
  }

  return (
    <div
      ref={ref}
      role="menu"
      onKeyDown={menuKey}
      className={`fixed z-[60] min-w-[190px] py-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-xl text-sm ${measured ? '' : 'opacity-0'}`}
      style={{ left: pos.x, top: pos.y }}
      tabIndex={-1}>
      {items.map(item => item.separator ? (
        <div key={item.key} className="my-1 border-t border-slate-100 dark:border-slate-700" />
      ) : (
        <button
          key={item.key}
          data-mi
          onClick={item.onClick}
          className={`w-full text-left px-3 py-1.5 flex items-center gap-2 transition ${item.danger ? 'text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'}`}
          role="menuitem">
          <span className="flex w-4 flex-shrink-0 items-center justify-center"><Icon d={item.icon} /></span>
          <span>{item.label}</span>
        </button>
      ))}
    </div>
  )
}

// ===== Helper components =====
function RenameModal({ entry, onDone, onCancel }: { entry: Entry; onDone: (newName: string) => void; onCancel: () => void }) {
  const { t } = useTranslation('DomainFilesPage')
  const [name, setName] = useState(entry.name)
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('renameModal.title')}</h3>
        <p className="text-xs text-slate-500 dark:text-slate-500 mb-3"><code className="font-mono">{entry.path}</code></p>
        <input value={name} onChange={e => setName(e.target.value)} autoFocus
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm" />
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('renameModal.cancel')}</button>
          <button onClick={() => onDone(name)} disabled={!name || name === entry.name}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded">{t('renameModal.rename')}</button>
        </div>
      </div>
    </div>
  )
}

function ChmodModal({ entry, onDone, onCancel }: { entry: Entry; onDone: (mod: string) => void; onCancel: () => void }) {
  const { t } = useTranslation('DomainFilesPage')
  const [mod, setMod] = useState(entry.mode || '0644')
  // Nine permission-bit checkboxes.
  const n = parseInt(mod.replace(/^0/, ''), 8) || 0
  function bit(b: number) { return (n & b) !== 0 }
  function tog(b: number) {
    const newMode = (n & b) ? n & ~b : n | b
    setMod('0' + newMode.toString(8).padStart(3, '0'))
  }
  const cls = (on: boolean) => `text-xs px-2 py-1 rounded border ${on ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-300 text-emerald-700 dark:text-emerald-300' : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-500'}`
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('chmodModal.title')}</h3>
        <p className="text-xs text-slate-500 dark:text-slate-500 mb-3"><code className="font-mono">{entry.path}</code></p>
        <div className="grid grid-cols-3 gap-2 mb-3 text-center">
          <div className="text-xs text-slate-500 dark:text-slate-500 font-semibold">{t('chmodModal.owner')}</div>
          <div className="text-xs text-slate-500 dark:text-slate-500 font-semibold">{t('chmodModal.group')}</div>
          <div className="text-xs text-slate-500 dark:text-slate-500 font-semibold">{t('chmodModal.other')}</div>
          {[0o400, 0o040, 0o004].map((b, i) => <button key={'r'+i} onClick={() => tog(b)} className={cls(bit(b))}>{t('chmodModal.read')}</button>)}
          {[0o200, 0o020, 0o002].map((b, i) => <button key={'w'+i} onClick={() => tog(b)} className={cls(bit(b))}>{t('chmodModal.write')}</button>)}
          {[0o100, 0o010, 0o001].map((b, i) => <button key={'x'+i} onClick={() => tog(b)} className={cls(bit(b))}>{t('chmodModal.execute')}</button>)}
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-500 mb-3">{t('chmodModal.octal')}<input value={mod} onChange={e => setMod(e.target.value)} className="font-mono ml-1 px-2 py-0.5 border border-slate-300 dark:border-slate-600 rounded w-20" /></div>
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('chmodModal.cancel')}</button>
          <button onClick={() => onDone(mod)} className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded">{t('chmodModal.apply')}</button>
        </div>
      </div>
    </div>
  )
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function formatSpeed(bps: number): string {
  return formatBytes(bps) + '/s'
}

function formatEta(seconds: number, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (seconds < 1) return t('eta.lessThanSec')
  if (seconds < 60) return t('eta.sec', { count: Math.round(seconds) })
  if (seconds < 3600) return t('eta.minSec', { min: Math.floor(seconds / 60), sec: Math.round(seconds % 60) })
  return t('eta.hrMin', { hr: Math.floor(seconds / 3600), min: Math.floor((seconds % 3600) / 60) })
}

function CopyMoveModal({ type, paths, onDone, onCancel }:
  { type: 'copy' | 'move'; paths: string[]; onDone: (target: string) => void; onCancel: () => void }) {
  const { t } = useTranslation('DomainFilesPage')
  const [target, setTarget] = useState('/public_html')
  const title = type === 'copy' ? t('copyMoveModal.titleCopy') : t('copyMoveModal.titleMove')
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-lg p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('copyMoveModal.heading', { title, count: paths.length })}</h3>
        <ul className="text-xs font-mono text-slate-500 dark:text-slate-500 bg-slate-50 dark:bg-slate-900 rounded p-2 max-h-32 overflow-auto mb-4">
          {paths.slice(0, 5).map(y => <li key={y} className="truncate">{y}</li>)}
          {paths.length > 5 && <li className="text-slate-400 dark:text-slate-500 italic">{t('copyMoveModal.moreItems', { count: paths.length - 5 })}</li>}
        </ul>
        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('copyMoveModal.targetLabel')}</label>
        <input value={target} onChange={e => setTarget(e.target.value)} placeholder={t('copyMoveModal.targetPlaceholder')}
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm" />
        <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">{t('copyMoveModal.hintPre')}{type === 'copy' ? t('copyMoveModal.hintCopy') : t('copyMoveModal.hintMove')}</p>
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('copyMoveModal.cancel')}</button>
          <button onClick={() => onDone(target)} className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 text-sm rounded">{title}</button>
        </div>
      </div>
    </div>
  )
}

function ArchiveModal({ itemCount, onDone, onCancel }: { itemCount: number; onDone: (name: string, format: 'zip' | 'tar.gz') => void; onCancel: () => void }) {
  const { t } = useTranslation('DomainFilesPage')
  const [name, setName] = useState('backups-' + new Date().toISOString().slice(0, 10))
  const [format, setFormat] = useState<'zip' | 'tar.gz'>('zip')
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('archiveModal.title', { count: itemCount })}</h3>
        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('archiveModal.fileName')}</label>
        <input value={name} onChange={e => setName(e.target.value)}
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm mb-3" />
        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('archiveModal.format')}</label>
        <div className="flex gap-2">
          <button onClick={() => setFormat('zip')}
            className={`px-3 py-1.5 text-sm rounded border ${format === 'zip' ? 'bg-brand-50 dark:bg-brand-900/20 border-brand-500 text-brand-700 dark:text-brand-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800'}`}>
            ZIP
          </button>
          <button onClick={() => setFormat('tar.gz')}
            className={`px-3 py-1.5 text-sm rounded border ${format === 'tar.gz' ? 'bg-brand-50 dark:bg-brand-900/20 border-brand-500 text-brand-700 dark:text-brand-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400 dark:text-slate-500 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800'}`}>
            TAR.GZ
          </button>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-500 mt-2">{t('archiveModal.output')}<code className="font-mono">{name}.{format}</code></p>
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('archiveModal.cancel')}</button>
          <button onClick={() => onDone(name, format)} disabled={!name}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded">{t('archiveModal.archive')}</button>
        </div>
      </div>
    </div>
  )
}

function NewFileModal({ onDone, onCancel }: { onDone: (name: string) => void; onCancel: () => void }) {
  const { t } = useTranslation('DomainFilesPage')
  const [name, setName] = useState('new-file.txt')
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl w-full max-w-md p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">{t('newFile.title')}</h3>
        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 dark:text-slate-500 mb-1">{t('newFile.label')}</label>
        <input value={name} onChange={e => setName(e.target.value)} autoFocus
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded font-mono text-sm" />
        <p className="text-xs text-slate-500 dark:text-slate-500 mt-2">{t('newFile.hint')}</p>
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-sm rounded">{t('newFile.cancel')}</button>
          <button onClick={() => onDone(name)} disabled={!name}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 disabled:opacity-60 text-sm rounded">{t('newFile.create')}</button>
        </div>
      </div>
    </div>
  )
}