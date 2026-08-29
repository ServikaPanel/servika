import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { ICON } from '@/components/iconPaths'
import CodeMirror, { EditorView } from '@uiw/react-codemirror'
import { html } from '@codemirror/lang-html'
import { css } from '@codemirror/lang-css'
import { javascript } from '@codemirror/lang-javascript'
import { json } from '@codemirror/lang-json'
import { php } from '@codemirror/lang-php'
import { markdown } from '@codemirror/lang-markdown'
import { sql } from '@codemirror/lang-sql'
import { xml } from '@codemirror/lang-xml'
import { oneDark } from '@codemirror/theme-one-dark'

type Language = 'html' | 'css' | 'js' | 'json' | 'php' | 'md' | 'sql' | 'xml' | 'text'

const LANGUAGES: { code: Language; name: string; extensions: string[] }[] = [
  { code: 'html', name: 'HTML',       extensions: ['html', 'htm'] },
  { code: 'css',  name: 'CSS',        extensions: ['css', 'scss', 'sass', 'less'] },
  { code: 'js',   name: 'JavaScript', extensions: ['js', 'jsx', 'mjs', 'ts', 'tsx'] },
  { code: 'json', name: 'JSON',       extensions: ['json'] },
  { code: 'php',  name: 'PHP',        extensions: ['php', 'phtml', 'phps'] },
  { code: 'md',   name: 'Markdown',   extensions: ['md', 'markdown'] },
  { code: 'sql',  name: 'SQL',        extensions: ['sql'] },
  { code: 'xml',  name: 'XML',        extensions: ['xml', 'svg'] },
  { code: 'text', name: 'Plain Text',  extensions: ['txt', 'log', 'ini', 'conf', 'env'] },
]

function detectLanguage(path: string): Language {
  const m = path.toLowerCase().match(/\.([a-z0-9]+)$/)
  if (!m) return 'text'
  const u = m[1]
  for (const d of LANGUAGES) if (d.extensions.includes(u)) return d.code
  return 'text'
}

function languageExtensions(code: Language) {
  switch (code) {
    case 'html': return [html()]
    case 'css':  return [css()]
    case 'js':   return [javascript({ jsx: true, typescript: true })]
    case 'json': return [json()]
    case 'php':  return [php()]
    case 'md':   return [markdown()]
    case 'sql':  return [sql()]
    case 'xml':  return [xml()]
    default:     return []
  }
}

interface Props {
  path: string
  content: string
  onChange: (s: string) => void
  onSave: () => Promise<void> | void
  onClose: () => void
}

export default function CodeEditor({ path, content, onChange, onSave, onClose }: Props) {
  const { t } = useTranslation('CodeEditor')
  const [fullscreen, setFullscreen] = useState(false)
  const [language, setLanguage] = useState<Language>(() => detectLanguage(path))
  const [saveStatus, setSaveStatus] = useState<'clean' | 'dirty' | 'saving' | 'saved'>('clean')
  const [cursor, setCursor] = useState({ line: 1, column: 1 })
  // Tracks the content as last persisted, NOT as first opened. Comparing against
  // the opened content made every buffer look dirty forever after the first
  // edit, so a successful save flipped its own badge from saved straight back to
  // unsaved and left the save button enabled with nothing left to write.
  const [savedContent, setSavedContent] = useState(content)

  // Adjusted during render rather than in an effect: the buffer is dirty the
  // moment it differs from what was last written, so deferring that to a commit
  // only paints one frame with a stale badge. The extra 'dirty' guard is what
  // makes it converge; the effect relied on setState bailing out instead.
  if (content !== savedContent && saveStatus !== 'saving' && saveStatus !== 'dirty') {
    setSaveStatus('dirty')
  }

  // CTRL+S handler
  useEffect(() => {
    function ks(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        save()
      }
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', ks)
    return () => window.removeEventListener('keydown', ks)
  })

  async function save() {
    setSaveStatus('saving')
    try {
      await onSave()
      setSavedContent(content)
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('clean'), 1200)
    } catch {
      setSaveStatus('dirty')
    }
  }

  const ext = useMemo(() => [
    ...languageExtensions(language),
    EditorView.theme({
      '&': { fontSize: '13px' },
      '.cm-scroller': { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace' },
    }),
    EditorView.updateListener.of(u => {
      if (u.selectionSet || u.docChanged) {
        const sel = u.state.selection.main
        const line = u.state.doc.lineAt(sel.head)
        setCursor({ line: line.number, column: sel.head - line.from + 1 })
      }
    }),
  ], [language])

  const fileName = path.split('/').filter(Boolean).pop() || path

  // Size info
  const byteCount = new TextEncoder().encode(content).length

  return (
    <div
      className={`fixed inset-0 z-50 bg-black/50 flex items-center justify-center ${fullscreen ? '' : 'p-4'}`}
      onClick={onClose}
    >
      <div
        className={`bg-slate-900 shadow-2xl flex flex-col text-slate-100 ${fullscreen ? 'w-full h-full' : 'w-full h-[85vh] rounded-2xl overflow-hidden'}`}
        onClick={e => e.stopPropagation()}
      >
        {/* Top bar */}
        <div className="flex items-center justify-between px-3 py-2 bg-slate-800 border-b border-slate-700">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            {/* "Traffic light" dot style */}
            <div className="flex items-center gap-1 mr-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
            </div>
            <svg className="w-4 h-4 text-slate-400 dark:text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <span className="text-sm font-semibold text-slate-100 truncate">{fileName}</span>
            <span className="text-xs text-slate-500 dark:text-slate-500 truncate min-w-0 hidden md:inline">— {path}</span>
            {saveStatus === 'dirty' && <span className="text-[10px] uppercase tracking-wider text-amber-400 bg-amber-500/15 px-1.5 py-0.5 rounded">{t('unsaved')}</span>}
            {saveStatus === 'saving' && <span className="text-[10px] uppercase tracking-wider text-sky-400 bg-sky-500/15 px-1.5 py-0.5 rounded">{t('saving')}</span>}
            {saveStatus === 'saved' && <span className="text-[10px] uppercase tracking-wider text-emerald-400 bg-emerald-500/15 px-1.5 py-0.5 rounded">{t('saved')}</span>}
          </div>

          <div className="flex items-center gap-1.5 flex-shrink-0">
            <select
              value={language}
              onChange={e => setLanguage(e.target.value as Language)}
              className="text-xs bg-slate-700 text-slate-100 border border-slate-600 rounded px-2 py-1 focus:outline-none focus:border-slate-400"
              title={t('syntax')}
            >
              {LANGUAGES.map(d => <option key={d.code} value={d.code}>{d.code === 'text' ? t('langPlainText') : d.name}</option>)}
            </select>
            <button
              onClick={() => setFullscreen(!fullscreen)}
              className="text-xs px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-100 rounded"
              title={fullscreen ? t('exitFullscreen') : t('fullscreen')}
            >
              <Icon d={fullscreen ? ICON.close : ICON.fullscreen} className="h-4 w-4" />
            </button>
            <button
              onClick={save}
              disabled={saveStatus === 'saving' || saveStatus === 'clean'}
              className="text-xs px-3 py-1 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded font-medium"
              title="Ctrl+S"
            >
              {t('save')}
            </button>
            <button
              onClick={onClose}
              className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-100 rounded"
              title="ESC"
            >
              {t('close')}
            </button>
          </div>
        </div>

        {/* Editor */}
        <div className="flex-1 min-h-0 overflow-hidden">
          <CodeMirror
            value={content}
            height="100%"
            theme={oneDark}
            extensions={ext}
            onChange={onChange}
            basicSetup={{
              lineNumbers: true,
              highlightActiveLineGutter: true,
              highlightSpecialChars: true,
              foldGutter: true,
              drawSelection: true,
              dropCursor: true,
              allowMultipleSelections: true,
              indentOnInput: true,
              syntaxHighlighting: true,
              bracketMatching: true,
              closeBrackets: true,
              autocompletion: true,
              rectangularSelection: true,
              highlightActiveLine: true,
              highlightSelectionMatches: true,
              tabSize: 2,
            }}
            style={{ height: '100%' }}
          />
        </div>

        {/* Status bar */}
        <div className="flex items-center justify-between gap-4 px-3 py-1.5 bg-slate-800 border-t border-slate-700 text-[11px] text-slate-400 dark:text-slate-500 font-mono">
          <div className="flex items-center gap-4">
            <span>{t('cursor', { line: cursor.line, column: cursor.column })}</span>
            <span>{t('lines', { count: content.split('\n').length })}</span>
            <span>{t('bytes', { count: byteCount })}</span>
          </div>
          <div className="flex items-center gap-3">
            <span>UTF-8</span>
            <span>LF</span>
            <span className="text-slate-300">{language === 'text' ? t('langPlainText') : LANGUAGES.find(d => d.code === language)?.name}</span>
            <span className="text-slate-500 dark:text-slate-500">{t('shortcuts')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}