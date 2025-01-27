import { useEditor, EditorContent } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import TurndownService from 'turndown'
import { useCallback } from 'react'

const turndown = new TurndownService()

const RichTextEditor = ({ content, onChange }) => {
  const editor = useEditor({
    extensions: [StarterKit],
    content: content,
    onUpdate: ({ editor }) => {
      const html = editor.getHTML()
      const markdown = turndown.turndown(html)
      onChange(markdown)
    },
  })

  const toggleBold = useCallback(() => {
    editor?.chain().focus().toggleBold().run()
  }, [editor])

  const toggleItalic = useCallback(() => {
    editor?.chain().focus().toggleItalic().run()
  }, [editor])

  const toggleCode = useCallback(() => {
    editor?.chain().focus().toggleCode().run()
  }, [editor])

  const toggleHeading = useCallback((level) => {
    editor?.chain().focus().toggleHeading({ level }).run()
  }, [editor])

  const toggleBulletList = useCallback(() => {
    editor?.chain().focus().toggleBulletList().run()
  }, [editor])

  const toggleOrderedList = useCallback(() => {
    editor?.chain().focus().toggleOrderedList().run()
  }, [editor])

  if (!editor) {
    return null
  }

  return (
    <div className="rich-text-editor">
      <div className="editor-toolbar">
        <button
          type="button"
          onClick={toggleBold}
          className={editor.isActive('bold') ? 'is-active' : ''}
        >
          <strong>B</strong>
        </button>
        <button
          type="button"
          onClick={toggleItalic}
          className={editor.isActive('italic') ? 'is-active' : ''}
        >
          <em>I</em>
        </button>
        <button
          type="button"
          onClick={toggleCode}
          className={editor.isActive('code') ? 'is-active' : ''}
        >
          {'</>'}
        </button>
        <button
          type="button"
          onClick={() => toggleHeading(1)}
          className={editor.isActive('heading', { level: 1 }) ? 'is-active' : ''}
        >
          H1
        </button>
        <button
          type="button"
          onClick={() => toggleHeading(2)}
          className={editor.isActive('heading', { level: 2 }) ? 'is-active' : ''}
        >
          H2
        </button>
        <button
          type="button"
          onClick={toggleBulletList}
          className={editor.isActive('bulletList') ? 'is-active' : ''}
        >
          •
        </button>
        <button
          type="button"
          onClick={toggleOrderedList}
          className={editor.isActive('orderedList') ? 'is-active' : ''}
        >
          1.
        </button>
      </div>
      <EditorContent editor={editor} />
    </div>
  )
}

export default RichTextEditor 