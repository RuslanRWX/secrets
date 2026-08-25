import { useEffect, useRef, type ReactNode } from 'react'

/** Panel is the standard raised surface used for cards and forms. */
export function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`panel ${className}`}>{children}</div>
}

interface FieldProps {
  label: string
  hint?: string
  children: ReactNode
}

export function Field({ label, hint, children }: FieldProps) {
  return (
    <label className="block">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  )
}

/** Notice reports the outcome of an action; it never apologises or hedges. */
export function Notice({ kind, children }: { kind: 'error' | 'ok'; children: ReactNode }) {
  const tone = kind === 'error' ? 'border-breach/40 text-breach' : 'border-sealed/40 text-sealed'
  return (
    <p role={kind === 'error' ? 'alert' : 'status'} className={`rounded-md border ${tone} bg-vault px-3 py-2 text-sm`}>
      {children}
    </p>
  )
}

interface ModalProps {
  title: string
  subtitle?: string
  onClose: () => void
  children: ReactNode
  width?: string
}

export function Modal({ title, subtitle, onClose, children, width = 'max-w-lg' }: ModalProps) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    ref.current?.querySelector<HTMLElement>('input, textarea, select, button')?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="scrim fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 backdrop-blur-sm sm:p-8">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`panel w-full ${width} animate-rise p-6`}
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 className="font-display text-lg font-medium text-chalk">{title}</h2>
            {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="btn-ghost px-2 py-1 text-xs" aria-label="Close">
            Esc
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

/** Empty is an invitation to act, not a shrug. */
export function Empty({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-4 rounded-lg border border-dashed border-edge px-6 py-16 text-center">
      <p className="text-sm text-muted">{title}</p>
      {action}
    </div>
  )
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 px-1 py-10 text-sm text-muted">
      <span className="h-3 w-3 animate-pulse rounded-full bg-brass" aria-hidden />
      {label}
    </div>
  )
}

/** Copy puts a value on the clipboard and confirms in place. */
export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const ref = useRef<HTMLButtonElement>(null)

  return (
    <button
      ref={ref}
      type="button"
      className="btn-ghost px-2.5 py-1 text-xs"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          const button = ref.current
          if (!button) return
          const original = button.textContent
          button.textContent = 'Copied'
          setTimeout(() => {
            button.textContent = original
          }, 1400)
        } catch {
          window.prompt('Copy this value', value)
        }
      }}
    >
      {label}
    </button>
  )
}

/** formatDate renders timestamps compactly and consistently. */
export function formatDate(value?: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}
