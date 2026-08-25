import { useEffect, useState } from 'react'
import { CopyButton } from './ui'

const HOLD_SECONDS = 30

/**
 * RevealedValue shows a decrypted secret and takes it off the screen again after
 * half a minute, so a value does not sit visible on an unattended desk. The ring
 * counts that time down in the open.
 */
export function RevealedValue({ value, onHide }: { value: string; onHide: () => void }) {
  const [remaining, setRemaining] = useState(HOLD_SECONDS)

  useEffect(() => {
    const timer = setInterval(() => {
      setRemaining((seconds) => {
        if (seconds <= 1) {
          clearInterval(timer)
          onHide()
          return 0
        }
        return seconds - 1
      })
    }, 1000)

    return () => clearInterval(timer)
  }, [onHide])

  const progress = remaining / HOLD_SECONDS
  const circumference = 2 * Math.PI * 9

  return (
    <div className="flex items-start gap-3 rounded-md border border-brass/30 bg-vault p-3">
      <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-sm text-brass-bright">
        {value}
      </pre>

      <div className="flex shrink-0 items-center gap-2">
        <CopyButton value={value} />
        <button
          onClick={onHide}
          className="btn-ghost px-2.5 py-1 text-xs"
          title={`Hides automatically in ${remaining}s`}
        >
          Hide
        </button>
        <svg width="22" height="22" viewBox="0 0 22 22" role="img" aria-label={`Hides in ${remaining} seconds`}>
          <circle cx="11" cy="11" r="9" fill="none" stroke="#2A313E" strokeWidth="2" />
          <circle
            cx="11"
            cy="11"
            r="9"
            fill="none"
            stroke="#C79A3C"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - progress)}
            transform="rotate(-90 11 11)"
            style={{ transition: 'stroke-dashoffset 1s linear' }}
          />
        </svg>
      </div>
    </div>
  )
}
