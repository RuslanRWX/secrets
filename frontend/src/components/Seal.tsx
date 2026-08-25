import { useMemo } from 'react'
import { sealShape } from '../lib/seal'

interface SealProps {
  id: string
  size?: number
  /** broken renders the seal open, which is how a revealed secret is marked. */
  broken?: boolean
  className?: string
}

const CELL = 3.2
const PITCH = 3.9
const ORIGIN = 6.6

/**
 * Seal draws a deterministic glyph for an identifier: a mirrored 5x5 stamp
 * inside a toothed brass rim. The same id always produces the same seal, and a
 * revealed secret shows the rim broken open.
 */
export function Seal({ id, size = 28, broken = false, className = '' }: SealProps) {
  const shape = useMemo(() => sealShape(id), [id])

  const teeth = Array.from({ length: shape.notches }, (_, i) => (360 / shape.notches) * i)
  const stampClass = broken ? 'fill-sealed' : 'fill-brass'
  const toothClass = broken ? 'fill-edge' : 'fill-brass-dim'

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role="img"
      aria-label={`${broken ? 'Open' : 'Sealed'} ${id.slice(0, 8)}`}
      className={className}
    >
      <circle cx="16" cy="16" r="14" className="fill-raised stroke-edge" />

      {/* A broken seal loses the teeth on its right flank. */}
      {teeth
        .filter((angle) => !broken || angle < 150 || angle > 300)
        .map((angle) => (
          <rect
            key={angle}
            x="15.1"
            y="1.1"
            width="1.8"
            height="3"
            rx="0.7"
            className={toothClass}
            transform={`rotate(${angle} 16 16)`}
          />
        ))}

      <g>
        {shape.cells.map((on, index) =>
          on ? (
            <rect
              key={index}
              x={ORIGIN + (index % 5) * PITCH}
              y={ORIGIN + Math.floor(index / 5) * PITCH}
              width={CELL}
              height={CELL}
              rx="0.8"
              className={stampClass}
            />
          ) : null,
        )}
      </g>
    </svg>
  )
}
