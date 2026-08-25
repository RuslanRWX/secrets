// Every object in this system has a machine identity that a person occasionally
// has to match by eye. A seal turns that UUID into a small symmetric glyph, so
// two identifiers can be told apart at a glance without reading 36 characters.

/** hash folds a string into a 32-bit integer (FNV-1a). */
function hash(input: string): number {
  let value = 0x811c9dc5
  for (let i = 0; i < input.length; i += 1) {
    value ^= input.charCodeAt(i)
    value = Math.imul(value, 0x01000193)
  }
  return value >>> 0
}

/** mulberry32 is a small deterministic PRNG seeded from the hash. */
function prng(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export interface SealShape {
  /** cells is a 5x5 grid, mirrored left-to-right so the glyph reads as a stamp. */
  cells: boolean[]
  /** notches is the count of teeth around the rim, from 4 to 9. */
  notches: number
}

export function sealShape(id: string): SealShape {
  const random = prng(hash(id))
  const cells: boolean[] = new Array(25).fill(false)

  // Fill the left three columns, then mirror onto the right two. The centre
  // column is biased sparse so the glyph keeps an open middle and stays legible
  // at the sizes it is actually rendered: 28 to 40 pixels.
  for (let y = 0; y < 5; y += 1) {
    for (let x = 0; x < 3; x += 1) {
      const on = random() > (x === 2 ? 0.62 : 0.46)
      cells[y * 5 + x] = on
      cells[y * 5 + (4 - x)] = on
    }
  }

  // Clear the corners so the stamp sits inside the rim rather than touching it.
  for (const corner of [0, 4, 20, 24]) cells[corner] = false

  return { cells, notches: 4 + Math.floor(random() * 6) }
}
