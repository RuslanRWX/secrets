import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

/**
 * Appearance is a per-browser preference, kept in localStorage rather than on
 * the account: it describes the screen you are sitting at, and the same person
 * may want night on a laptop and day on a projector.
 */

export type Theme = 'system' | 'night' | 'day'
export type TextSize = 'small' | 'medium' | 'large' | 'xlarge'

export const themeLabels: Record<Theme, string> = {
  system: 'Match system',
  night: 'Night',
  day: 'Day',
}

export const textSizeLabels: Record<TextSize, string> = {
  small: 'Small',
  medium: 'Default',
  large: 'Large',
  xlarge: 'Largest',
}

const THEME_KEY = 'secrets.theme'
const SIZE_KEY = 'secrets.textSize'

interface AppearanceState {
  theme: Theme
  textSize: TextSize
  /** resolvedTheme is what is actually painted once "system" is worked out. */
  resolvedTheme: 'night' | 'day'
  setTheme: (theme: Theme) => void
  setTextSize: (size: TextSize) => void
}

const AppearanceContext = createContext<AppearanceState | null>(null)

function readStored<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  const stored = localStorage.getItem(key)
  return allowed.includes(stored as T) ? (stored as T) : fallback
}

function systemPrefersDay() {
  return window.matchMedia('(prefers-color-scheme: light)').matches
}

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() =>
    readStored(THEME_KEY, ['system', 'night', 'day'] as const, 'system'),
  )
  const [textSize, setTextSizeState] = useState<TextSize>(() =>
    readStored(SIZE_KEY, ['small', 'medium', 'large', 'xlarge'] as const, 'medium'),
  )
  const [systemIsDay, setSystemIsDay] = useState(systemPrefersDay)

  // Follow the operating system while the preference is "system".
  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: light)')
    const onChange = (event: MediaQueryListEvent) => setSystemIsDay(event.matches)
    query.addEventListener('change', onChange)
    return () => query.removeEventListener('change', onChange)
  }, [])

  const resolvedTheme: 'night' | 'day' =
    theme === 'system' ? (systemIsDay ? 'day' : 'night') : theme

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme
  }, [resolvedTheme])

  useEffect(() => {
    document.documentElement.dataset.size = textSize
  }, [textSize])

  const setTheme = useCallback((next: Theme) => {
    localStorage.setItem(THEME_KEY, next)
    setThemeState(next)
  }, [])

  const setTextSize = useCallback((next: TextSize) => {
    localStorage.setItem(SIZE_KEY, next)
    setTextSizeState(next)
  }, [])

  const value = useMemo<AppearanceState>(
    () => ({ theme, textSize, resolvedTheme, setTheme, setTextSize }),
    [theme, textSize, resolvedTheme, setTheme, setTextSize],
  )

  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>
}

export function useAppearance() {
  const context = useContext(AppearanceContext)
  if (!context) throw new Error('useAppearance must be used inside AppearanceProvider')
  return context
}
