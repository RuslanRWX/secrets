import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { ApiError, api, session, type Permission, type User } from './api'

interface AuthState {
  user: User | null
  permissions: Permission[]
  isAdmin: boolean
  mustChangePassword: boolean
  loading: boolean
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => void
  refresh: () => Promise<void>
  can: (permission: Permission) => boolean
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [isAdmin, setIsAdmin] = useState(false)
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    if (!session.get()) {
      setUser(null)
      setLoading(false)
      return
    }

    try {
      const me = await api.me()
      setUser(me.user ?? null)
      setPermissions(me.permissions ?? [])
      setIsAdmin(me.isAdmin)
      setMustChangePassword(Boolean(me.mustChangePassword))
    } catch (error) {
      // A rejected credential is the normal way a session ends.
      if (error instanceof ApiError && error.status === 401) session.clear()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const signIn = useCallback(async (username: string, password: string) => {
    const result = await api.login(username, password)
    session.set(result.token)
    setUser(result.user)
    setPermissions(result.user.permissions ?? [])
    setIsAdmin(result.user.isAdmin)
    setMustChangePassword(result.mustChangePassword)
  }, [])

  const signOut = useCallback(() => {
    session.clear()
    setUser(null)
    setPermissions([])
    setIsAdmin(false)
    setMustChangePassword(false)
  }, [])

  const value = useMemo<AuthState>(
    () => ({
      user,
      permissions,
      isAdmin,
      mustChangePassword,
      loading,
      signIn,
      signOut,
      refresh,
      can: (permission) => isAdmin || permissions.includes(permission),
    }),
    [user, permissions, isAdmin, mustChangePassword, loading, signIn, signOut, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
