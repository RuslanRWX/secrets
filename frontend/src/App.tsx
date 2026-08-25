import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { api } from './lib/api'
import { useAuth } from './lib/auth'
import { Layout } from './components/Layout'
import { Spinner } from './components/ui'
import Setup from './pages/Setup'
import Login from './pages/Login'
import ChangePassword from './pages/ChangePassword'
import Secrets from './pages/Secrets'
import Groups from './pages/Groups'
import Users from './pages/Users'
import Tokens from './pages/Tokens'
import Audit from './pages/Audit'
import Settings from './pages/Settings'

/**
 * App resolves three gates in order: is the instance installed, is there a
 * session, and has the user replaced their starting password. Only then does
 * the application itself render.
 */
export default function App() {
  const { user, loading, mustChangePassword, isAdmin, can } = useAuth()
  const location = useLocation()

  const [initialized, setInitialized] = useState<boolean | null>(null)
  const [unreachable, setUnreachable] = useState(false)

  useEffect(() => {
    api
      .setupStatus()
      .then((status) => setInitialized(status.initialized))
      .catch(() => setUnreachable(true))
  }, [])

  if (unreachable) {
    return (
      <div className="flex min-h-screen items-center justify-center px-6 text-center">
        <div>
          <h1 className="font-display text-xl">The API is not responding</h1>
          <p className="mt-2 max-w-sm text-sm text-muted">
            The web interface loaded but could not reach the server. Check that the API container is
            running and that requests to /api reach it.
          </p>
        </div>
      </div>
    )
  }

  if (initialized === null || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Starting" />
      </div>
    )
  }

  if (!initialized) {
    return (
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  if (mustChangePassword) {
    return (
      <Routes>
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="*" element={<Navigate to="/change-password" replace />} />
      </Routes>
    )
  }

  // A signed-in user should never sit on the sign-in screen.
  if (['/login', '/setup', '/change-password'].includes(location.pathname)) {
    return <Navigate to="/secrets" replace />
  }

  return (
    <Layout>
      <Routes>
        <Route path="/secrets" element={<Secrets />} />
        <Route path="/groups" element={<Groups />} />
        <Route path="/tokens" element={<Tokens />} />
        <Route path="/settings" element={<Settings />} />
        {can('users:manage') && <Route path="/users" element={<Users />} />}
        {isAdmin && <Route path="/audit" element={<Audit />} />}
        <Route path="*" element={<Navigate to="/secrets" replace />} />
      </Routes>
    </Layout>
  )
}
