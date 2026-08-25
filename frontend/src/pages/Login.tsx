import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ApiError, api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { Field, Notice } from '../components/ui'

export default function Login() {
  const navigate = useNavigate()
  const { signIn } = useAuth()

  const [instanceName, setInstanceName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api
      .setupStatus()
      .then((status) => setInstanceName(status.instanceName))
      .catch(() => setInstanceName(''))
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)

    try {
      await signIn(username.trim(), password)
      navigate('/secrets')
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'Sign-in failed. Check the server is reachable.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4">
      <div className="mb-8 flex items-center gap-3 animate-rise">
        <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden className="text-brass">
          <circle cx="16" cy="13" r="5" fill="none" stroke="currentColor" strokeWidth="2.5" />
          <path d="M16 18v7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
          <path d="M16 22h4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
        <div>
          <h1 className="font-display text-xl font-medium tracking-tight">Secrets</h1>
          {instanceName && <p className="font-mono text-xs text-muted">{instanceName}</p>}
        </div>
      </div>

      <form onSubmit={submit} className="panel animate-rise space-y-4 p-6">
        <Field label="Username">
          <input
            className="field"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
            autoFocus
          />
        </Field>

        <Field label="Password">
          <input
            className="field"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </Field>

        {error && <Notice kind="error">{error}</Notice>}

        <button type="submit" className="btn-primary w-full" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
