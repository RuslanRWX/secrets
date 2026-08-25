import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ApiError, api, session } from '../lib/api'
import { useAuth } from '../lib/auth'
import { Field, Notice } from '../components/ui'

/**
 * Setup runs once, on a fresh installation. It creates the first administrator
 * and stamps the master key fingerprint into the database.
 */
export default function Setup() {
  const navigate = useNavigate()
  const { refresh } = useAuth()

  const [instanceName, setInstanceName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')

    if (password !== confirm) {
      setError('The two passwords do not match.')
      return
    }

    setBusy(true)
    try {
      const result = await api.setup({
        instanceName: instanceName.trim() || 'secrets',
        username: username.trim(),
        password,
      })
      session.set(result.token)
      await refresh()
      navigate('/secrets')
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Setup could not be completed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-xl flex-col justify-center px-4 py-12">
      <div className="mb-8 animate-rise">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-brass">First run</p>
        <h1 className="mt-3 font-display text-3xl font-medium tracking-tight">
          Open the vault for the first time
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-muted">
          This creates the administrator account. Everything stored here is encrypted with the master
          key you supplied to the server, so keep that key safe: without it the stored secrets cannot
          be read again.
        </p>
      </div>

      <form onSubmit={submit} className="panel animate-rise space-y-5 p-6">
        <Field label="Instance name" hint="Shown on the sign-in screen. Name it after the team or environment.">
          <input
            className="field"
            value={instanceName}
            onChange={(e) => setInstanceName(e.target.value)}
            placeholder="platform-team"
            autoComplete="off"
          />
        </Field>

        <Field label="Administrator username">
          <input
            className="field"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
            placeholder="admin"
          />
        </Field>

        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Password" hint="At least 12 characters.">
            <input
              className="field"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              autoComplete="new-password"
            />
          </Field>
          <Field label="Confirm password">
            <input
              className="field"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              minLength={12}
              autoComplete="new-password"
            />
          </Field>
        </div>

        {error && <Notice kind="error">{error}</Notice>}

        <button type="submit" className="btn-primary w-full" disabled={busy}>
          {busy ? 'Creating the administrator…' : 'Create administrator'}
        </button>
      </form>
    </div>
  )
}
