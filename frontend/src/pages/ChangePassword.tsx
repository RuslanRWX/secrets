import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ApiError, api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { Field, Notice } from '../components/ui'

/**
 * ChangePassword is the gate a newly created user passes through. Until it is
 * done the API refuses every other request from that account.
 */
export default function ChangePassword() {
  const navigate = useNavigate()
  const { refresh, user } = useAuth()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')

    if (next !== confirm) {
      setError('The two passwords do not match.')
      return
    }

    setBusy(true)
    try {
      await api.changePassword(current, next)
      await refresh()
      navigate('/secrets')
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The password could not be changed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4">
      <div className="mb-6 animate-rise">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-brass">
          Signed in as {user?.username}
        </p>
        <h1 className="mt-3 font-display text-2xl font-medium tracking-tight">Choose your password</h1>
        <p className="mt-2 text-sm text-muted">
          Your account was created with a temporary password. Replace it to continue.
        </p>
      </div>

      <form onSubmit={submit} className="panel animate-rise space-y-4 p-6">
        <Field label="Temporary password">
          <input
            className="field"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
            autoComplete="current-password"
            autoFocus
          />
        </Field>

        <Field label="New password" hint="At least 12 characters.">
          <input
            className="field"
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
            minLength={12}
            autoComplete="new-password"
          />
        </Field>

        <Field label="Confirm new password">
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

        {error && <Notice kind="error">{error}</Notice>}

        <button type="submit" className="btn-primary w-full" disabled={busy}>
          {busy ? 'Saving…' : 'Save password'}
        </button>
      </form>
    </div>
  )
}
