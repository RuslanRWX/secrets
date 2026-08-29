import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, api } from '../lib/api'
import { useAuth } from '../lib/auth'
import {
  textSizeLabels,
  themeLabels,
  useAppearance,
  type TextSize,
  type Theme,
} from '../lib/appearance'
import { PageHeader } from '../components/Layout'
import { Field, Notice, Panel } from '../components/ui'

export default function Settings() {
  return (
    <>
      <PageHeader title="Settings" description="Your account and how this interface looks on this device." />

      <div className="space-y-4">
        <Appearance />
        <EmailAddress />
        <Password />
        <Account />
        <About />
      </div>
    </>
  )
}

/** Section is one settings card: a title, a line of orientation, and controls. */
function Section({
  title,
  description,
  children,
}: {
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <Panel className="p-6">
      <h2 className="font-display text-base font-medium text-chalk">{title}</h2>
      <p className="mb-4 mt-1 text-sm text-muted">{description}</p>
      {children}
    </Panel>
  )
}

/** Choice is a segmented control; the options are few and always worth showing. */
function Choice<T extends string>({
  legend,
  value,
  options,
  onChange,
}: {
  legend: string
  value: T
  options: { value: T; label: string }[]
  onChange: (next: T) => void
}) {
  return (
    <fieldset>
      <legend className="field-label">{legend}</legend>
      <div className="flex flex-wrap gap-2">
        {options.map((option) => (
          <label
            key={option.value}
            className={[
              'cursor-pointer rounded-md border px-3 py-1.5 text-sm transition-colors',
              option.value === value
                ? 'border-brass/60 bg-brass/10 text-brass-bright'
                : 'border-edge text-muted hover:border-brass/30 hover:text-chalk',
            ].join(' ')}
          >
            <input
              type="radio"
              className="sr-only"
              name={legend}
              checked={option.value === value}
              onChange={() => onChange(option.value)}
            />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  )
}

function Appearance() {
  const { theme, textSize, setTheme, setTextSize } = useAppearance()

  return (
    <Section
      title="Appearance"
      description="Applies to this browser straight away. Other devices keep their own setting."
    >
      <div className="space-y-5">
        <Choice<Theme>
          legend="Theme"
          value={theme}
          onChange={setTheme}
          options={(Object.keys(themeLabels) as Theme[]).map((value) => ({
            value,
            label: themeLabels[value],
          }))}
        />

        <Choice<TextSize>
          legend="Text size"
          value={textSize}
          onChange={setTextSize}
          options={(Object.keys(textSizeLabels) as TextSize[]).map((value) => ({
            value,
            label: textSizeLabels[value],
          }))}
        />

        <p className="rounded-md border border-edge bg-vault px-3 py-2 text-sm text-muted">
          Sample text at this size, next to <code className="text-chalk">a machine identifier</code>.
        </p>
      </div>
    </Section>
  )
}

function EmailAddress() {
  const { user, refresh } = useAuth()

  const [email, setEmail] = useState(user?.email ?? '')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setSaved(false)
    setBusy(true)

    try {
      await api.updateProfile({ email: email.trim() })
      await refresh()
      setSaved(true)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The address could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section title="Email address" description="Used to reach you. Leave it empty if you would rather not give one.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email">
          <input
            className="field max-w-sm"
            type="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value)
              setSaved(false)
            }}
            placeholder="you@example.com"
            autoComplete="email"
          />
        </Field>

        {error && <Notice kind="error">{error}</Notice>}
        {saved && <Notice kind="ok">Email address saved.</Notice>}

        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? 'Saving…' : 'Save email'}
        </button>
      </form>
    </Section>
  )
}

function Password() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setSaved(false)

    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }

    setBusy(true)
    try {
      await api.changePassword(current, next)
      setCurrent('')
      setNext('')
      setConfirm('')
      setSaved(true)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The password could not be changed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section title="Password" description="Changing it here does not sign out your other sessions.">
      <form onSubmit={submit} className="max-w-sm space-y-4">
        <Field label="Current password">
          <input
            className="field"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
            autoComplete="current-password"
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
        {saved && <Notice kind="ok">Password changed.</Notice>}

        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? 'Saving…' : 'Change password'}
        </button>
      </form>
    </Section>
  )
}

/**
 * About names what is actually deployed. The API and the interface are separate
 * images, so a mismatch between them is worth being able to see.
 */
function About() {
  const [instance, setInstance] = useState('')
  const [apiVersion, setApiVersion] = useState('')

  useEffect(() => {
    api
      .setupStatus()
      .then((status) => {
        setInstance(status.instanceName)
        setApiVersion(status.version)
      })
      .catch(() => setApiVersion('unavailable'))
  }, [])

  return (
    <Section title="About" description="What this deployment is running.">
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="field-label">Instance</dt>
          <dd><code className="text-chalk">{instance || '—'}</code></dd>
        </div>
        <div>
          <dt className="field-label">API</dt>
          <dd><code className="text-chalk">{apiVersion || '…'}</code></dd>
        </div>
        <div>
          <dt className="field-label">Interface</dt>
          <dd><code className="text-chalk">{__UI_VERSION__}</code></dd>
        </div>
      </dl>
    </Section>
  )
}

/** Account shows what only an administrator can change, so it is read-only here. */
function Account() {
  const { user, isAdmin, permissions } = useAuth()

  return (
    <Section title="Account" description="An administrator sets these. Ask one if something is wrong.">
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="field-label">Username</dt>
          <dd><code className="text-chalk">{user?.username}</code></dd>
        </div>
        <div>
          <dt className="field-label">Display name</dt>
          <dd className="text-chalk">{user?.displayName || '—'}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="field-label">Access</dt>
          <dd className="flex flex-wrap gap-1.5">
            {isAdmin ? (
              <span className="chip border-brass/40 text-brass">administrator</span>
            ) : permissions.length === 0 ? (
              <span className="text-muted">No permissions granted.</span>
            ) : (
              permissions.map((permission) => (
                <span key={permission} className="chip">
                  {permission}
                </span>
              ))
            )}
          </dd>
        </div>
      </dl>
    </Section>
  )
}
