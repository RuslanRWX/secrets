import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, permissionLabels, type Permission, type User } from '../lib/api'
import { useAuth } from '../lib/auth'
import { PageHeader } from '../components/Layout'
import { CopyButton, Empty, Field, Modal, Notice, Spinner, formatDate } from '../components/ui'

const ALL_PERMISSIONS = Object.keys(permissionLabels) as Permission[]
const DEFAULT_PERMISSIONS: Permission[] = [
  'secrets:read',
  'secrets:create',
  'secrets:update',
  'secrets:share',
]

export default function Users() {
  const { user: me } = useAuth()

  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)

  const load = useCallback(async () => {
    setError('')
    try {
      const result = await api.listUsers()
      setUsers(result.users)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Users could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <>
      <PageHeader
        title="Users"
        description="Each person gets an account, a starting password they must replace, and the set of permissions you choose."
        action={
          <button className="btn-primary" onClick={() => setCreating(true)}>
            Add user
          </button>
        }
      />

      {error && <Notice kind="error">{error}</Notice>}
      {loading && <Spinner label="Loading users" />}
      {!loading && users.length === 0 && <Empty title="No users yet." />}

      {users.length > 0 && (
        <div className="panel overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-edge text-xs uppercase tracking-[0.12em] text-muted">
                <th className="px-4 py-3 font-medium">User</th>
                <th className="px-4 py-3 font-medium">Access</th>
                <th className="px-4 py-3 font-medium">Last sign-in</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {users.map((user) => (
                <tr key={user.id} className={user.isActive ? '' : 'opacity-50'}>
                  <td className="px-4 py-3">
                    <span className="block text-chalk">{user.displayName || user.username}</span>
                    <code className="text-muted">{user.username}</code>
                  </td>
                  <td className="px-4 py-3">
                    {user.isAdmin ? (
                      <span className="chip border-brass/40 text-brass">administrator</span>
                    ) : (
                      <span className="chip">{user.permissions.length} permissions</span>
                    )}
                    {user.mustChangePassword && (
                      <span className="chip ml-1.5 border-sealed/40 text-sealed">password pending</span>
                    )}
                    {!user.isActive && <span className="chip ml-1.5 border-breach/40 text-breach">disabled</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{formatDate(user.lastLoginAt)}</td>
                  <td className="px-4 py-3 text-right">
                    <button className="btn-ghost px-2.5 py-1 text-xs" onClick={() => setEditing(user)}>
                      {user.id === me?.id ? 'You' : 'Manage'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false)
            void load()
          }}
        />
      )}

      {editing && (
        <EditUser
          user={editing}
          onClose={() => setEditing(null)}
          onChanged={() => {
            setEditing(null)
            void load()
          }}
        />
      )}
    </>
  )
}

/** PermissionPicker is used both when creating a user and when editing one. */
function PermissionPicker({
  selected,
  onChange,
  disabled = false,
}: {
  selected: Permission[]
  onChange: (next: Permission[]) => void
  disabled?: boolean
}) {
  return (
    <fieldset disabled={disabled}>
      <legend className="field-label">Permissions</legend>
      <div className="grid gap-1.5 sm:grid-cols-2">
        {ALL_PERMISSIONS.map((permission) => (
          <label
            key={permission}
            className={[
              'flex cursor-pointer items-start gap-2 rounded border px-2.5 py-1.5 text-xs transition-colors',
              selected.includes(permission)
                ? 'border-brass/50 bg-brass/10'
                : 'border-edge hover:border-brass/30',
              disabled ? 'cursor-not-allowed opacity-50' : '',
            ].join(' ')}
          >
            <input
              type="checkbox"
              className="mt-0.5 h-3 w-3 accent-[#C79A3C]"
              checked={selected.includes(permission)}
              onChange={(e) =>
                onChange(
                  e.target.checked
                    ? [...selected, permission]
                    : selected.filter((p) => p !== permission),
                )
              }
            />
            <span>
              <span className="block text-chalk">{permissionLabels[permission]}</span>
              <code className="text-muted">{permission}</code>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  )
}

/** randomPassword generates a starting password so an admin does not invent one. */
function randomPassword() {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const values = crypto.getRandomValues(new Uint32Array(20))
  return Array.from(values, (v) => alphabet[v % alphabet.length]).join('')
}

function CreateUser({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState(randomPassword)
  const [isAdmin, setIsAdmin] = useState(false)
  const [permissions, setPermissions] = useState<Permission[]>(DEFAULT_PERMISSIONS)
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await api.createUser({
        username: username.trim(),
        password,
        displayName,
        email,
        isAdmin,
        permissions,
      })
      setCreated({ username: username.trim(), password })
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The user could not be created.')
    } finally {
      setBusy(false)
    }
  }

  if (created) {
    return (
      <Modal
        title="User created"
        subtitle="Hand these over once. The password must be changed at first sign-in."
        onClose={onSaved}
      >
        <div className="space-y-3">
          <div className="rounded-md border border-brass/30 bg-vault p-3">
            <p className="field-label">Username</p>
            <code className="text-chalk">{created.username}</code>
            <p className="field-label mt-3">Temporary password</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all text-brass-bright">{created.password}</code>
              <CopyButton value={created.password} />
            </div>
          </div>
          <button className="btn-primary w-full" onClick={onSaved}>
            Done
          </button>
        </div>
      </Modal>
    )
  }

  return (
    <Modal title="Add user" subtitle="They choose their own password at first sign-in." onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Username">
            <input
              className="field"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </Field>
          <Field label="Display name" hint="Optional.">
            <input
              className="field"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>
        </div>

        <Field label="Email" hint="Optional.">
          <input className="field" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>

        <Field label="Temporary password" hint="Generated for you. Share it once, in person or over a trusted channel.">
          <div className="flex gap-2">
            <input
              className="field font-mono"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
            />
            <button type="button" className="btn-ghost shrink-0" onClick={() => setPassword(randomPassword())}>
              Regenerate
            </button>
          </div>
        </Field>

        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <input
            type="checkbox"
            className="h-3.5 w-3.5 accent-[#C79A3C]"
            checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
          />
          <span className="text-chalk">Administrator</span>
          <span className="text-xs text-muted">— holds every permission</span>
        </label>

        <PermissionPicker selected={permissions} onChange={setPermissions} disabled={isAdmin} />

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? 'Creating…' : 'Create user'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function EditUser({
  user,
  onClose,
  onChanged,
}: {
  user: User
  onClose: () => void
  onChanged: () => void
}) {
  const [permissions, setPermissions] = useState<Permission[]>(user.permissions)
  const [isAdmin, setIsAdmin] = useState(user.isAdmin)
  const [isActive, setIsActive] = useState(user.isActive)
  const [resetTo, setResetTo] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function save() {
    setError('')
    setBusy(true)
    try {
      await api.updateUser(user.id, { permissions, isAdmin, isActive })
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The changes could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  async function resetPassword() {
    setError('')
    const password = randomPassword()
    try {
      await api.resetPassword(user.id, password)
      setResetTo(password)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The password could not be reset.')
    }
  }

  async function remove() {
    if (!window.confirm(`Delete ${user.username}? Every secret they own is deleted with them.`)) return
    setError('')
    try {
      await api.deleteUser(user.id)
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The user could not be deleted.')
    }
  }

  return (
    <Modal title={user.displayName || user.username} subtitle={user.email || undefined} onClose={onClose}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-4">
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-[#C79A3C]"
              checked={isAdmin}
              onChange={(e) => setIsAdmin(e.target.checked)}
            />
            <span className="text-chalk">Administrator</span>
          </label>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-[#C79A3C]"
              checked={isActive}
              onChange={(e) => setIsActive(e.target.checked)}
            />
            <span className="text-chalk">Account enabled</span>
          </label>
        </div>

        <PermissionPicker selected={permissions} onChange={setPermissions} disabled={isAdmin} />

        {resetTo && (
          <div className="rounded-md border border-brass/30 bg-vault p-3">
            <p className="field-label">New temporary password</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all text-brass-bright">{resetTo}</code>
              <CopyButton value={resetTo} />
            </div>
          </div>
        )}

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-edge pt-4">
          <div className="flex gap-2">
            <button className="btn-ghost" onClick={resetPassword}>
              Reset password
            </button>
            <button className="btn-danger" onClick={remove}>
              Delete
            </button>
          </div>
          <button className="btn-primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </Modal>
  )
}
