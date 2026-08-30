import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { ApiError, api, type Group, type Secret, type ShareTarget, type User } from '../lib/api'
import { useAuth } from '../lib/auth'
import { PageHeader } from '../components/Layout'
import { Seal } from '../components/Seal'
import { RevealedValue } from '../components/RevealedValue'
import { Empty, Field, Modal, Notice, Spinner, formatDate, useSavedFlash } from '../components/ui'

/** shareOverflow counts the shares a row could not fit, across both kinds. */
function shareOverflow(secret: Secret) {
  const hiddenGroups = Math.max((secret.shares ?? []).length - 2, 0)
  const hiddenUsers = Math.max((secret.userShares ?? []).length - 2, 0)

  return hiddenGroups + hiddenUsers
}

export default function Secrets() {
  const { can, user } = useAuth()

  const [secrets, setSecrets] = useState<Secret[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)

  const load = useCallback(async () => {
    setError('')
    try {
      const [secretList, groupList, userList] = await Promise.all([
        api.listSecrets(),
        api.listGroups(),
        api.listUsers(),
      ])
      setSecrets(secretList.secrets)
      setGroups(groupList.groups)
      setUsers(userList.users)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The vault could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Derived, never copied: the open dialog and the row behind it always agree.
  const selected = useMemo(
    () => secrets.find((secret) => secret.id === selectedId) ?? null,
    [secrets, selectedId],
  )

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return secrets
    return secrets.filter((secret) =>
      [secret.name, secret.description, secret.username, secret.ownerName ?? '']
        .join(' ')
        .toLowerCase()
        .includes(needle),
    )
  }, [secrets, query])

  return (
    <>
      <PageHeader
        title="Secrets"
        description="Passwords and text you keep for yourself or share with a group. Values are decrypted only when you ask for them."
        action={
          can('secrets:create') ? (
            <button className="btn-primary" onClick={() => setAdding(true)}>
              Add secret
            </button>
          ) : undefined
        }
      />

      <div className="mb-4">
        <input
          className="field max-w-sm"
          placeholder="Filter by name, owner or username"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter secrets"
        />
      </div>

      {error && <Notice kind="error">{error}</Notice>}
      {loading && <Spinner label="Opening the vault" />}

      {!loading && filtered.length === 0 && (
        <Empty
          title={
            secrets.length === 0
              ? 'The vault is empty. Add the first secret.'
              : 'Nothing matches that filter.'
          }
          action={
            can('secrets:create') && secrets.length === 0 ? (
              <button className="btn-primary" onClick={() => setAdding(true)}>
                Add secret
              </button>
            ) : undefined
          }
        />
      )}

      {filtered.length > 0 && (
        <ul className="panel divide-y divide-edge overflow-hidden">
          {filtered.map((secret) => (
            <li key={secret.id}>
              <button
                onClick={() => setSelectedId(secret.id)}
                className="flex w-full items-center gap-4 px-4 py-3 text-left transition-colors hover:bg-raised/50"
              >
                <Seal id={secret.id} size={30} className="shrink-0" />

                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-chalk">{secret.name}</span>
                  <span className="block truncate font-mono text-[11px] text-muted">
                    {secret.username || secret.description || secret.kind}
                  </span>
                </span>

                <span className="hidden shrink-0 items-center gap-1.5 sm:flex">
                  {secret.ownerId === user?.id ? (
                    <span className="chip border-brass/30 text-brass">yours</span>
                  ) : (
                    <span className="chip">{secret.ownerName || 'shared'}</span>
                  )}
                  {(secret.shares ?? []).slice(0, 2).map((share) => (
                    <span key={share.groupId} className="chip">
                      {share.groupName}
                      {share.canWrite && <span className="text-brass">rw</span>}
                    </span>
                  ))}
                  {(secret.userShares ?? []).slice(0, 2).map((share) => (
                    <span key={share.userId} className="chip">
                      @{share.username}
                      {share.canWrite && <span className="text-brass">rw</span>}
                    </span>
                  ))}
                  {shareOverflow(secret) > 0 && (
                    <span className="chip">+{shareOverflow(secret)}</span>
                  )}
                </span>

                <span className="shrink-0 font-mono text-[11px] text-muted">v{secret.version}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {adding && (
        <AddSecret
          groups={groups}
          users={users}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false)
            void load()
          }}
        />
      )}

      {selected && (
        <SecretDetail
          secret={selected}
          groups={groups}
          users={users}
          onClose={() => setSelectedId(null)}
          onSaved={load}
          onDeleted={() => {
            setSelectedId(null)
            void load()
          }}
        />
      )}
    </>
  )
}

function AddSecret({
  groups,
  users,
  onClose,
  onSaved,
}: {
  groups: Group[]
  users: User[]
  onClose: () => void
  onSaved: () => void
}) {
  const { can, user: me } = useAuth()

  const [name, setName] = useState('')
  const [kind, setKind] = useState<'password' | 'text'>('password')
  const [username, setUsername] = useState('')
  const [url, setUrl] = useState('')
  const [description, setDescription] = useState('')
  const [value, setValue] = useState('')
  const [shareGroups, setShareGroups] = useState<Record<string, boolean>>({})
  const [shareUsers, setShareUsers] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // You always hold your own secret; offering yourself would be noise.
  const shareableUsers = users.filter((u) => u.isActive && u.id !== me?.id)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)

    try {
      await api.createSecret({
        name: name.trim(),
        kind,
        username,
        url,
        description,
        value,
        shareWith: [
          ...Object.entries(shareGroups)
            .filter(([, on]) => on)
            .map(([groupId]): ShareTarget => ({ groupId, canWrite: false })),
          ...Object.entries(shareUsers)
            .filter(([, on]) => on)
            .map(([userId]): ShareTarget => ({ userId, canWrite: false })),
        ],
      })
      onSaved()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The secret could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title="Add secret" subtitle="Encrypted before it reaches the database." onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name">
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Type">
            <select
              className="field"
              value={kind}
              onChange={(e) => setKind(e.target.value as 'password' | 'text')}
            >
              <option value="password">Password</option>
              <option value="text">Text</option>
            </select>
          </Field>

          {kind === 'password' && (
            <Field label="Username" hint="Optional.">
              <input className="field" value={username} onChange={(e) => setUsername(e.target.value)} />
            </Field>
          )}
        </div>

        <Field label={kind === 'password' ? 'Password' : 'Text'}>
          {kind === 'password' ? (
            <input
              className="field font-mono"
              type="password"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
              autoComplete="new-password"
            />
          ) : (
            <textarea
              className="field h-32 font-mono"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
            />
          )}
        </Field>

        {kind === 'password' && (
          <Field label="URL" hint="Optional.">
            <input className="field" value={url} onChange={(e) => setUrl(e.target.value)} />
          </Field>
        )}

        <Field label="Note" hint="Optional. Never put the secret itself here.">
          <input
            className="field"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        {can('secrets:share') && (groups.length > 0 || shareableUsers.length > 0) && (
          <div className="space-y-3">
            {groups.length > 0 && (
              <ChipPicker
                legend="Share with groups"
                items={groups.map((g) => ({ id: g.id, label: g.name }))}
                selected={shareGroups}
                onChange={setShareGroups}
              />
            )}
            {shareableUsers.length > 0 && (
              <ChipPicker
                legend="Share with people"
                items={shareableUsers.map((u) => ({
                  id: u.id,
                  label: u.displayName || u.username,
                }))}
                selected={shareUsers}
                onChange={setShareUsers}
              />
            )}
            <p className="text-xs text-muted">
              Everyone added here starts read-only. Grant editing from the secret afterwards.
            </p>
          </div>
        )}

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save secret'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

/** ChipPicker is a compact multi-select for a handful of groups or people. */
function ChipPicker({
  legend,
  items,
  selected,
  onChange,
}: {
  legend: string
  items: { id: string; label: string }[]
  selected: Record<string, boolean>
  onChange: (next: Record<string, boolean>) => void
}) {
  return (
    <fieldset>
      <legend className="field-label">{legend}</legend>
      <div className="flex max-h-32 flex-wrap gap-2 overflow-y-auto">
        {items.map((item) => (
          <label
            key={item.id}
            className={[
              'cursor-pointer rounded border px-2.5 py-1 text-xs transition-colors',
              selected[item.id]
                ? 'border-brass/50 bg-brass/10 text-brass-bright'
                : 'border-edge text-muted hover:border-brass/30',
            ].join(' ')}
          >
            <input
              type="checkbox"
              className="sr-only"
              checked={Boolean(selected[item.id])}
              onChange={(e) => onChange({ ...selected, [item.id]: e.target.checked })}
            />
            {item.label}
          </label>
        ))}
      </div>
    </fieldset>
  )
}

/**
 * ShareEditor lists who currently holds a secret and lets the owner add or
 * remove access. Each entry carries its own read or edit setting, so "can
 * change the value" is decided per group and per person.
 */
function ShareEditor({
  secret,
  groups,
  users,
  onChanged,
}: {
  secret: Secret
  groups: Group[]
  users: User[]
  onChanged: (message: string) => Promise<void>
}) {
  const [pending, setPending] = useState('')
  const [pendingWrite, setPendingWrite] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // A toggle is controlled by the server value, so without this it would snap
  // back to the old setting for the length of the round trip and read as a
  // change that did not take.
  const [optimistic, setOptimistic] = useState<Record<string, boolean>>({})

  const groupShares = secret.shares ?? []
  const userShares = secret.userShares ?? []

  const sharedGroups = new Set(groupShares.map((share) => share.groupId))
  const sharedUsers = new Set(userShares.map((share) => share.userId))

  const availableGroups = groups.filter((group) => !sharedGroups.has(group.id))
  const availableUsers = users.filter(
    (user) => user.isActive && !sharedUsers.has(user.id) && user.id !== secret.ownerId,
  )

  async function run(action: () => Promise<unknown>, message: string) {
    setError('')
    setBusy(true)
    try {
      await action()
      await onChanged(message)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Sharing could not be changed.')
    } finally {
      setBusy(false)
      // The reloaded secret is now authoritative again.
      setOptimistic({})
    }
  }

  /** setWrite shows the new setting at once and then persists it. */
  function setWrite(key: string, persist: (canWrite: boolean) => Promise<unknown>) {
    return (canWrite: boolean) => {
      setOptimistic((previous) => ({ ...previous, [key]: canWrite }))

      return run(() => persist(canWrite), canWrite ? 'Editing allowed.' : 'Set to read-only.')
    }
  }

  function addShare(event: FormEvent) {
    event.preventDefault()
    if (!pending) return

    const [kind, id] = pending.split(':')
    const target: ShareTarget =
      kind === 'group' ? { groupId: id, canWrite: pendingWrite } : { userId: id, canWrite: pendingWrite }

    void run(async () => {
      await api.shareSecret(secret.id, target)
      setPending('')
      setPendingWrite(false)
    }, 'Access granted.')
  }

  const rows = [
    ...userShares.map((share) => ({
      key: `user:${share.userId}`,
      label: share.displayName || share.username,
      note: `@${share.username}`,
      canWrite: share.canWrite,
      setWrite: setWrite(`user:${share.userId}`, (canWrite) =>
        api.shareSecret(secret.id, { userId: share.userId, canWrite }),
      ),
      remove: () => run(() => api.unshareUser(secret.id, share.userId), 'Access removed.'),
    })),
    ...groupShares.map((share) => ({
      key: `group:${share.groupId}`,
      label: share.groupName,
      note: 'group',
      canWrite: share.canWrite,
      setWrite: setWrite(`group:${share.groupId}`, (canWrite) =>
        api.shareSecret(secret.id, { groupId: share.groupId, canWrite }),
      ),
      remove: () => run(() => api.unshareGroup(secret.id, share.groupId), 'Access removed.'),
    })),
  ]

  return (
    <div className="border-t border-edge pt-4">
      <p className="field-label">Who can see this</p>

      <ul className="mb-3 divide-y divide-edge rounded-md border border-edge">
        <li className="flex items-center gap-3 px-3 py-2 text-sm">
          <span className="min-w-0 flex-1 truncate text-chalk">{secret.ownerName || 'You'}</span>
          <span className="chip">owner</span>
        </li>

        {rows.map((row) => (
          <li key={row.key} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
            <span className="min-w-0 flex-1 truncate">
              <span className="text-chalk">{row.label}</span>{' '}
              <span className="font-mono text-[11px] text-muted">{row.note}</span>
            </span>

            <label className="flex cursor-pointer items-center gap-1.5 font-mono text-[11px] text-muted">
              <input
                type="checkbox"
                className="h-3 w-3 accent-brass"
                checked={optimistic[row.key] ?? row.canWrite}
                disabled={busy}
                onChange={(e) => row.setWrite(e.target.checked)}
              />
              can edit
            </label>

            <button className="btn-ghost px-2 py-0.5 text-xs" disabled={busy} onClick={row.remove}>
              Remove
            </button>
          </li>
        ))}

        {rows.length === 0 && (
          <li className="px-3 py-2 text-sm text-muted">Nobody else. This secret is yours alone.</li>
        )}
      </ul>

      {(availableGroups.length > 0 || availableUsers.length > 0) && (
        <form onSubmit={addShare} className="flex flex-wrap items-end gap-2">
          <div className="min-w-[12rem] flex-1">
            <Field label="Share with">
              <select className="field" value={pending} onChange={(e) => setPending(e.target.value)}>
                <option value="">Choose a person or group</option>
                {availableUsers.length > 0 && (
                  <optgroup label="People">
                    {availableUsers.map((user) => (
                      <option key={user.id} value={`user:${user.id}`}>
                        {user.displayName || user.username}
                      </option>
                    ))}
                  </optgroup>
                )}
                {availableGroups.length > 0 && (
                  <optgroup label="Groups">
                    {availableGroups.map((group) => (
                      <option key={group.id} value={`group:${group.id}`}>
                        {group.name}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </Field>
          </div>

          <label className="flex cursor-pointer items-center gap-1.5 py-2 text-xs text-muted">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-brass"
              checked={pendingWrite}
              onChange={(e) => setPendingWrite(e.target.checked)}
            />
            can edit
          </label>

          <button type="submit" className="btn-primary" disabled={busy || !pending}>
            Share
          </button>
        </form>
      )}

      {error && <div className="mt-3"><Notice kind="error">{error}</Notice></div>}
    </div>
  )
}

/**
 * SecretDetailsForm edits everything about a secret except its value: the name
 * it is filed under, the account it belongs to, where it is used, and a note.
 * The value has its own form because replacing it keeps a version.
 */
function SecretDetailsForm({
  secret,
  onSaved,
  onFlash,
}: {
  secret: Secret
  onSaved: () => Promise<void>
  onFlash: (message: string) => void
}) {
  const [name, setName] = useState(secret.name)
  const [username, setUsername] = useState(secret.username)
  const [url, setUrl] = useState(secret.url)
  const [description, setDescription] = useState(secret.description)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // A reload replaces the secret this dialog reads from, so take the saved
  // values as the new starting point rather than leaving stale edits behind.
  useEffect(() => {
    setName(secret.name)
    setUsername(secret.username)
    setUrl(secret.url)
    setDescription(secret.description)
  }, [secret.name, secret.username, secret.url, secret.description])

  const changed =
    name.trim() !== secret.name ||
    username !== secret.username ||
    url !== secret.url ||
    description !== secret.description

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)

    try {
      await api.updateSecret(secret.id, {
        name: name.trim(),
        username,
        url,
        description,
      })
      await onSaved()
      onFlash('Details saved.')
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The details could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 border-t border-edge pt-4">
      <p className="field-label">Details</p>

      <Field label="Name">
        <input className="field" value={name} onChange={(e) => setName(e.target.value)} required />
      </Field>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Username" hint="The account this password belongs to.">
          <input className="field" value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>

        <Field label="URL" hint="Where it is used. Include https://.">
          <input
            className="field"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />
        </Field>
      </div>

      <Field label="Note" hint="Never put the secret itself here.">
        <input
          className="field"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </Field>

      {error && <Notice kind="error">{error}</Notice>}

      <div className="flex items-center gap-3">
        <button type="submit" className="btn-ghost" disabled={busy || !changed}>
          {busy ? 'Saving…' : 'Save details'}
        </button>
        {secret.url && (
          <a
            href={secret.url}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-brass hover:underline"
          >
            Open {secret.url}
          </a>
        )}
      </div>
    </form>
  )
}

function SecretDetail({
  secret,
  groups,
  users,
  onClose,
  onSaved,
  onDeleted,
}: {
  secret: Secret
  groups: Group[]
  users: User[]
  onClose: () => void
  /** Reloads the list this dialog reads from, leaving the dialog open. */
  onSaved: () => Promise<void>
  onDeleted: () => void
}) {
  const { can, user } = useAuth()

  const [saved, flashSaved] = useSavedFlash()
  const [revealed, setRevealed] = useState<string | null>(null)
  const [breaking, setBreaking] = useState(false)
  const [newValue, setNewValue] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const isOwner = secret.ownerId === user?.id
  const canEdit = secret.canWrite && can('secrets:update')

  async function reveal() {
    setError('')
    setBreaking(true)
    try {
      const result = await api.revealSecret(secret.id)
      setRevealed(result.value)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The secret could not be decrypted.')
    } finally {
      setBreaking(false)
    }
  }

  async function rotate(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await api.updateSecret(secret.id, { value: newValue })
      setNewValue('')
      setRevealed(null)
      await onSaved()
      flashSaved('New value saved.')
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The new value could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  async function handleShared(message: string) {
    await onSaved()
    flashSaved(message)
  }

  async function remove() {
    if (!window.confirm(`Delete "${secret.name}"? This cannot be undone.`)) return
    setError('')
    try {
      await api.deleteSecret(secret.id)
      onDeleted()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The secret could not be deleted.')
    }
  }

  return (
    <Modal title={secret.name} subtitle={secret.description || undefined} onClose={onClose} width="max-w-2xl">
      <div className="space-y-5">
        <div className="flex items-center gap-4 rounded-md border border-edge bg-vault px-4 py-3">
          <Seal
            id={secret.id}
            size={40}
            broken={revealed !== null}
            className={breaking ? 'animate-seal-break' : ''}
          />
          <dl className="grid flex-1 grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
            <div>
              <dt className="text-muted">Owner</dt>
              <dd className="font-mono text-chalk">{secret.ownerName || '—'}</dd>
            </div>
            <div>
              <dt className="text-muted">Type</dt>
              <dd className="font-mono text-chalk">{secret.kind}</dd>
            </div>
            <div>
              <dt className="text-muted">Version</dt>
              <dd className="font-mono text-chalk">v{secret.version}</dd>
            </div>
            <div>
              <dt className="text-muted">Updated</dt>
              <dd className="font-mono text-chalk">{formatDate(secret.updatedAt)}</dd>
            </div>
          </dl>
        </div>

        {canEdit ? (
          <SecretDetailsForm secret={secret} onSaved={onSaved} onFlash={flashSaved} />
        ) : (
          <>
            {secret.username && (
              <div className="flex items-center gap-3 text-sm">
                <span className="text-muted">Username</span>
                <code className="text-chalk">{secret.username}</code>
              </div>
            )}

            {secret.url && (
              <div className="flex items-center gap-3 text-sm">
                <span className="text-muted">URL</span>
                <a href={secret.url} target="_blank" rel="noreferrer" className="text-brass hover:underline">
                  {secret.url}
                </a>
              </div>
            )}
          </>
        )}

        <div>
          <p className="field-label">Value</p>
          {revealed === null ? (
            <button className="btn-ghost w-full justify-center" onClick={reveal}>
              Reveal value
            </button>
          ) : (
            <RevealedValue value={revealed} onHide={() => setRevealed(null)} />
          )}
        </div>

        {canEdit && (
          <form onSubmit={rotate} className="space-y-2 border-t border-edge pt-4">
            <Field label="Replace value" hint="The previous value is kept in the version history.">
              <input
                className="field font-mono"
                type="password"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                placeholder="New value"
                autoComplete="new-password"
              />
            </Field>
            <button type="submit" className="btn-ghost" disabled={busy || !newValue}>
              {busy ? 'Saving…' : 'Save new value'}
            </button>
          </form>
        )}

        {(isOwner || can('secrets:share')) && (
          <ShareEditor secret={secret} groups={groups} users={users} onChanged={handleShared} />
        )}

        {error && <Notice kind="error">{error}</Notice>}
        {saved && <Notice kind="ok">{saved}</Notice>}

        <div className="flex items-center justify-between border-t border-edge pt-4">
          <code className="text-muted">{secret.id}</code>
          {secret.canWrite && can('secrets:delete') && (
            <button className="btn-danger" onClick={remove}>
              Delete secret
            </button>
          )}
        </div>
      </div>
    </Modal>
  )
}
