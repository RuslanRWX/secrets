import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { ApiError, api, type Group, type Secret } from '../lib/api'
import { useAuth } from '../lib/auth'
import { PageHeader } from '../components/Layout'
import { Seal } from '../components/Seal'
import { RevealedValue } from '../components/RevealedValue'
import { Empty, Field, Modal, Notice, Spinner, formatDate } from '../components/ui'

export default function Secrets() {
  const { can, user } = useAuth()

  const [secrets, setSecrets] = useState<Secret[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<Secret | null>(null)
  const [adding, setAdding] = useState(false)

  const load = useCallback(async () => {
    setError('')
    try {
      const [secretList, groupList] = await Promise.all([api.listSecrets(), api.listGroups()])
      setSecrets(secretList.secrets)
      setGroups(groupList.groups)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The vault could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

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
                onClick={() => setSelected(secret)}
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
                  {(secret.shares ?? []).length > 2 && (
                    <span className="chip">+{(secret.shares ?? []).length - 2}</span>
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
          onClose={() => setSelected(null)}
          onChanged={() => {
            setSelected(null)
            void load()
          }}
        />
      )}
    </>
  )
}

function AddSecret({
  groups,
  onClose,
  onSaved,
}: {
  groups: Group[]
  onClose: () => void
  onSaved: () => void
}) {
  const { can } = useAuth()

  const [name, setName] = useState('')
  const [kind, setKind] = useState<'password' | 'text'>('password')
  const [username, setUsername] = useState('')
  const [url, setUrl] = useState('')
  const [description, setDescription] = useState('')
  const [value, setValue] = useState('')
  const [shareWith, setShareWith] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

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
        shareWith: Object.entries(shareWith)
          .filter(([, on]) => on)
          .map(([groupId]) => ({ groupId, canWrite: false })),
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

        {can('secrets:share') && groups.length > 0 && (
          <fieldset>
            <legend className="field-label">Share with</legend>
            <div className="flex flex-wrap gap-2">
              {groups.map((group) => (
                <label
                  key={group.id}
                  className={[
                    'cursor-pointer rounded border px-2.5 py-1 text-xs transition-colors',
                    shareWith[group.id]
                      ? 'border-brass/50 bg-brass/10 text-brass-bright'
                      : 'border-edge text-muted hover:border-brass/30',
                  ].join(' ')}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={Boolean(shareWith[group.id])}
                    onChange={(e) => setShareWith({ ...shareWith, [group.id]: e.target.checked })}
                  />
                  {group.name}
                </label>
              ))}
            </div>
          </fieldset>
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

function SecretDetail({
  secret,
  groups,
  onClose,
  onChanged,
}: {
  secret: Secret
  groups: Group[]
  onClose: () => void
  onChanged: () => void
}) {
  const { can, user } = useAuth()

  const [current, setCurrent] = useState(secret)
  const [revealed, setRevealed] = useState<string | null>(null)
  const [breaking, setBreaking] = useState(false)
  const [newValue, setNewValue] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const isOwner = current.ownerId === user?.id

  async function reveal() {
    setError('')
    setBreaking(true)
    try {
      const result = await api.revealSecret(current.id)
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
      await api.updateSecret(current.id, { value: newValue })
      setNewValue('')
      setRevealed(null)
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The new value could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  async function toggleShare(groupId: string, on: boolean, canWrite: boolean) {
    setError('')
    try {
      const updated = on
        ? await api.shareSecret(current.id, groupId, canWrite)
        : await api.unshareSecret(current.id, groupId).then(() => api.getSecret(current.id))
      setCurrent(updated as Secret)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Sharing could not be changed.')
    }
  }

  async function remove() {
    if (!window.confirm(`Delete "${current.name}"? This cannot be undone.`)) return
    setError('')
    try {
      await api.deleteSecret(current.id)
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The secret could not be deleted.')
    }
  }

  const shareMap = new Map((current.shares ?? []).map((share) => [share.groupId, share]))

  return (
    <Modal title={current.name} subtitle={current.description || undefined} onClose={onClose} width="max-w-2xl">
      <div className="space-y-5">
        <div className="flex items-center gap-4 rounded-md border border-edge bg-vault px-4 py-3">
          <Seal
            id={current.id}
            size={40}
            broken={revealed !== null}
            className={breaking ? 'animate-seal-break' : ''}
          />
          <dl className="grid flex-1 grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
            <div>
              <dt className="text-muted">Owner</dt>
              <dd className="font-mono text-chalk">{current.ownerName || '—'}</dd>
            </div>
            <div>
              <dt className="text-muted">Type</dt>
              <dd className="font-mono text-chalk">{current.kind}</dd>
            </div>
            <div>
              <dt className="text-muted">Version</dt>
              <dd className="font-mono text-chalk">v{current.version}</dd>
            </div>
            <div>
              <dt className="text-muted">Updated</dt>
              <dd className="font-mono text-chalk">{formatDate(current.updatedAt)}</dd>
            </div>
          </dl>
        </div>

        {current.username && (
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted">Username</span>
            <code className="text-chalk">{current.username}</code>
          </div>
        )}

        {current.url && (
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted">URL</span>
            <a href={current.url} target="_blank" rel="noreferrer" className="text-brass hover:underline">
              {current.url}
            </a>
          </div>
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

        {current.canWrite && can('secrets:update') && (
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

        {(isOwner || can('secrets:share')) && groups.length > 0 && (
          <div className="border-t border-edge pt-4">
            <p className="field-label">Shared with</p>
            <ul className="space-y-1.5">
              {groups.map((group) => {
                const share = shareMap.get(group.id)
                return (
                  <li key={group.id} className="flex items-center gap-3 text-sm">
                    <label className="flex flex-1 cursor-pointer items-center gap-2">
                      <input
                        type="checkbox"
                        checked={Boolean(share)}
                        onChange={(e) => toggleShare(group.id, e.target.checked, false)}
                        className="h-3.5 w-3.5 accent-[#C79A3C]"
                      />
                      <span className={share ? 'text-chalk' : 'text-muted'}>{group.name}</span>
                    </label>
                    {share && (
                      <label className="flex cursor-pointer items-center gap-1.5 font-mono text-[11px] text-muted">
                        <input
                          type="checkbox"
                          checked={share.canWrite}
                          onChange={(e) => toggleShare(group.id, true, e.target.checked)}
                          className="h-3 w-3 accent-[#C79A3C]"
                        />
                        can edit
                      </label>
                    )}
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex items-center justify-between border-t border-edge pt-4">
          <code className="text-muted">{current.id}</code>
          {current.canWrite && can('secrets:delete') && (
            <button className="btn-danger" onClick={remove}>
              Delete secret
            </button>
          )}
        </div>
      </div>
    </Modal>
  )
}
