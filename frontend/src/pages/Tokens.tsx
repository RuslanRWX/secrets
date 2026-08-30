import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  ApiError,
  api,
  groupTokenScopes,
  permissionLabels,
  type ApiToken,
  type Group,
  type Permission,
  type User,
} from '../lib/api'
import { useAuth } from '../lib/auth'
import { PageHeader } from '../components/Layout'
import { CopyButton, Empty, Field, Modal, Notice, Spinner, formatDate } from '../components/ui'

export default function Tokens() {
  const { can, isAdmin, permissions } = useAuth()

  const [tokens, setTokens] = useState<ApiToken[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    setError('')
    try {
      const [tokenList, groupList, userList] = await Promise.all([
        api.listTokens(),
        api.listGroups(),
        api.listUsers(),
      ])
      setTokens(tokenList.tokens)
      setGroups(groupList.groups)
      setUsers(userList.users)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Tokens could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function revoke(token: ApiToken) {
    if (!window.confirm(`Revoke "${token.name}"? Anything using it stops working immediately.`)) return
    try {
      await api.revokeToken(token.id)
      void load()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The token could not be revoked.')
    }
  }

  return (
    <>
      <PageHeader
        title="API tokens"
        description="Tokens let a script or a pipeline read secrets over the API. A token never carries more permission than the account or group behind it."
        action={
          can('tokens:create') ? (
            <button className="btn-primary" onClick={() => setCreating(true)}>
              Create token
            </button>
          ) : undefined
        }
      />

      {error && <Notice kind="error">{error}</Notice>}
      {loading && <Spinner label="Loading tokens" />}

      {!loading && tokens.length === 0 && (
        <Empty
          title="No tokens yet. Create one to reach the API from a script."
          action={
            can('tokens:create') ? (
              <button className="btn-primary" onClick={() => setCreating(true)}>
                Create token
              </button>
            ) : undefined
          }
        />
      )}

      {tokens.length > 0 && (
        <ul className="panel divide-y divide-edge">
          {tokens.map((token) => {
            const revoked = Boolean(token.revokedAt)
            const expired = token.expiresAt ? new Date(token.expiresAt) < new Date() : false
            return (
              <li key={token.id} className={`px-4 py-3 ${revoked || expired ? 'opacity-50' : ''}`}>
                <div className="flex flex-wrap items-center gap-3">
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-chalk">{token.name}</span>
                    <code className="text-muted">sks_{token.prefix}…</code>
                  </span>

                  <span className="chip">
                    {token.groupId ? `group ${token.groupName}` : `user ${token.username}`}
                  </span>

                  {revoked && <span className="chip border-breach/40 text-breach">revoked</span>}
                  {!revoked && expired && <span className="chip border-breach/40 text-breach">expired</span>}

                  {!revoked && (
                    <button className="btn-ghost px-2.5 py-1 text-xs" onClick={() => revoke(token)}>
                      Revoke
                    </button>
                  )}
                </div>

                <div className="mt-2 flex flex-wrap gap-1.5">
                  {token.scopes.map((scope) => (
                    <span key={scope} className="chip">
                      {scope}
                    </span>
                  ))}
                </div>

                <p className="mt-2 font-mono text-[11px] text-muted">
                  created {formatDate(token.createdAt)}
                  {token.createdByName && ` by ${token.createdByName}`} · last used{' '}
                  {formatDate(token.lastUsedAt)}
                  {token.expiresAt && ` · expires ${formatDate(token.expiresAt)}`}
                </p>
              </li>
            )
          })}
        </ul>
      )}

      {creating && (
        <CreateToken
          groups={groups}
          users={users}
          isAdmin={isAdmin}
          ownPermissions={permissions}
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false)
            void load()
          }}
        />
      )}
    </>
  )
}

function CreateToken({
  groups,
  users,
  isAdmin,
  ownPermissions,
  onClose,
  onSaved,
}: {
  groups: Group[]
  users: User[]
  isAdmin: boolean
  ownPermissions: Permission[]
  onClose: () => void
  onSaved: () => void
}) {
  const [name, setName] = useState('')
  const [bearer, setBearer] = useState<'self' | 'user' | 'group'>('self')
  const [userId, setUserId] = useState('')
  const [groupId, setGroupId] = useState('')
  const [scopes, setScopes] = useState<Permission[]>(['secrets:read'])
  const [expiresInDays, setExpiresInDays] = useState(90)
  const [issued, setIssued] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // A self-issued token can only carry what the caller already holds, and a
  // group token is further limited to the permissions a group can act on.
  const held: Permission[] = isAdmin
    ? (Object.keys(permissionLabels) as Permission[])
    : ownPermissions
  const offered = bearer === 'group' ? held.filter((p) => groupTokenScopes.includes(p)) : held

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const result = await api.createToken({
        name: name.trim(),
        userId: bearer === 'user' ? userId : undefined,
        groupId: bearer === 'group' ? groupId : undefined,
        scopes,
        expiresInDays,
      })
      setIssued(result.plaintext)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The token could not be created.')
    } finally {
      setBusy(false)
    }
  }

  if (issued) {
    return (
      <Modal
        title="Token created"
        subtitle="Copy it now. The server keeps only a hash, so this is the only time it is shown."
        onClose={onSaved}
      >
        <div className="space-y-4">
          <div className="rounded-md border border-brass/30 bg-vault p-3">
            <div className="flex items-start gap-2">
              <code className="flex-1 break-all text-brass-bright">{issued}</code>
              <CopyButton value={issued} />
            </div>
          </div>

          <div>
            <p className="field-label">Use it like this</p>
            <pre className="overflow-x-auto rounded-md border border-edge bg-vault p-3 font-mono text-[11px] leading-relaxed text-muted">
{`curl -H "Authorization: Bearer ${issued}" \\
  ${window.location.origin}/api/v1/secrets`}
            </pre>
          </div>

          <button className="btn-primary w-full" onClick={onSaved}>
            Done
          </button>
        </div>
      </Modal>
    )
  }

  return (
    <Modal title="Create API token" subtitle="Scope it to the least it needs." onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" hint="Name it after what will use it, such as deploy-pipeline.">
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>

        <Field label="Acts as">
          <select
            className="field"
            value={bearer}
            onChange={(e) => {
              const next = e.target.value as 'self' | 'user' | 'group'
              setBearer(next)
              if (next === 'group') {
                setScopes((current) => current.filter((s) => groupTokenScopes.includes(s)))
              }
            }}
          >
            <option value="self">Me</option>
            {isAdmin && <option value="user">Another user</option>}
            <option value="group">A group you belong to</option>
          </select>
        </Field>

        {bearer === 'user' && (
          <Field label="User">
            <select className="field" value={userId} onChange={(e) => setUserId(e.target.value)} required>
              <option value="">Choose a user</option>
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.displayName || user.username}
                </option>
              ))}
            </select>
          </Field>
        )}

        {bearer === 'group' && (
          <Field
            label="Group"
            hint="The token reaches only the secrets shared with this group, and nothing that belongs to you personally."
          >
            <select className="field" value={groupId} onChange={(e) => setGroupId(e.target.value)} required>
              <option value="">Choose a group</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
          </Field>
        )}

        <fieldset>
          <legend className="field-label">Scopes</legend>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {offered.map((permission) => (
              <label
                key={permission}
                className={[
                  'flex cursor-pointer items-center gap-2 rounded border px-2.5 py-1.5 text-xs transition-colors',
                  scopes.includes(permission) ? 'border-brass/50 bg-brass/10' : 'border-edge hover:border-brass/30',
                ].join(' ')}
              >
                <input
                  type="checkbox"
                  className="h-3 w-3 accent-brass"
                  checked={scopes.includes(permission)}
                  onChange={(e) =>
                    setScopes(
                      e.target.checked
                        ? [...scopes, permission]
                        : scopes.filter((s) => s !== permission),
                    )
                  }
                />
                <code className="text-chalk">{permission}</code>
              </label>
            ))}
          </div>
        </fieldset>

        <Field label="Expires in days" hint="Zero means the token never expires.">
          <input
            className="field"
            type="number"
            min={0}
            max={3650}
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(Number(e.target.value))}
          />
        </Field>

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={busy || scopes.length === 0}>
            {busy ? 'Creating…' : 'Create token'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
