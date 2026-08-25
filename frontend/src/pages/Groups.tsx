import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, type Group, type User } from '../lib/api'
import { useAuth } from '../lib/auth'
import { PageHeader } from '../components/Layout'
import { Seal } from '../components/Seal'
import { Empty, Field, Modal, Notice, Spinner } from '../components/ui'

export default function Groups() {
  const { can } = useAuth()

  const [groups, setGroups] = useState<Group[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [openGroup, setOpenGroup] = useState<Group | null>(null)

  const load = useCallback(async () => {
    setError('')
    try {
      const [groupList, userList] = await Promise.all([api.listGroups(), api.listUsers()])
      setGroups(groupList.groups)
      setUsers(userList.users)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Groups could not be loaded.')
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
        title="Groups"
        description="A group is who a secret is shared with. Add people to a group once, then share by group instead of one by one."
        action={
          can('groups:create') ? (
            <button className="btn-primary" onClick={() => setCreating(true)}>
              Create group
            </button>
          ) : undefined
        }
      />

      {error && <Notice kind="error">{error}</Notice>}
      {loading && <Spinner label="Loading groups" />}

      {!loading && groups.length === 0 && (
        <Empty
          title="No groups yet. Create one to start sharing."
          action={
            can('groups:create') ? (
              <button className="btn-primary" onClick={() => setCreating(true)}>
                Create group
              </button>
            ) : undefined
          }
        />
      )}

      {groups.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {groups.map((group) => (
            <button
              key={group.id}
              onClick={async () => setOpenGroup(await api.getGroup(group.id))}
              className="panel flex items-start gap-3 p-4 text-left transition-colors hover:border-brass/40"
            >
              <Seal id={group.id} size={30} className="shrink-0" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-chalk">{group.name}</span>
                <span className="mt-0.5 block truncate text-xs text-muted">
                  {group.description || 'No description'}
                </span>
                <span className="mt-2 flex gap-1.5">
                  <span className="chip">
                    {group.memberCount} {group.memberCount === 1 ? 'member' : 'members'}
                  </span>
                  <span className="chip">
                    {group.secretCount} {group.secretCount === 1 ? 'secret' : 'secrets'}
                  </span>
                </span>
              </span>
            </button>
          ))}
        </div>
      )}

      {creating && (
        <CreateGroup
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false)
            void load()
          }}
        />
      )}

      {openGroup && (
        <GroupDetail
          group={openGroup}
          users={users}
          onClose={() => setOpenGroup(null)}
          onChanged={async () => {
            setOpenGroup(await api.getGroup(openGroup.id))
            void load()
          }}
          onDeleted={() => {
            setOpenGroup(null)
            void load()
          }}
        />
      )}
    </>
  )
}

function CreateGroup({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await api.createGroup(name.trim(), description)
      onSaved()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The group could not be created.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title="Create group" subtitle="You become its first manager." onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name">
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label="Description" hint="Optional.">
          <input
            className="field"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        {error && <Notice kind="error">{error}</Notice>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? 'Creating…' : 'Create group'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function GroupDetail({
  group,
  users,
  onClose,
  onChanged,
  onDeleted,
}: {
  group: Group
  users: User[]
  onClose: () => void
  onChanged: () => void
  onDeleted: () => void
}) {
  const { isAdmin, can, user: me } = useAuth()

  const [addUserId, setAddUserId] = useState('')
  const [addRole, setAddRole] = useState<'member' | 'manager'>('member')
  const [name, setName] = useState(group.name)
  const [description, setDescription] = useState(group.description)
  const [renamed, setRenamed] = useState(false)
  const [savingName, setSavingName] = useState(false)
  const [error, setError] = useState('')

  // Group managers may rename their own group without holding groups:manage,
  // and the members list is the reliable way to tell from here.
  const isManager = (group.members ?? []).some(
    (member) => member.userId === me?.id && member.role === 'manager',
  )
  const canRename = isAdmin || can('groups:manage') || isManager
  const nameChanged = name.trim() !== group.name || description !== group.description

  async function rename(event: FormEvent) {
    event.preventDefault()
    setError('')
    setRenamed(false)
    setSavingName(true)

    try {
      await api.updateGroup(group.id, { name: name.trim(), description })
      setRenamed(true)
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The group could not be renamed.')
    } finally {
      setSavingName(false)
    }
  }

  const memberIds = new Set((group.members ?? []).map((m) => m.userId))
  const candidates = users.filter((u) => !memberIds.has(u.id) && u.isActive)

  async function addMember(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      await api.addGroupMember(group.id, addUserId, addRole)
      setAddUserId('')
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The member could not be added.')
    }
  }

  async function removeMember(userId: string) {
    setError('')
    try {
      await api.removeGroupMember(group.id, userId)
      onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The member could not be removed.')
    }
  }

  async function remove() {
    if (!window.confirm(`Delete the group "${group.name}"? Secrets shared with it stay with their owners.`))
      return
    try {
      await api.deleteGroup(group.id)
      onDeleted()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The group could not be deleted.')
    }
  }

  return (
    <Modal title={group.name} subtitle={group.description || undefined} onClose={onClose}>
      <div className="space-y-5">
        {canRename && (
          <form onSubmit={rename} className="space-y-3 border-b border-edge pb-5">
            <Field label="Group name">
              <input
                className="field"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  setRenamed(false)
                }}
                required
              />
            </Field>
            <Field label="Description" hint="Optional.">
              <input
                className="field"
                value={description}
                onChange={(e) => {
                  setDescription(e.target.value)
                  setRenamed(false)
                }}
              />
            </Field>
            {renamed && <Notice kind="ok">Group updated.</Notice>}
            <button type="submit" className="btn-ghost" disabled={savingName || !nameChanged}>
              {savingName ? 'Saving…' : 'Save group details'}
            </button>
          </form>
        )}

        <div>
          <p className="field-label">Members</p>
          {(group.members ?? []).length === 0 ? (
            <p className="text-sm text-muted">Nobody is in this group yet.</p>
          ) : (
            <ul className="divide-y divide-edge rounded-md border border-edge">
              {(group.members ?? []).map((member) => (
                <li key={member.userId} className="flex items-center gap-3 px-3 py-2">
                  <span className="min-w-0 flex-1 truncate text-sm text-chalk">
                    {member.displayName || member.username}
                  </span>
                  <span className="chip">{member.role}</span>
                  <button
                    className="btn-ghost px-2 py-0.5 text-xs"
                    onClick={() => removeMember(member.userId)}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {candidates.length > 0 && (
          <form onSubmit={addMember} className="flex items-end gap-2 border-t border-edge pt-4">
            <div className="flex-1">
              <Field label="Add member">
                <select
                  className="field"
                  value={addUserId}
                  onChange={(e) => setAddUserId(e.target.value)}
                  required
                >
                  <option value="">Choose a person</option>
                  {candidates.map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.displayName || user.username}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="w-32">
              <Field label="Role">
                <select
                  className="field"
                  value={addRole}
                  onChange={(e) => setAddRole(e.target.value as 'member' | 'manager')}
                >
                  <option value="member">Member</option>
                  <option value="manager">Manager</option>
                </select>
              </Field>
            </div>
            <button type="submit" className="btn-primary" disabled={!addUserId}>
              Add
            </button>
          </form>
        )}

        {error && <Notice kind="error">{error}</Notice>}

        <div className="flex items-center justify-between border-t border-edge pt-4">
          <code className="text-muted">{group.id}</code>
          {canRename && (
            <button className="btn-danger" onClick={remove}>
              Delete group
            </button>
          )}
        </div>
      </div>
    </Modal>
  )
}
