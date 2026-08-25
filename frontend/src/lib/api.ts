// Thin wrapper over the REST API. Every call goes through request() so that
// error shapes, auth headers and session expiry are handled in one place.

export type Permission =
  | 'secrets:read'
  | 'secrets:create'
  | 'secrets:update'
  | 'secrets:delete'
  | 'secrets:share'
  | 'groups:create'
  | 'groups:manage'
  | 'tokens:create'
  | 'users:manage'
  | 'audit:read'

export interface User {
  id: string
  username: string
  email?: string
  displayName: string
  isAdmin: boolean
  isActive: boolean
  mustChangePassword: boolean
  permissions: Permission[]
  lastLoginAt?: string
  createdAt: string
}

export interface SecretShare {
  groupId: string
  groupName: string
  canWrite: boolean
  sharedAt: string
}

export interface Secret {
  id: string
  name: string
  description: string
  kind: 'password' | 'text'
  username: string
  url: string
  ownerId?: string
  ownerName?: string
  version: number
  createdAt: string
  updatedAt: string
  shares?: SecretShare[]
  canWrite: boolean
}

export interface GroupMember {
  userId: string
  username: string
  displayName: string
  role: 'member' | 'manager'
  addedAt: string
}

export interface Group {
  id: string
  name: string
  description: string
  createdAt: string
  memberCount: number
  secretCount: number
  members?: GroupMember[]
}

export interface ApiToken {
  id: string
  name: string
  prefix: string
  userId?: string
  username?: string
  groupId?: string
  groupName?: string
  scopes: Permission[]
  expiresAt?: string
  lastUsedAt?: string
  revokedAt?: string
  createdAt: string
}

export interface AuditEntry {
  id: number
  actorLabel: string
  action: string
  targetType: string
  targetId: string
  detail: Record<string, unknown>
  ip: string
  createdAt: string
}

/** ApiError carries the machine-readable code so callers can branch on it. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

const TOKEN_KEY = 'secrets.session'

export const session = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (token: string) => localStorage.setItem(TOKEN_KEY, token),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  const token = session.get()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 204) return undefined as T

  const raw = await response.text()
  const parsed = raw ? JSON.parse(raw) : {}

  if (!response.ok) {
    throw new ApiError(
      response.status,
      parsed.error ?? 'error',
      parsed.message ?? `request failed with status ${response.status}`,
    )
  }

  return parsed as T
}

export interface SetupStatus {
  initialized: boolean
  instanceName: string
  version: string
}

export interface LoginResult {
  token: string
  expiresAt: string
  user: User
  mustChangePassword: boolean
}

export const api = {
  setupStatus: () => request<SetupStatus>('GET', '/setup/status'),
  setup: (body: {
    instanceName: string
    username: string
    password: string
    email?: string
    displayName?: string
  }) => request<LoginResult>('POST', '/setup', body),

  login: (username: string, password: string) =>
    request<LoginResult>('POST', '/auth/login', { username, password }),
  me: () =>
    request<{ user?: User; permissions: Permission[]; isAdmin: boolean; mustChangePassword?: boolean }>(
      'GET',
      '/auth/me',
    ),
  updateProfile: (body: { email: string }) => request<User>('PATCH', '/auth/me', body),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ status: string }>('POST', '/auth/change-password', { currentPassword, newPassword }),
  permissionCatalog: () =>
    request<{ permissions: Permission[]; defaults: Permission[] }>('GET', '/meta/permissions'),

  listSecrets: () => request<{ secrets: Secret[] }>('GET', '/secrets'),
  getSecret: (id: string) => request<Secret>('GET', `/secrets/${id}`),
  revealSecret: (id: string) => request<{ id: string; value: string }>('GET', `/secrets/${id}/reveal`),
  createSecret: (body: {
    name: string
    description?: string
    kind: 'password' | 'text'
    username?: string
    url?: string
    value: string
    shareWith?: { groupId: string; canWrite: boolean }[]
  }) => request<Secret>('POST', '/secrets', body),
  updateSecret: (
    id: string,
    body: Partial<{ name: string; description: string; username: string; url: string; value: string }>,
  ) => request<Secret>('PATCH', `/secrets/${id}`, body),
  deleteSecret: (id: string) => request<void>('DELETE', `/secrets/${id}`),
  shareSecret: (id: string, groupId: string, canWrite: boolean) =>
    request<Secret>('POST', `/secrets/${id}/shares`, { groupId, canWrite }),
  unshareSecret: (id: string, groupId: string) =>
    request<void>('DELETE', `/secrets/${id}/shares/${groupId}`),
  secretVersions: (id: string) =>
    request<{ versions: { id: string; version: number; createdAt: string }[] }>(
      'GET',
      `/secrets/${id}/versions`,
    ),

  listGroups: () => request<{ groups: Group[] }>('GET', '/groups'),
  getGroup: (id: string) => request<Group>('GET', `/groups/${id}`),
  createGroup: (name: string, description: string) =>
    request<Group>('POST', '/groups', { name, description }),
  updateGroup: (id: string, body: { name?: string; description?: string }) =>
    request<Group>('PATCH', `/groups/${id}`, body),
  deleteGroup: (id: string) => request<void>('DELETE', `/groups/${id}`),
  addGroupMember: (id: string, userId: string, role: 'member' | 'manager') =>
    request<Group>('POST', `/groups/${id}/members`, { userId, role }),
  removeGroupMember: (id: string, userId: string) =>
    request<void>('DELETE', `/groups/${id}/members/${userId}`),

  listUsers: () => request<{ users: User[] }>('GET', '/users'),
  createUser: (body: {
    username: string
    password: string
    email?: string
    displayName?: string
    isAdmin: boolean
    permissions: Permission[]
  }) => request<User>('POST', '/users', body),
  updateUser: (
    id: string,
    body: Partial<{
      email: string
      displayName: string
      isAdmin: boolean
      isActive: boolean
      permissions: Permission[]
    }>,
  ) => request<User>('PATCH', `/users/${id}`, body),
  deleteUser: (id: string) => request<void>('DELETE', `/users/${id}`),
  resetPassword: (id: string, newPassword: string) =>
    request<{ status: string }>('POST', `/users/${id}/reset-password`, { newPassword }),

  listTokens: () => request<{ tokens: ApiToken[] }>('GET', '/tokens'),
  createToken: (body: {
    name: string
    userId?: string
    groupId?: string
    scopes: Permission[]
    expiresInDays: number
  }) => request<{ token: ApiToken; plaintext: string }>('POST', '/tokens', body),
  revokeToken: (id: string) => request<void>('DELETE', `/tokens/${id}`),

  audit: (limit = 200) => request<{ entries: AuditEntry[] }>('GET', `/audit?limit=${limit}`),
}

/** Human-readable labels for permission flags, used everywhere they are shown. */
export const permissionLabels: Record<Permission, string> = {
  'secrets:read': 'View secrets',
  'secrets:create': 'Add secrets',
  'secrets:update': 'Edit secrets',
  'secrets:delete': 'Delete secrets',
  'secrets:share': 'Share with groups',
  'groups:create': 'Create groups',
  'groups:manage': 'Manage all groups',
  'tokens:create': 'Create API tokens',
  'users:manage': 'Manage users',
  'audit:read': 'Read the audit log',
}
