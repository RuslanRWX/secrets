# API reference

Base path: `/api/v1`. Every response is JSON. Errors share one shape:

```json
{ "error": "forbidden", "message": "this action requires the secrets:read permission" }
```

## Authentication

Send either a session token from `/auth/login` or an API token:

```
Authorization: Bearer <token>
```

API tokens start with `sks_`. They are matched by prefix and verified against a
stored SHA-256 hash, and are checked on every request for revocation, expiry, and
whether the owning account is still active and still holds the scopes.

## Status codes

| Code | Meaning |
| --- | --- |
| `400` | The request body is malformed or a field is invalid |
| `401` | No credential, or it is expired, revoked or unknown |
| `403` | Authenticated, but missing the required permission |
| `404` | The item does not exist, or is not visible to you |
| `409` | The action conflicts with current state, such as a duplicate username |

A secret you may not read returns `404`, not `403`, so the API does not confirm
that an identifier exists.

## Setup

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/setup/status` | Unauthenticated. Reports whether the install wizard has run. |
| `POST` | `/setup` | Unauthenticated, and succeeds only once. Creates the first administrator and returns a session. |

```sh
curl -X POST https://secrets.example.com/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"instanceName":"platform","username":"admin","password":"a-long-password"}'
```

## Sessions

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/auth/login` | Returns `token`, `expiresAt`, `user` and `mustChangePassword`. |
| `GET` | `/auth/me` | The current principal, its permissions and, for a token, the token itself. |
| `PATCH` | `/auth/me` | Change your own email address. Send `""` to clear it. |
| `POST` | `/auth/change-password` | Requires the current password. Clears the forced-change flag. |
| `GET` | `/meta/permissions` | The permission catalog and the defaults for a new user. |

While `mustChangePassword` is set, every other endpoint returns `403` with the
code `password_change_required`.

`PATCH /auth/me` accepts only `email`. Display name, roles and permissions are
not fields of this endpoint, so a request carrying them is rejected with `400`
rather than silently ignored — an account cannot widen its own access here.

## Secrets

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/secrets` | `secrets:read` |
| `POST` | `/secrets` | `secrets:create` |
| `GET` | `/secrets/{id}` | `secrets:read` |
| `GET` | `/secrets/{id}/reveal` | `secrets:read` |
| `GET` | `/secrets/{id}/versions` | `secrets:read` |
| `PATCH` | `/secrets/{id}` | `secrets:update` |
| `DELETE` | `/secrets/{id}` | `secrets:delete` |
| `POST` | `/secrets/{id}/shares` | `secrets:share` |
| `DELETE` | `/secrets/{id}/shares/{groupId}` | `secrets:share` |

Listing and fetching return metadata only. `reveal` is the sole endpoint that
decrypts, and every call to it is audited.

```sh
# Store a secret and share it with a group in one call
curl -X POST https://secrets.example.com/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "prod postgres",
        "kind": "password",
        "username": "app",
        "value": "the-password",
        "shareWith": [{"groupId": "…", "canWrite": false}]
      }'
```

`PATCH` with a `value` field replaces the secret and keeps the old one in the
version history. Sharing is limited to the owner or an administrator, and only
into groups the sharer belongs to.

## Groups

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/groups` | Any. Non-managers see only their own groups. |
| `POST` | `/groups` | `groups:create`. The creator becomes manager. |
| `GET` | `/groups/{id}` | Members and anyone who can manage groups |
| `PATCH` | `/groups/{id}` | Administrator, group manager, or `groups:manage` |
| `DELETE` | `/groups/{id}` | Administrator, group manager, or `groups:manage` |
| `POST` | `/groups/{id}/members` | Administrator, group manager, or `groups:manage` |
| `DELETE` | `/groups/{id}/members/{userId}` | Administrator, group manager, or `groups:manage` |

Members take a `role` of `member` or `manager`.

## Users

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/users` | Any. Without `users:manage` this is a name-only directory. |
| `POST` | `/users` | `users:manage` |
| `PATCH` | `/users/{id}` | `users:manage`; role and permission changes need administrator |
| `DELETE` | `/users/{id}` | `users:manage` |
| `POST` | `/users/{id}/reset-password` | `users:manage` |

New users and reset passwords always carry the forced-change flag. The last
active administrator cannot be demoted, disabled, or deleted.

## API tokens

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/tokens` | Any. Non-administrators see their own and their groups'. |
| `POST` | `/tokens` | `tokens:create` |
| `DELETE` | `/tokens/{id}` | Owner or administrator |

```sh
curl -X POST https://secrets.example.com/api/v1/tokens \
  -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' \
  -d '{"name":"deploy-pipeline","scopes":["secrets:read"],"expiresInDays":90}'
```

The response carries `plaintext` once and never again. Supply `groupId` instead
of `userId` for a machine credential scoped to a group; a group token can read
what is shared with that group and cannot create anything.

`expiresInDays` of `0` means the token never expires.

## Audit

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/audit?limit=200` | Administrator |

Recorded actions include `auth.login`, `auth.login_failed`,
`auth.password_changed`, `secret.created`, `secret.revealed`,
`secret.value_rotated`, `secret.shared`, `secret.unshared`, `secret.deleted`,
`user.created`, `user.updated`, `user.password_reset`, `user.deleted`,
`group.created`, `group.member_added`, `token.created` and `token.revoked`.

## Health

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. Outside `/api/v1`. |
| `GET` | `/readyz` | Readiness; checks the database. Outside `/api/v1`. |
