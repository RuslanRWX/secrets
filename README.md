# Secrets

A small self-hosted secrets manager. Keep passwords and text, share them with a
group, and read them from a script over the API.

- **Encrypted at rest.** Every value is sealed with its own key, and that key is
  sealed with a master key you supply. Nothing readable reaches PostgreSQL.
- **Two services.** `backend/` is a Go API, `frontend/` is a React app served by
  nginx. They ship as separate images.
- **Install from a browser.** The first page you open creates the administrator.
- **Permissions, not roles.** An administrator grants named flags per user, and
  an API token can never carry more than the account behind it.

## Quick start with Docker Compose

```sh
cp .env.example .env

# Generate the two keys. Keep MASTER_KEY safe: without it the stored
# secrets cannot be read again.
sed -i "s|^MASTER_KEY=.*|MASTER_KEY=$(openssl rand -base64 32)|" .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -base64 32)|" .env

docker compose up -d
```

Open <http://localhost:8088>. The install wizard asks for an instance name and
the administrator's username and password. From there, add users on the **Users**
page: each gets a generated temporary password and must choose their own at first
sign-in.

## Install on Kubernetes

```sh
helm install secrets ./helm/secrets \
  --namespace secrets --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=secrets.example.com
```

The chart generates a master key on first install and reuses it on every upgrade,
so an upgrade never orphans your data. Back it up straight away:

```sh
kubectl -n secrets get secret secrets-keys \
  -o jsonpath='{.data.master-key}' | base64 -d; echo
```

To supply your own key instead, pass `--set encryption.masterKey=...`, or point
the chart at a Secret you manage with `--set encryption.existingSecret=my-keys`
(it must hold `master-key` and `jwt-secret`).

The chart bundles a single-replica PostgreSQL for evaluation. For anything real,
use a managed database:

```sh
helm install secrets ./helm/secrets --namespace secrets --create-namespace \
  --set postgresql.enabled=false \
  --set externalDatabase.host=db.internal \
  --set externalDatabase.password=... \
  --set externalDatabase.sslmode=require
```

## How access works

A secret has one **owner**, the user who created it. The owner can share it with
any **group** they belong to, either read-only or read-write. Access is the union
of those two rules, and administrators can see everything.

**Permissions** are granted per user by an administrator:

| Flag | What it allows |
| --- | --- |
| `secrets:read` | See the vault and decrypt values you have access to |
| `secrets:create` | Add new secrets |
| `secrets:update` | Edit secrets and replace their values |
| `secrets:delete` | Delete secrets |
| `secrets:share` | Share your own secrets with groups |
| `groups:create` | Create groups, becoming their manager |
| `groups:manage` | Manage any group, not just your own |
| `tokens:create` | Mint API tokens |
| `users:manage` | Add, edit and remove users |
| `audit:read` | Read the audit log |

A group's **manager** can add and remove its members, and rename the group,
without holding `groups:manage`.

## What each person controls

From **Settings**, any signed-in user can change their own password and email
address, and pick a theme (night, day, or match the system) and a text size.
Appearance is stored in the browser, so the same account can be set differently
on a laptop and on a shared screen.

Display name, permissions and the admin flag stay with an administrator: the
name is how other people recognise the account in group and user lists.

## Using the API

Create a token on the **API tokens** page. A token belongs either to a user, in
which case it acts as that person, or to a group, in which case it can only read
what is shared with that group. Its scopes are a subset of what the owner holds,
checked on every request: revoking a permission from a user immediately narrows
every token they issued.

```sh
TOKEN=sks_...

# List what the token can reach. Values are never included.
curl -H "Authorization: Bearer $TOKEN" https://secrets.example.com/api/v1/secrets

# Decrypt one value. This call is written to the audit log.
curl -H "Authorization: Bearer $TOKEN" \
  https://secrets.example.com/api/v1/secrets/$ID/reveal
```

Full endpoint reference: [docs/api.md](docs/api.md).

## Configuration

The API reads its settings from the environment.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | — | PostgreSQL connection string. Assembled from the `POSTGRES_*` variables when unset. |
| `MASTER_KEY` | — | **Required.** Encrypts every secret. At least 16 characters. |
| `JWT_SECRET` | — | **Required.** Signs session tokens. At least 16 characters. |
| `PORT` | `8080` | Listen port. |
| `SESSION_TTL` | `12h` | How long a browser session lasts. |
| `CORS_ORIGINS` | — | Comma-separated origins, when the UI is served elsewhere. |
| `TRUST_PROXY_HEADERS` | `false` | Read the client address from `X-Forwarded-For`. |
| `AUTO_MIGRATE` | `true` | Apply schema migrations at start. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

`POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`,
`POSTGRES_PASSWORD` and `POSTGRES_SSLMODE` are used when `DATABASE_URL` is not
set, which is how the Helm chart wires things up.

## How the encryption works

```
MASTER_KEY  ──HKDF-SHA256──▶  key-encryption key
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
        wraps a random data key           wraps another data key
        (AES-256-GCM)                     for the next secret
                     │                               │
                     ▼                               ▼
        seals one secret value            seals that secret value
```

Each secret gets a fresh 256-bit data key, so two identical passwords produce
different ciphertext. Only the wrapped data key and the sealed value are stored.
At install time the server seals a known constant and keeps it; on every later
start it opens that constant first and **refuses to serve** if the master key does
not match, rather than failing one secret at a time.

Passwords are hashed with Argon2id. API tokens are stored as SHA-256 hashes and
shown in full exactly once.

### Losing or rotating the master key

There is no recovery. If the key is gone, the data is gone — that is the point of
encrypting it. Keep a copy somewhere separate from the cluster.

Rotating it means re-encrypting: read every secret with the old key, write it
back with the new one. The envelope design means only the wrapped data keys have
to change, but there is no built-in rotation command yet.

## Development

```sh
# Database
docker run -d --name secrets-db -e POSTGRES_PASSWORD=dev \
  -e POSTGRES_USER=secrets -e POSTGRES_DB=secrets -p 5432:5432 postgres:16-alpine

# API
cd backend
DATABASE_URL='postgres://secrets:dev@localhost:5432/secrets?sslmode=disable' \
MASTER_KEY='dev-master-key-at-least-16' \
JWT_SECRET='dev-jwt-secret-at-least-16' \
go run ./cmd/server

# Web UI, proxying /api to the server above
cd frontend && npm install && npm run dev
```

Run the tests. The integration suite needs a database and skips itself without
one:

```sh
cd backend
TEST_DATABASE_URL='postgres://secrets:dev@localhost:5432/secrets?sslmode=disable' \
  go test ./...
```

## Security notes

- Put TLS in front of this. It moves credentials over the wire.
- The audit log records every decryption, sign-in, and permission change.
- A revealed value clears itself from the screen after 30 seconds.
- API responses carrying plaintext are sent with `Cache-Control: no-store`.
- Containers run as a non-root user with a read-only root filesystem.
