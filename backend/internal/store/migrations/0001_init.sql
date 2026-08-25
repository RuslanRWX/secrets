-- Core schema for the secrets service.

CREATE TABLE IF NOT EXISTS app_settings (
    id                 SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    initialized        BOOLEAN     NOT NULL DEFAULT FALSE,
    instance_name      TEXT        NOT NULL DEFAULT 'secrets',
    key_id             TEXT        NOT NULL DEFAULT '',
    key_check          BYTEA,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO app_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username             TEXT        NOT NULL UNIQUE,
    email                TEXT,
    display_name         TEXT        NOT NULL DEFAULT '',
    password_hash        TEXT        NOT NULL,
    is_admin             BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN     NOT NULL DEFAULT TRUE,
    permissions          TEXT[]      NOT NULL DEFAULT '{}',
    password_changed_at  TIMESTAMPTZ,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (lower(username));

CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    created_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS groups_name_lower_idx ON groups (lower(name));

-- role: 'member' can read group secrets, 'manager' can also write them and manage membership.
CREATE TABLE IF NOT EXISTS group_members (
    group_id  UUID        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role      TEXT        NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'manager')),
    added_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS group_members_user_idx ON group_members (user_id);

CREATE TABLE IF NOT EXISTS secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    kind        TEXT        NOT NULL DEFAULT 'password' CHECK (kind IN ('password', 'text')),
    username    TEXT        NOT NULL DEFAULT '',
    url         TEXT        NOT NULL DEFAULT '',
    owner_id    UUID        REFERENCES users (id) ON DELETE CASCADE,
    created_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    -- Envelope encryption: value is sealed with a per-secret data key,
    -- the data key itself is sealed with the key-encryption key.
    key_id      TEXT        NOT NULL,
    wrapped_dek BYTEA       NOT NULL,
    ciphertext  BYTEA       NOT NULL,
    version     INTEGER     NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS secrets_owner_idx ON secrets (owner_id);

CREATE TABLE IF NOT EXISTS secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id   UUID        NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    version     INTEGER     NOT NULL,
    key_id      TEXT        NOT NULL,
    wrapped_dek BYTEA       NOT NULL,
    ciphertext  BYTEA       NOT NULL,
    created_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (secret_id, version)
);

CREATE TABLE IF NOT EXISTS secret_shares (
    secret_id UUID        NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    group_id  UUID        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    can_write BOOLEAN     NOT NULL DEFAULT FALSE,
    shared_by UUID        REFERENCES users (id) ON DELETE SET NULL,
    shared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (secret_id, group_id)
);

CREATE INDEX IF NOT EXISTS secret_shares_group_idx ON secret_shares (group_id);

-- An API token is bound either to a user (acts as that user) or to a group
-- (read-only machine access to everything shared with that group).
CREATE TABLE IF NOT EXISTS api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    prefix       TEXT        NOT NULL UNIQUE,
    token_hash   BYTEA       NOT NULL,
    user_id      UUID        REFERENCES users (id) ON DELETE CASCADE,
    group_id     UUID        REFERENCES groups (id) ON DELETE CASCADE,
    scopes       TEXT[]      NOT NULL DEFAULT '{}',
    created_by   UUID        REFERENCES users (id) ON DELETE SET NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((user_id IS NULL) <> (group_id IS NULL))
);

CREATE INDEX IF NOT EXISTS api_tokens_user_idx ON api_tokens (user_id);
CREATE INDEX IF NOT EXISTS api_tokens_group_idx ON api_tokens (group_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    actor_user_id  UUID        REFERENCES users (id) ON DELETE SET NULL,
    actor_token_id UUID        REFERENCES api_tokens (id) ON DELETE SET NULL,
    actor_label    TEXT        NOT NULL DEFAULT '',
    action         TEXT        NOT NULL,
    target_type    TEXT        NOT NULL DEFAULT '',
    target_id      TEXT        NOT NULL DEFAULT '',
    detail         JSONB       NOT NULL DEFAULT '{}',
    ip             TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log (created_at DESC);
