-- A secret can be shared with a person directly, not only through a group.
-- Group shares stay in secret_shares; this is the per-user equivalent.
CREATE TABLE IF NOT EXISTS secret_user_shares (
    secret_id UUID        NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    can_write BOOLEAN     NOT NULL DEFAULT FALSE,
    shared_by UUID        REFERENCES users (id) ON DELETE SET NULL,
    shared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (secret_id, user_id)
);

CREATE INDEX IF NOT EXISTS secret_user_shares_user_idx ON secret_user_shares (user_id);
