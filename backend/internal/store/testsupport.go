package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The helpers in this file exist so integration tests can inspect and shape
// database state that the API deliberately does not expose.

// Reset empties every table, returning the database to a pre-install state.
func (s *Store) Reset(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`TRUNCATE audit_log, api_tokens, secret_shares, secret_versions, secrets,
		          group_members, groups, users RESTART IDENTITY CASCADE;
		 UPDATE app_settings
		    SET initialized = FALSE, instance_name = 'secrets', key_id = '', key_check = NULL
		  WHERE id = 1;`)

	return err
}

// RawCiphertext returns the bytes stored for a secret, so a test can confirm
// that no plaintext reached the table.
func (s *Store) RawCiphertext(ctx context.Context, id string) ([]byte, error) {
	secretID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte
	err = s.pool.QueryRow(ctx, `SELECT ciphertext FROM secrets WHERE id = $1`, secretID).Scan(&ciphertext)
	if err != nil {
		return nil, normalize(err)
	}

	return ciphertext, nil
}

// ForceExpireToken backdates a token's expiry so expiry handling can be tested
// without waiting.
func (s *Store) ForceExpireToken(ctx context.Context, id string, at time.Time) error {
	tokenID, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx, `UPDATE api_tokens SET expires_at = $2 WHERE id = $1`, tokenID, at)

	return err
}

// DropSchema removes every object this application owns, so a test can exercise
// a first install against a genuinely empty database.
func (s *Store) DropSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)

	return err
}

// AppliedMigrations reports how many migrations are recorded.
func (s *Store) AppliedMigrations(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n)

	return n, err
}
