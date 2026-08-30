package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const tokenColumns = `t.id, t.name, t.prefix, t.user_id, COALESCE(u.username, ''),
	t.group_id, COALESCE(g.name, ''), t.scopes, t.expires_at, t.last_used_at,
	t.revoked_at, t.created_at, t.created_by, COALESCE(c.username, '')`

const tokenFrom = ` FROM api_tokens t
	LEFT JOIN users u ON u.id = t.user_id
	LEFT JOIN groups g ON g.id = t.group_id
	LEFT JOIN users c ON c.id = t.created_by`

func scanToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.UserID, &t.Username, &t.GroupID,
		&t.GroupName, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt,
		&t.CreatedBy, &t.CreatedByName)
	if err != nil {
		return nil, normalize(err)
	}

	return &t, nil
}

// NewToken describes a token about to be issued.
type NewToken struct {
	Name      string
	Prefix    string
	Hash      []byte
	UserID    *uuid.UUID
	GroupID   *uuid.UUID
	Scopes    []string
	ExpiresAt *time.Time
	CreatedBy uuid.UUID
}

// CreateToken stores the hash of a freshly minted token.
func (s *Store) CreateToken(ctx context.Context, in NewToken) (*APIToken, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO api_tokens (name, prefix, token_hash, user_id, group_id, scopes, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		in.Name, in.Prefix, in.Hash, in.UserID, in.GroupID, in.Scopes, in.ExpiresAt, in.CreatedBy).Scan(&id)
	if err != nil {
		return nil, err
	}

	return s.TokenByID(ctx, id)
}

// TokenByID fetches one token's metadata.
func (s *Store) TokenByID(ctx context.Context, id uuid.UUID) (*APIToken, error) {
	return scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenColumns+tokenFrom+` WHERE t.id = $1`, id))
}

// TokenByPrefix finds a token by its public prefix, along with the stored hash.
func (s *Store) TokenByPrefix(ctx context.Context, prefix string) (*APIToken, []byte, error) {
	var t APIToken
	var hash []byte
	err := s.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+`, t.token_hash`+tokenFrom+` WHERE t.prefix = $1`, prefix,
	).Scan(&t.ID, &t.Name, &t.Prefix, &t.UserID, &t.Username, &t.GroupID, &t.GroupName,
		&t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt,
		&t.CreatedBy, &t.CreatedByName, &hash)
	if err != nil {
		return nil, nil, normalize(err)
	}

	return &t, hash, nil
}

// ListTokens returns tokens; a non-nil forUser limits the result to that user's own tokens.
func (s *Store) ListTokens(ctx context.Context, forUser *uuid.UUID) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+tokenColumns+tokenFrom+`
		  WHERE $1::uuid IS NULL
		     OR t.user_id = $1::uuid
		     OR t.created_by = $1::uuid
		     OR t.group_id IN (SELECT group_id FROM group_members
		                        WHERE user_id = $1::uuid AND role = 'manager')
		     OR t.group_id IN (SELECT id FROM groups WHERE created_by = $1::uuid)
		  ORDER BY t.created_at DESC`, forUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}

	return out, rows.Err()
}

// RevokeToken marks a token unusable. It stays in the table so audit entries keep their reference.
func (s *Store) RevokeToken(ctx context.Context, id uuid.UUID, forUser *uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = now()
		  WHERE id = $1 AND revoked_at IS NULL
		    AND ($2::uuid IS NULL
		      OR user_id = $2::uuid
		      OR created_by = $2::uuid
		      OR group_id IN (SELECT group_id FROM group_members
		                       WHERE user_id = $2::uuid AND role = 'manager')
		      OR group_id IN (SELECT id FROM groups WHERE created_by = $2::uuid))`,
		id, forUser)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// TouchToken records that a token was just used.
func (s *Store) TouchToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)

	return err
}
