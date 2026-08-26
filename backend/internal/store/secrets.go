package store

import (
	"context"

	"github.com/google/uuid"
)

// Actor identifies who is asking for a secret. Exactly one of UserID or GroupID
// is set: a session or user token acts as a user, a group token acts as a group.
type Actor struct {
	UserID  *uuid.UUID
	GroupID *uuid.UUID
	IsAdmin bool
}

// accessClause matches any secret the actor may read. It is written against the
// alias `s` and takes the actor as parameters $1 (admin), $2 (user), $3 (group).
const accessClause = `(
	$1::boolean
	OR ($2::uuid IS NOT NULL AND (
	        s.owner_id = $2::uuid
	     OR EXISTS (SELECT 1 FROM secret_user_shares us
	                 WHERE us.secret_id = s.id AND us.user_id = $2::uuid)
	     OR EXISTS (SELECT 1 FROM secret_shares sh
	                  JOIN group_members m ON m.group_id = sh.group_id
	                 WHERE sh.secret_id = s.id AND m.user_id = $2::uuid)))
	OR ($3::uuid IS NOT NULL AND EXISTS (
	        SELECT 1 FROM secret_shares sh
	         WHERE sh.secret_id = s.id AND sh.group_id = $3::uuid))
)`

// writeClause is the subset of accessClause that also permits modification.
const writeClause = `(
	$1::boolean
	OR ($2::uuid IS NOT NULL AND (
	        s.owner_id = $2::uuid
	     OR EXISTS (SELECT 1 FROM secret_user_shares us
	                 WHERE us.secret_id = s.id AND us.user_id = $2::uuid AND us.can_write)
	     OR EXISTS (SELECT 1 FROM secret_shares sh
	                  JOIN group_members m ON m.group_id = sh.group_id
	                 WHERE sh.secret_id = s.id AND m.user_id = $2::uuid AND sh.can_write)))
	OR ($3::uuid IS NOT NULL AND EXISTS (
	        SELECT 1 FROM secret_shares sh
	         WHERE sh.secret_id = s.id AND sh.group_id = $3::uuid AND sh.can_write))
)`

const secretColumns = `s.id, s.name, s.description, s.kind, s.username, s.url,
	s.owner_id, COALESCE(o.username, ''), s.created_by, s.version, s.created_at, s.updated_at`

// NewSecret carries everything needed to store a secret's first version.
type NewSecret struct {
	Name        string
	Description string
	Kind        string
	Username    string
	URL         string
	OwnerID     uuid.UUID
	CreatedBy   uuid.UUID
	KeyID       string
	WrappedDEK  []byte
	Ciphertext  []byte
}

// CreateSecret inserts a secret together with its first version row.
func (s *Store) CreateSecret(ctx context.Context, in NewSecret) (*Secret, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO secrets (name, description, kind, username, url, owner_id, created_by,
		                      key_id, wrapped_dek, ciphertext)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id`,
		in.Name, in.Description, in.Kind, in.Username, in.URL, in.OwnerID, in.CreatedBy,
		in.KeyID, in.WrappedDEK, in.Ciphertext).Scan(&id)
	if err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_versions (secret_id, version, key_id, wrapped_dek, ciphertext, created_by)
		 VALUES ($1, 1, $2, $3, $4, $5)`,
		id, in.KeyID, in.WrappedDEK, in.Ciphertext, in.CreatedBy); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return s.SecretByID(ctx, id, Actor{IsAdmin: true})
}

// ListSecrets returns the metadata of every secret the actor can read.
func (s *Store) ListSecrets(ctx context.Context, a Actor) ([]Secret, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+secretColumns+`, `+writeClause+` AS can_write
		   FROM secrets s
		   LEFT JOIN users o ON o.id = s.owner_id
		  WHERE `+accessClause+`
		  ORDER BY s.name`,
		a.IsAdmin, a.UserID, a.GroupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Secret{}
	ids := []uuid.UUID{}
	for rows.Next() {
		var sec Secret
		if err := rows.Scan(&sec.ID, &sec.Name, &sec.Description, &sec.Kind, &sec.Username,
			&sec.URL, &sec.OwnerID, &sec.OwnerName, &sec.CreatedBy, &sec.Version,
			&sec.CreatedAt, &sec.UpdatedAt, &sec.CanWrite); err != nil {
			return nil, err
		}
		out = append(out, sec)
		ids = append(ids, sec.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	shares, err := s.sharesFor(ctx, ids)
	if err != nil {
		return nil, err
	}

	userShares, err := s.userSharesFor(ctx, ids)
	if err != nil {
		return nil, err
	}

	for i := range out {
		out[i].Shares = shares[out[i].ID]
		out[i].UserShares = userShares[out[i].ID]
	}

	return out, nil
}

// SecretByID returns one secret's metadata if the actor may read it.
func (s *Store) SecretByID(ctx context.Context, id uuid.UUID, a Actor) (*Secret, error) {
	var sec Secret
	err := s.pool.QueryRow(ctx,
		`SELECT `+secretColumns+`, `+writeClause+` AS can_write
		   FROM secrets s
		   LEFT JOIN users o ON o.id = s.owner_id
		  WHERE s.id = $4 AND `+accessClause,
		a.IsAdmin, a.UserID, a.GroupID, id,
	).Scan(&sec.ID, &sec.Name, &sec.Description, &sec.Kind, &sec.Username, &sec.URL,
		&sec.OwnerID, &sec.OwnerName, &sec.CreatedBy, &sec.Version, &sec.CreatedAt,
		&sec.UpdatedAt, &sec.CanWrite)
	if err != nil {
		return nil, normalize(err)
	}

	shares, err := s.sharesFor(ctx, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	sec.Shares = shares[id]

	userShares, err := s.userSharesFor(ctx, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	sec.UserShares = userShares[id]

	return &sec, nil
}

// SecretCipher returns the sealed value if the actor may read it.
func (s *Store) SecretCipher(ctx context.Context, id uuid.UUID, a Actor) (wrappedDEK, ciphertext []byte, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT s.wrapped_dek, s.ciphertext FROM secrets s WHERE s.id = $4 AND `+accessClause,
		a.IsAdmin, a.UserID, a.GroupID, id).Scan(&wrappedDEK, &ciphertext)
	if err != nil {
		return nil, nil, normalize(err)
	}

	return wrappedDEK, ciphertext, nil
}

// SecretMetaUpdate carries the mutable non-secret fields.
type SecretMetaUpdate struct {
	Name        *string
	Description *string
	Username    *string
	URL         *string
}

// UpdateSecretMeta changes labels without touching the sealed value.
func (s *Store) UpdateSecretMeta(ctx context.Context, id uuid.UUID, a Actor, up SecretMetaUpdate) (*Secret, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets s SET
		     name        = COALESCE($5, s.name),
		     description = COALESCE($6, s.description),
		     username    = COALESCE($7, s.username),
		     url         = COALESCE($8, s.url),
		     updated_at  = now()
		  WHERE s.id = $4 AND `+writeClause,
		a.IsAdmin, a.UserID, a.GroupID, id, up.Name, up.Description, up.Username, up.URL)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	return s.SecretByID(ctx, id, a)
}

// RotateValue stores a new sealed value and archives the previous one.
func (s *Store) RotateValue(ctx context.Context, id uuid.UUID, a Actor,
	keyID string, wrappedDEK, ciphertext []byte, actorID *uuid.UUID,
) (*Secret, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var version int
	err = tx.QueryRow(ctx,
		`UPDATE secrets s SET key_id = $5, wrapped_dek = $6, ciphertext = $7,
		        version = s.version + 1, updated_at = now()
		  WHERE s.id = $4 AND `+writeClause+`
		  RETURNING s.version`,
		a.IsAdmin, a.UserID, a.GroupID, id, keyID, wrappedDEK, ciphertext).Scan(&version)
	if err != nil {
		return nil, normalize(err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_versions (secret_id, version, key_id, wrapped_dek, ciphertext, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, version, keyID, wrappedDEK, ciphertext, actorID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return s.SecretByID(ctx, id, a)
}

// DeleteSecret removes a secret the actor may write.
func (s *Store) DeleteSecret(ctx context.Context, id uuid.UUID, a Actor) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM secrets s WHERE s.id = $4 AND `+writeClause,
		a.IsAdmin, a.UserID, a.GroupID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// SecretVersions lists the value history of a secret.
func (s *Store) SecretVersions(ctx context.Context, id uuid.UUID) ([]SecretVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, version, created_by, created_at
		   FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SecretVersion{}
	for rows.Next() {
		var v SecretVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}

	return out, rows.Err()
}

// IsSecretOwner reports whether the user owns the secret, which is what sharing requires.
func (s *Store) IsSecretOwner(ctx context.Context, id, userID uuid.UUID) (bool, error) {
	var owned bool
	err := s.pool.QueryRow(ctx,
		`SELECT owner_id = $2 FROM secrets WHERE id = $1`, id, userID).Scan(&owned)
	if err != nil {
		return false, normalize(err)
	}

	return owned, nil
}

// SecretOwner returns the owner of a secret, or nil when it has none.
func (s *Store) SecretOwner(ctx context.Context, id uuid.UUID) (*uuid.UUID, error) {
	var owner *uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT owner_id FROM secrets WHERE id = $1`, id).Scan(&owner); err != nil {
		return nil, normalize(err)
	}

	return owner, nil
}

// ShareSecret grants a group access to a secret.
func (s *Store) ShareSecret(ctx context.Context, secretID, groupID uuid.UUID, canWrite bool, by uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO secret_shares (secret_id, group_id, can_write, shared_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (secret_id, group_id) DO UPDATE SET can_write = EXCLUDED.can_write`,
		secretID, groupID, canWrite, by)

	return err
}

// ShareSecretWithUser grants one person access to a secret.
func (s *Store) ShareSecretWithUser(ctx context.Context, secretID, userID uuid.UUID, canWrite bool, by uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO secret_user_shares (secret_id, user_id, can_write, shared_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (secret_id, user_id) DO UPDATE SET can_write = EXCLUDED.can_write`,
		secretID, userID, canWrite, by)

	return err
}

// UnshareSecretFromUser revokes one person's access.
func (s *Store) UnshareSecretFromUser(ctx context.Context, secretID, userID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM secret_user_shares WHERE secret_id = $1 AND user_id = $2`, secretID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// userSharesFor loads the direct shares of many secrets in one round trip.
func (s *Store) userSharesFor(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]SecretUserShare, error) {
	out := map[uuid.UUID][]SecretUserShare{}
	if len(ids) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx,
		`SELECT us.secret_id, us.user_id, u.username, u.display_name, us.can_write, us.shared_at
		   FROM secret_user_shares us
		   JOIN users u ON u.id = us.user_id
		  WHERE us.secret_id = ANY($1)
		  ORDER BY u.username`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var secretID uuid.UUID
		var sh SecretUserShare
		if err := rows.Scan(&secretID, &sh.UserID, &sh.Username, &sh.DisplayName,
			&sh.CanWrite, &sh.SharedAt); err != nil {
			return nil, err
		}
		out[secretID] = append(out[secretID], sh)
	}

	return out, rows.Err()
}

// UnshareSecret revokes a group's access.
func (s *Store) UnshareSecret(ctx context.Context, secretID, groupID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM secret_shares WHERE secret_id = $1 AND group_id = $2`, secretID, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// sharesFor loads the group shares of many secrets in one round trip.
func (s *Store) sharesFor(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]SecretShare, error) {
	out := map[uuid.UUID][]SecretShare{}
	if len(ids) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx,
		`SELECT sh.secret_id, sh.group_id, g.name, sh.can_write, sh.shared_at
		   FROM secret_shares sh
		   JOIN groups g ON g.id = sh.group_id
		  WHERE sh.secret_id = ANY($1)
		  ORDER BY g.name`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var secretID uuid.UUID
		var sh SecretShare
		if err := rows.Scan(&secretID, &sh.GroupID, &sh.GroupName, &sh.CanWrite, &sh.SharedAt); err != nil {
			return nil, err
		}
		out[secretID] = append(out[secretID], sh)
	}

	return out, rows.Err()
}
