package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

const userColumns = `id, username, COALESCE(email, ''), display_name, password_hash,
	is_admin, is_active, must_change_password, permissions, last_login_at, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash,
		&u.IsAdmin, &u.IsActive, &u.MustChangePassword, &u.Permissions,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, normalize(err)
	}

	return &u, nil
}

// CreateUser inserts a user. Usernames are compared case-insensitively.
func (s *Store) CreateUser(ctx context.Context, u *User) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, is_admin,
		                    is_active, must_change_password, permissions)
		 VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8)
		 RETURNING `+userColumns,
		strings.TrimSpace(u.Username), u.Email, u.DisplayName, u.PasswordHash,
		u.IsAdmin, u.IsActive, u.MustChangePassword, u.Permissions)

	return scanUser(row)
}

// UserByUsername looks up a user for login.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1)`, username)

	return scanUser(row)
}

// UserByID fetches one user.
func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)

	return scanUser(row)
}

// ListUsers returns every account, newest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}

	return users, rows.Err()
}

// CountUsers reports how many accounts exist, used to gate first-run setup.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)

	return n, err
}

// UserUpdate carries the mutable fields of a user; nil means "leave unchanged".
type UserUpdate struct {
	Email       *string
	DisplayName *string
	IsAdmin     *bool
	IsActive    *bool
	Permissions *[]string
}

// UpdateUser applies a partial update.
func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, up UserUpdate) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE users SET
		    email                = COALESCE(NULLIF($2, ''), email),
		    display_name         = COALESCE($3, display_name),
		    is_admin             = COALESCE($4, is_admin),
		    is_active            = COALESCE($5, is_active),
		    permissions          = COALESCE($6, permissions),
		    updated_at           = now()
		  WHERE id = $1
		  RETURNING `+userColumns,
		id, derefString(up.Email), up.DisplayName, up.IsAdmin, up.IsActive, up.Permissions)

	return scanUser(row)
}

// SetPassword replaces a user's password hash and clears or sets the forced-change flag.
func (s *Store) SetPassword(ctx context.Context, id uuid.UUID, hash string, mustChange bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users
		    SET password_hash = $2, must_change_password = $3,
		        password_changed_at = now(), updated_at = now()
		  WHERE id = $1`,
		id, hash, mustChange)

	return err
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, id, time.Now())

	return err
}

// DeleteUser removes an account and, by cascade, the secrets it owns.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// CountAdmins reports how many active admins remain, so the last one cannot be removed.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE is_admin AND is_active`).Scan(&n)

	return n, err
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}

	return *p
}
