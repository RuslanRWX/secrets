package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// CreateGroup inserts a group.
func (s *Store) CreateGroup(ctx context.Context, name, description string, createdBy uuid.UUID) (*Group, error) {
	var g Group
	err := s.pool.QueryRow(ctx,
		`INSERT INTO groups (name, description, created_by)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, description, created_by, created_at`,
		strings.TrimSpace(name), description, createdBy,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedBy, &g.CreatedAt)
	if err != nil {
		return nil, normalize(err)
	}

	return &g, nil
}

// ListGroups returns groups with membership and share counts. When onlyForUser is
// set, the result is limited to groups that user belongs to.
func (s *Store) ListGroups(ctx context.Context, onlyForUser *uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT g.id, g.name, g.description, g.created_by, g.created_at,
		        (SELECT count(*) FROM group_members m WHERE m.group_id = g.id),
		        (SELECT count(*) FROM secret_shares sh WHERE sh.group_id = g.id)
		   FROM groups g
		  WHERE $1::uuid IS NULL
		     OR EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = g.id AND m.user_id = $1)
		  ORDER BY g.name`, onlyForUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedBy, &g.CreatedAt,
			&g.MemberCount, &g.SecretCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, rows.Err()
}

// GroupByID returns a group with its members attached.
func (s *Store) GroupByID(ctx context.Context, id uuid.UUID) (*Group, error) {
	var g Group
	err := s.pool.QueryRow(ctx,
		`SELECT g.id, g.name, g.description, g.created_by, g.created_at,
		        (SELECT count(*) FROM group_members m WHERE m.group_id = g.id),
		        (SELECT count(*) FROM secret_shares sh WHERE sh.group_id = g.id)
		   FROM groups g WHERE g.id = $1`, id,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedBy, &g.CreatedAt, &g.MemberCount, &g.SecretCount)
	if err != nil {
		return nil, normalize(err)
	}

	members, err := s.GroupMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	g.Members = members

	return &g, nil
}

// GroupMembers lists the users in a group.
func (s *Store) GroupMembers(ctx context.Context, groupID uuid.UUID) ([]GroupMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id, u.username, u.display_name, m.role, m.added_at
		   FROM group_members m
		   JOIN users u ON u.id = m.user_id
		  WHERE m.group_id = $1
		  ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := []GroupMember{}
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName, &m.Role, &m.AddedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, rows.Err()
}

// UpdateGroup renames a group or changes its description.
func (s *Store) UpdateGroup(ctx context.Context, id uuid.UUID, name, description *string) (*Group, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE groups SET name = COALESCE($2, name), description = COALESCE($3, description),
		        updated_at = now()
		  WHERE id = $1`, id, name, description)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	return s.GroupByID(ctx, id)
}

// DeleteGroup removes a group and all of its shares.
func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// AddGroupMember adds or re-roles a member.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID uuid.UUID, role string, addedBy *uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO group_members (group_id, user_id, role, added_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (group_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		groupID, userID, role, addedBy)

	return err
}

// RemoveGroupMember drops a membership.
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// GroupRole returns the user's role in a group, or "" when not a member.
func (s *Store) GroupRole(ctx context.Context, groupID, userID uuid.UUID) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx,
		`SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2`,
		groupID, userID).Scan(&role)
	if err != nil {
		if normalize(err) == ErrNotFound {
			return "", nil
		}

		return "", err
	}

	return role, nil
}
