package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// AuditRecord is a single entry to append to the audit log.
type AuditRecord struct {
	ActorUserID  *uuid.UUID
	ActorTokenID *uuid.UUID
	ActorLabel   string
	Action       string
	TargetType   string
	TargetID     string
	Detail       map[string]any
	IP           string
}

// AppendAudit writes an audit entry.
func (s *Store) AppendAudit(ctx context.Context, r AuditRecord) error {
	detail := []byte("{}")
	if len(r.Detail) > 0 {
		encoded, err := json.Marshal(r.Detail)
		if err != nil {
			return err
		}
		detail = encoded
	}

	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (actor_user_id, actor_token_id, actor_label, action,
		                        target_type, target_id, detail, ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.ActorUserID, r.ActorTokenID, r.ActorLabel, r.Action,
		r.TargetType, r.TargetID, detail, r.IP)

	return err
}

// ListAudit returns the most recent entries, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, actor_label, action, target_type, target_id, detail, ip, created_at
		   FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.ActorLabel, &e.Action, &e.TargetType, &e.TargetID,
			&detail, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(detail, &e.Detail); err != nil {
			e.Detail = map[string]any{}
		}
		out = append(out, e)
	}

	return out, rows.Err()
}
