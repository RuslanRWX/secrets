// Package store owns the PostgreSQL connection pool and all queries.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:migrations
var migrationFS embed.FS

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store is the database handle shared by the API handlers.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// Open connects to PostgreSQL, retrying briefly so the service can start
// alongside its database in Docker Compose or Kubernetes.
func Open(ctx context.Context, dsn string, log *slog.Logger) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		if err = pool.Ping(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			pool.Close()

			return nil, fmt.Errorf("database unreachable: %w", err)
		}
		log.Info("waiting for database", "error", err)
		select {
		case <-ctx.Done():
			pool.Close()

			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return &Store{pool: pool, log: log}, nil
}

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database liveness for the readiness probe.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// migrationLockID identifies the advisory lock that serializes migrations.
// Replicas start together, so without it they race on the same DDL.
const migrationLockID int64 = 0x5EC2E75

// Migrate applies every embedded migration that has not run yet. It holds a
// PostgreSQL advisory lock for the duration, so it is safe to run from every
// replica at once: the first one migrates and the rest wait, then find nothing
// left to do.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx),
			`SELECT pg_advisory_unlock($1)`, migrationLockID); err != nil {
			s.log.Warn("release migration lock", "error", err)
		}
	}()

	_, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}

		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}

		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf("apply migration %s: %w", name, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf("record migration %s: %w", name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}

		s.log.Info("applied migration", "name", name)
	}

	return nil
}

// normalize maps pgx's no-rows sentinel onto the package error.
func normalize(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	return err
}
