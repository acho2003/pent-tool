// Package recordstore is a PROTOTYPE Postgres-backed document store for the
// application's structured records (scans, credentials, schedules, saved
// instances). It is gated behind XALGORIX_STORE=postgres and is NOT wired into
// the default file-based persistence. Large scanner artifacts and reports stay
// as files on the data volume; only records live here.
//
// The model is deliberately simple: one table keyed by (collection, id) holding
// either a JSON document (data) or opaque bytes (bytes, e.g. an encrypted
// credential blob). It is enough to prove the migration path without rewriting
// every directory-walk reader in the app.
package recordstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a (collection, id) is absent.
var ErrNotFound = errors.New("record not found")

// Store is a Postgres-backed record store.
type Store struct {
	pool *pgxpool.Pool
}

// Enabled reports whether the prototype Postgres store is selected.
func Enabled() bool {
	return os.Getenv("XALGORIX_STORE") == "postgres"
}

// DSN returns the configured connection string, defaulting to the prototype
// container's local mapping so a developer run needs no extra configuration.
func DSN() string {
	if dsn := os.Getenv("XALGORIX_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://postgres:proto@127.0.0.1:55432/xalgorix?sslmode=disable"
}

// Open connects to Postgres and ensures the schema exists.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) migrate(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS records (
    collection text        NOT NULL,
    id         text        NOT NULL,
    data       jsonb,
    bytes      bytea,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS records_collection_idx ON records (collection);`
	_, err := s.pool.Exec(ctx, ddl)
	if err != nil {
		return fmt.Errorf("migrate records table: %w", err)
	}
	return nil
}

// PutJSON upserts a JSON document.
func (s *Store) PutJSON(ctx context.Context, collection, id string, data []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO records (collection, id, data, updated_at) VALUES ($1,$2,$3,now())
         ON CONFLICT (collection, id) DO UPDATE SET data = EXCLUDED.data, bytes = NULL, updated_at = now()`,
		collection, id, data)
	return err
}

// PutBytes upserts an opaque byte blob (e.g. an encrypted credential).
func (s *Store) PutBytes(ctx context.Context, collection, id string, blob []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO records (collection, id, bytes, updated_at) VALUES ($1,$2,$3,now())
         ON CONFLICT (collection, id) DO UPDATE SET bytes = EXCLUDED.bytes, data = NULL, updated_at = now()`,
		collection, id, blob)
	return err
}

// GetJSON returns a JSON document, or ErrNotFound.
func (s *Store) GetJSON(ctx context.Context, collection, id string) ([]byte, error) {
	var data []byte
	err := s.pool.QueryRow(ctx, `SELECT data FROM records WHERE collection=$1 AND id=$2`, collection, id).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && data == nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetBytes returns an opaque byte blob, or ErrNotFound.
func (s *Store) GetBytes(ctx context.Context, collection, id string) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx, `SELECT bytes FROM records WHERE collection=$1 AND id=$2`, collection, id).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && blob == nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// ListIDs returns the ids in a collection, sorted.
func (s *Store) ListIDs(ctx context.Context, collection string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM records WHERE collection=$1 ORDER BY id`, collection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListJSON returns every JSON document in a collection, newest first.
func (s *Store) ListJSON(ctx context.Context, collection string) ([][]byte, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM records WHERE collection=$1 AND data IS NOT NULL ORDER BY updated_at DESC`, collection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, rows.Err()
}

// Delete removes a record. Absent ids are not an error.
func (s *Store) Delete(ctx context.Context, collection, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM records WHERE collection=$1 AND id=$2`, collection, id)
	return err
}

// Count returns the number of records in a collection.
func (s *Store) Count(ctx context.Context, collection string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM records WHERE collection=$1`, collection).Scan(&n)
	return n, err
}

// Ping verifies connectivity.
func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.pool.Ping(ctx)
}
