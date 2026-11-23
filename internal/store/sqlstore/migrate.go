package sqlstore

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// advisoryLockID serialises migrations across instances on PostgreSQL.
const advisoryLockID = 7239471001

// Migrate applies every pending migration in order and returns the versions
// it applied. The whole run is one transaction, so a failure leaves the
// schema exactly as it was. Migrations are forward-only: take a backup before
// upgrading.
//
// On PostgreSQL concurrent instances are serialised with a transaction-level
// advisory lock. A session-level lock would not survive a connection pooler
// such as PgBouncer in transaction mode, where consecutive statements may run
// on different server connections; a transaction-level one does.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if s.postgres {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(advisoryLockID)); err != nil {
			return nil, fmt.Errorf("acquire migration lock: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)`); err != nil {
		return nil, err
	}

	done := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		done[v] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var applied []string
	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		if done[version] {
			continue
		}
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		// Migration files contain plain DDL with no semicolons inside statements.
		for _, stmt := range strings.Split(stripSQLComments(string(body)), ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("migration %s: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`),
			version, time.Now().UnixMilli()); err != nil {
			return nil, fmt.Errorf("migration %s: %w", version, err)
		}
		applied = append(applied, version)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return applied, nil
}

func stripSQLComments(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
