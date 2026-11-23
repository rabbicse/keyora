package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/rabbicse/keyora/internal/server"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/sqlstore"
	"github.com/rabbicse/keyora/internal/store/storetest"
)

// TestSQLiteConformance runs the storage suite against a real SQLite file.
func TestSQLiteConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		dsn := "file:" + filepath.Join(t.TempDir(), "keyora.db") +
			"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return migrated(t, db, sqlstore.DialectSQLite)
	})
}

var schemaSeq atomic.Int64

// TestPostgresConformance runs the same suite against PostgreSQL when
// KEYORA_TEST_POSTGRES_DSN is set; each subtest gets its own schema.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("KEYORA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set KEYORA_TEST_POSTGRES_DSN to run PostgreSQL tests")
	}
	storetest.Run(t, func(t *testing.T) store.Store {
		admin, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("keyora_test_%d_%d", os.Getpid(), schemaSeq.Add(1))
		if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
			t.Fatal(err)
		}
		sep := "?"
		if contains(dsn, "?") {
			sep = "&"
		}
		db, err := sql.Open("pgx", dsn+sep+"search_path="+schema)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			db.Close()
			admin.Exec("DROP SCHEMA " + schema + " CASCADE")
			admin.Close()
		})
		return migrated(t, db, sqlstore.DialectPostgres)
	})
}

func migrated(t *testing.T, db *sql.DB, dialect string) store.Store {
	t.Helper()
	st, err := sqlstore.New(db, dialect)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := st.Migrate(context.Background())
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("no migrations were applied to an empty database")
	}
	again, err := st.Migrate(context.Background())
	if err != nil || len(again) != 0 {
		t.Fatalf("migrations are not idempotent: applied=%v err=%v", again, err)
	}
	return st
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestPgBouncerConformance runs the storage suite through PgBouncer in
// transaction pooling mode when KEYORA_TEST_PGBOUNCER_DSN is set. In that mode
// consecutive statements may land on different server connections, so this
// proves the store needs no session state: no named prepared statements, no
// session advisory locks, no SET.
func TestPgBouncerConformance(t *testing.T) {
	dsn := os.Getenv("KEYORA_TEST_PGBOUNCER_DSN")
	if dsn == "" {
		t.Skip("set KEYORA_TEST_PGBOUNCER_DSN to run PgBouncer tests")
	}
	db, err := sql.Open("pgx", server.PgBouncerDSN(dsn))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(20) // more client connections than the pooler has server connections
	st, err := sqlstore.New(db, sqlstore.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	// Several instances migrating at once must not collide.
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { _, err := st.Migrate(context.Background()); errs <- err }()
	}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent migration through the pooler: %v", err)
		}
	}
	storetest.Run(t, func(t *testing.T) store.Store {
		// One shared schema: empty it between subtests (cascades to every table).
		if _, err := db.Exec("TRUNCATE tenants CASCADE"); err != nil {
			t.Fatal(err)
		}
		return noClose{st}
	})
}

// noClose keeps the shared pool open across subtests.
type noClose struct{ store.Store }

func (noClose) Close() error { return nil }
