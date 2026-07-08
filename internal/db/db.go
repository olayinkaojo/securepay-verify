// Package db handles libSQL (Turso) storage of user verification history.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	user_id      TEXT PRIMARY KEY,
	last_country TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS devices (
	user_id     TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS transactions (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id            TEXT NOT NULL,
	ip_address         TEXT NOT NULL,
	country            TEXT NOT NULL,
	device_fingerprint TEXT NOT NULL,
	amount             REAL NOT NULL,
	created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions (user_id);

CREATE TABLE IF NOT EXISTS flagged_transactions (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id            TEXT NOT NULL,
	ip_address         TEXT NOT NULL,
	country            TEXT NOT NULL,
	device_fingerprint TEXT NOT NULL,
	amount             REAL NOT NULL,
	recommendation     TEXT NOT NULL,
	flags              TEXT NOT NULL,
	created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_flagged_transactions_user ON flagged_transactions (user_id);
`

// Store wraps the SQLite connection.
type Store struct {
	db *sql.DB
}

// Open connects to a Turso (libSQL) database and applies the schema.
// dbURL is the database URL (libsql://<db>-<org>.turso.io) and authToken a
// token with write access; the token is appended as a query parameter per
// the libsql-client-go connection format.
func Open(dbURL, authToken string) (*Store, error) {
	dsn := dbURL
	if authToken != "" {
		dsn += "?authToken=" + authToken
	}
	return open("libsql", dsn)
}

// OpenLocal opens a local database file through any registered
// database/sql driver speaking the same SQL dialect. It exists for tests,
// which register modernc.org/sqlite themselves and pass driverName "sqlite"
// so `go test ./...` runs offline without Turso credentials. Production
// code uses Open.
func OpenLocal(driverName, path string) (*Store, error) {
	store, err := open(driverName, path)
	if err != nil {
		return nil, err
	}
	// Local SQLite drivers serialize access per connection; a single
	// connection avoids SQLITE_BUSY under concurrent writes.
	store.db.SetMaxOpenConns(1)
	return store, nil
}

const (
	schemaAttempts      = 4
	schemaRetryBaseWait = 200 * time.Millisecond
)

func open(driverName, dsn string) (*Store, error) {
	conn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := applySchema(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Store{db: conn}, nil
}

// applySchema runs the schema with exponential backoff (200ms, 400ms,
// 800ms between attempts). The first request to a remote Turso database can
// fail transiently — e.g. a TLS handshake timeout — and a single blip
// shouldn't kill the server at boot. Only this startup step retries;
// regular queries afterwards do not.
func applySchema(conn *sql.DB) error {
	var err error
	wait := schemaRetryBaseWait
	for attempt := 1; attempt <= schemaAttempts; attempt++ {
		if _, err = conn.Exec(schema); err == nil {
			return nil
		}
		if attempt < schemaAttempts {
			log.Printf("db: apply schema attempt %d/%d failed, retrying in %v: %v",
				attempt, schemaAttempts, wait, err)
			time.Sleep(wait)
			wait *= 2
		}
	}
	return fmt.Errorf("apply schema: giving up after %d attempts: %w", schemaAttempts, err)
}

// Close closes the underlying connection.
func (s *Store) Close() error {
	return s.db.Close()
}
