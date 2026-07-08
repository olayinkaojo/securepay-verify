// Package db handles SQLite storage of user verification history.
package db

import (
	"database/sql"

	_ "modernc.org/sqlite"
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
`

// Store wraps the SQLite connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// modernc.org/sqlite serializes access per connection; a single connection
	// avoids SQLITE_BUSY under concurrent writes.
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, err
	}
	return &Store{db: conn}, nil
}

// Close closes the underlying connection.
func (s *Store) Close() error {
	return s.db.Close()
}
