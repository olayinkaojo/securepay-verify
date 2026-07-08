package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// UserHistory is the historical baseline used by the rules engine.
type UserHistory struct {
	Known         bool    // user has been seen before
	LastCountry   string  // last known country, "" if unknown
	KnownDevice   bool    // the presented fingerprint has been seen for this user
	AvgAmount     float64 // average historical transaction amount
	HasTxnHistory bool    // user has at least one recorded transaction
}

// GetUserHistory loads everything the rules engine needs about a user in one call.
func (s *Store) GetUserHistory(userID, fingerprint string) (UserHistory, error) {
	var h UserHistory

	err := s.db.QueryRow(`SELECT last_country FROM users WHERE user_id = ?`, userID).
		Scan(&h.LastCountry)
	switch {
	case err == sql.ErrNoRows:
		return h, nil // unknown user: everything zero-valued
	case err != nil:
		return h, err
	}
	h.Known = true

	err = s.db.QueryRow(
		`SELECT COUNT(*) > 0 FROM devices WHERE user_id = ? AND fingerprint = ?`,
		userID, fingerprint,
	).Scan(&h.KnownDevice)
	if err != nil {
		return h, err
	}

	var avg sql.NullFloat64
	err = s.db.QueryRow(`SELECT AVG(amount) FROM transactions WHERE user_id = ?`, userID).
		Scan(&avg)
	if err != nil {
		return h, err
	}
	h.AvgAmount = avg.Float64
	h.HasTxnHistory = avg.Valid

	return h, nil
}

// RecordTransaction persists a verified transaction and updates the user's
// device list and last known country so future verifications compare against it.
// An empty country leaves the user's last known country unchanged.
func (s *Store) RecordTransaction(userID, ipAddress, country, fingerprint string, amount float64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO users (user_id, last_country) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		   last_country = CASE WHEN excluded.last_country != '' THEN excluded.last_country ELSE last_country END`,
		userID, country,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO devices (user_id, fingerprint) VALUES (?, ?)`,
		userID, fingerprint,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		`INSERT INTO transactions (user_id, ip_address, country, device_fingerprint, amount)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, ipAddress, country, fingerprint, amount,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// FlaggedTransaction is a review/block verification kept for audit and
// investigation. It never feeds the rules engine's baseline.
type FlaggedTransaction struct {
	UserID            string    `json:"user_id"`
	IPAddress         string    `json:"ip_address"`
	Country           string    `json:"country"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	Amount            float64   `json:"amount"`
	Recommendation    string    `json:"recommendation"`
	Flags             []string  `json:"flags"`
	CreatedAt         time.Time `json:"created_at"`
}

// RecordFlaggedTransaction persists a review/block verification into
// flagged_transactions only. It deliberately does not touch users or devices,
// so repeated risky attempts cannot launder a device or location into the
// user's baseline.
func (s *Store) RecordFlaggedTransaction(userID, ipAddress, country, fingerprint string, amount float64, recommendation string, flags []string) error {
	flagsJSON, err := json.Marshal(flags)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO flagged_transactions (user_id, ip_address, country, device_fingerprint, amount, recommendation, flags)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, ipAddress, country, fingerprint, amount, recommendation, string(flagsJSON),
	)
	return err
}

// FlaggedTransactions returns the audit records for a user, oldest first.
func (s *Store) FlaggedTransactions(userID string) ([]FlaggedTransaction, error) {
	return s.queryFlagged(
		`SELECT user_id, ip_address, country, device_fingerprint, amount, recommendation, flags, created_at
		 FROM flagged_transactions WHERE user_id = ? ORDER BY id`,
		userID,
	)
}

// RecentFlaggedTransactions returns the newest audit records across all
// users, newest first, capped at limit.
func (s *Store) RecentFlaggedTransactions(limit int) ([]FlaggedTransaction, error) {
	return s.queryFlagged(
		`SELECT user_id, ip_address, country, device_fingerprint, amount, recommendation, flags, created_at
		 FROM flagged_transactions ORDER BY id DESC LIMIT ?`,
		limit,
	)
}

func (s *Store) queryFlagged(query string, args ...any) ([]FlaggedTransaction, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlaggedTransaction
	for rows.Next() {
		var ft FlaggedTransaction
		var flagsJSON string
		if err := rows.Scan(&ft.UserID, &ft.IPAddress, &ft.Country, &ft.DeviceFingerprint,
			&ft.Amount, &ft.Recommendation, &flagsJSON, &ft.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(flagsJSON), &ft.Flags); err != nil {
			return nil, err
		}
		out = append(out, ft)
	}
	return out, rows.Err()
}
