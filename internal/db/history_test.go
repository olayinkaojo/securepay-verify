package db

import (
	"path/filepath"
	"reflect"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestRecordTransactionUpdatesBaseline(t *testing.T) {
	store := newTestStore(t)

	if err := store.RecordTransaction("u1", "8.8.8.8", "US", "dev-a", 100); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := store.RecordTransaction("u1", "8.8.8.8", "US", "dev-a", 200); err != nil {
		t.Fatalf("record: %v", err)
	}

	h, err := store.GetUserHistory("u1", "dev-a")
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if !h.Known {
		t.Error("user should be known after RecordTransaction")
	}
	if !h.KnownDevice {
		t.Error("device should be known after RecordTransaction")
	}
	if h.LastCountry != "US" {
		t.Errorf("last country = %q, want US", h.LastCountry)
	}
	if !h.HasTxnHistory || h.AvgAmount != 150 {
		t.Errorf("avg = %v (has history %v), want 150", h.AvgAmount, h.HasTxnHistory)
	}
}

func TestRecordFlaggedTransactionDoesNotTouchBaseline(t *testing.T) {
	store := newTestStore(t)

	// Establish a baseline, then record a risky attempt from a new device
	// in a different country with a large amount.
	if err := store.RecordTransaction("u1", "8.8.8.8", "US", "dev-a", 100); err != nil {
		t.Fatalf("record baseline: %v", err)
	}
	flags := []string{"new_device", "location_mismatch", "unusual_amount"}
	if err := store.RecordFlaggedTransaction("u1", "102.89.1.1", "NG", "dev-evil", 5000, "block", flags); err != nil {
		t.Fatalf("record flagged: %v", err)
	}

	h, err := store.GetUserHistory("u1", "dev-evil")
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if h.KnownDevice {
		t.Error("flagged attempt must not add the device to the baseline")
	}
	if h.LastCountry != "US" {
		t.Errorf("flagged attempt must not change last country: got %q, want US", h.LastCountry)
	}
	if h.AvgAmount != 100 {
		t.Errorf("flagged attempt must not affect avg amount: got %v, want 100", h.AvgAmount)
	}

	got, err := store.FlaggedTransactions("u1")
	if err != nil {
		t.Fatalf("flagged transactions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("flagged transactions count = %d, want 1", len(got))
	}
	ft := got[0]
	if ft.UserID != "u1" || ft.IPAddress != "102.89.1.1" || ft.Country != "NG" ||
		ft.DeviceFingerprint != "dev-evil" || ft.Amount != 5000 || ft.Recommendation != "block" {
		t.Errorf("flagged transaction fields = %+v", ft)
	}
	if !reflect.DeepEqual(ft.Flags, flags) {
		t.Errorf("flags = %v, want %v", ft.Flags, flags)
	}
}
