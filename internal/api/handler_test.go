package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"securepay-verify/internal/db"
	"securepay-verify/internal/rules"
)

// newTestServer returns a test server backed by a fresh store seeded with one
// user: alice in the US (IP 8.8.8.8), device dev-alice, avg amount 100.
func newTestServer(t *testing.T) (*httptest.Server, *db.Store) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	for _, amount := range []float64{90, 100, 110} {
		if err := store.RecordTransaction("alice", "8.8.8.8", "US", "dev-alice", amount); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	ts := httptest.NewServer(NewServer(store).Routes())
	t.Cleanup(ts.Close)
	return ts, store
}

func postVerify(t *testing.T, ts *httptest.Server, req VerifyRequest) rules.Result {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/api/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result rules.Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return result
}

func TestVerifyAllowUpdatesBaseline(t *testing.T) {
	ts, store := newTestServer(t)

	// New device alone scores 30 -> allow, so it should join the baseline.
	result := postVerify(t, ts, VerifyRequest{
		UserID:            "alice",
		IPAddress:         "8.8.8.8",
		DeviceFingerprint: "dev-alice-new-phone",
		TransactionAmount: 100,
	})
	if result.Recommendation != "allow" || result.RiskScore != 30 {
		t.Fatalf("got %+v, want allow/30", result)
	}

	h, err := store.GetUserHistory("alice", "dev-alice-new-phone")
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if !h.KnownDevice {
		t.Error("allowed verification should record the new device")
	}
	if h.AvgAmount != 100 {
		t.Errorf("avg = %v, want 100 (allowed txn joins the average)", h.AvgAmount)
	}

	// The same device is known on a second call, so it scores clean.
	result = postVerify(t, ts, VerifyRequest{
		UserID:            "alice",
		IPAddress:         "8.8.8.8",
		DeviceFingerprint: "dev-alice-new-phone",
		TransactionAmount: 100,
	})
	if result.RiskScore != 0 || result.Recommendation != "allow" {
		t.Errorf("second call got %+v, want allow/0", result)
	}
}

func TestVerifyBlockDoesNotUpdateBaseline(t *testing.T) {
	ts, store := newTestServer(t)

	// New device + foreign IP + huge amount: 95 -> block.
	req := VerifyRequest{
		UserID:            "alice",
		IPAddress:         "102.89.1.1", // NG per the geo stub
		DeviceFingerprint: "dev-evil",
		TransactionAmount: 5000,
	}
	result := postVerify(t, ts, req)
	if result.Recommendation != "block" || result.RiskScore != 95 {
		t.Fatalf("got %+v, want block/95", result)
	}

	h, err := store.GetUserHistory("alice", "dev-evil")
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if h.KnownDevice {
		t.Error("blocked verification must not record the device")
	}
	if h.LastCountry != "US" {
		t.Errorf("last country = %q, want US (blocked txn must not move it)", h.LastCountry)
	}
	if h.AvgAmount != 100 {
		t.Errorf("avg = %v, want 100 (blocked txn must not join the average)", h.AvgAmount)
	}

	// Repeating the identical attempt scores the same: nothing was laundered.
	result = postVerify(t, ts, req)
	if result.Recommendation != "block" || result.RiskScore != 95 {
		t.Errorf("repeat call got %+v, want block/95", result)
	}

	// Both attempts are in the audit table.
	flagged, err := store.FlaggedTransactions("alice")
	if err != nil {
		t.Fatalf("flagged transactions: %v", err)
	}
	if len(flagged) != 2 {
		t.Fatalf("flagged count = %d, want 2", len(flagged))
	}
	ft := flagged[0]
	if ft.Recommendation != "block" || ft.DeviceFingerprint != "dev-evil" || ft.Amount != 5000 {
		t.Errorf("flagged record = %+v", ft)
	}
	wantFlags := []string{"new_device", "location_mismatch", "unusual_amount"}
	if len(ft.Flags) != len(wantFlags) {
		t.Errorf("flags = %v, want %v", ft.Flags, wantFlags)
	}
}
