package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"securepay-verify/internal/db"
	"securepay-verify/internal/rules"

	// Tests use a temporary local SQLite file instead of Turso so they run
	// offline without credentials; see db.OpenLocal.
	_ "modernc.org/sqlite"
)

const testAPIKey = "test-api-key-123"

// newTestServer returns a test server backed by a fresh store seeded with one
// user: alice in the US (IP 8.8.8.8), device dev-alice, avg amount 100.
// Requests must authenticate with testAPIKey.
func newTestServer(t *testing.T) (*httptest.Server, *db.Store) {
	t.Helper()
	store, err := db.OpenLocal("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	for _, amount := range []float64{90, 100, 110} {
		if err := store.RecordTransaction("alice", "8.8.8.8", "US", "dev-alice", amount); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	t.Setenv("SECUREPAY_API_KEY", testAPIKey)
	ts := httptest.NewServer(NewServer(store, os.Getenv("SECUREPAY_API_KEY")).Routes())
	t.Cleanup(ts.Close)
	return ts, store
}

// doRequest sends an authenticated request with an optional JSON body.
func doRequest(t *testing.T, method, url, apiKey string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func postVerify(t *testing.T, ts *httptest.Server, req VerifyRequest) rules.Result {
	t.Helper()
	body, _ := json.Marshal(req)
	resp := doRequest(t, http.MethodPost, ts.URL+"/api/verify", testAPIKey, body)
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

func getFlagged(t *testing.T, ts *httptest.Server) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodGet, ts.URL+"/api/flagged", testAPIKey, nil)
}

func TestAuth(t *testing.T) {
	ts, _ := newTestServer(t)

	endpoints := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/verify"},
		{http.MethodGet, "/api/flagged"},
	}
	for _, ep := range endpoints {
		for name, key := range map[string]string{"missing key": "", "wrong key": "not-the-key"} {
			t.Run(ep.path+" "+name, func(t *testing.T) {
				resp := doRequest(t, ep.method, ts.URL+ep.path, key, nil)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", resp.StatusCode)
				}
				var e struct {
					Error string `json:"error"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if e.Error != "missing or invalid API key" {
					t.Errorf("error = %q, want %q", e.Error, "missing or invalid API key")
				}
			})
		}
	}

	// CORS preflight must succeed without a key — browsers don't send
	// custom headers on OPTIONS.
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/verify", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-API-Key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", resp.StatusCode)
	}
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

func TestFlaggedEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)

	// Empty audit table serializes as [], not null.
	resp := getFlagged(t, ts)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("CORS origin = %q, want http://localhost:3000", got)
	}
	var flagged []db.FlaggedTransaction
	if err := json.NewDecoder(resp.Body).Decode(&flagged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(flagged) != 0 {
		t.Fatalf("flagged = %d rows, want 0", len(flagged))
	}

	// A blocked verification shows up, newest first.
	postVerify(t, ts, VerifyRequest{
		UserID:            "alice",
		IPAddress:         "102.89.1.1",
		DeviceFingerprint: "dev-evil",
		TransactionAmount: 5000,
	})
	resp2 := getFlagged(t, ts)
	defer resp2.Body.Close()
	if err := json.NewDecoder(resp2.Body).Decode(&flagged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(flagged) != 1 || flagged[0].Recommendation != "block" || flagged[0].UserID != "alice" {
		t.Fatalf("flagged = %+v, want one block row for alice", flagged)
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
