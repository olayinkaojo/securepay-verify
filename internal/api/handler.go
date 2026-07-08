// Package api exposes the HTTP interface for SecurePay Verify.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"

	"securepay-verify/internal/db"
	"securepay-verify/internal/rules"
)

// VerifyRequest is the POST /api/verify payload.
type VerifyRequest struct {
	UserID            string  `json:"user_id"`
	IPAddress         string  `json:"ip_address"`
	DeviceFingerprint string  `json:"device_fingerprint"`
	TransactionAmount float64 `json:"transaction_amount"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Server holds the API's dependencies.
type Server struct {
	store  *db.Store
	apiKey string
}

// NewServer returns a Server backed by the given store. Every request must
// present apiKey in the X-API-Key header.
func NewServer(store *db.Store, apiKey string) *Server {
	return &Server{store: store, apiKey: apiKey}
}

// Routes returns the HTTP handler with all API routes registered. cors wraps
// auth so OPTIONS preflight requests succeed without a key — browsers don't
// send custom headers on preflight.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/verify", s.handleVerify)
	mux.HandleFunc("GET /api/flagged", s.handleFlagged)
	return cors(s.auth(mux))
}

// cors allows the local dashboard (localhost:3000) to call the API from the
// browser, including preflight requests.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth rejects requests whose X-API-Key header doesn't match the configured
// key. The comparison is constant-time to avoid leaking the key by timing.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing or invalid API key"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body: " + err.Error()})
		return
	}
	if msg := validate(req); msg != "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: msg})
		return
	}

	history, err := s.store.GetUserHistory(req.UserID, req.DeviceFingerprint)
	if err != nil {
		log.Printf("verify: load history for %s: %v", req.UserID, err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	ipCountry := rules.CountryForIP(req.IPAddress)

	result := rules.Evaluate(rules.Input{
		KnownDevice:   history.KnownDevice,
		IPCountry:     ipCountry,
		LastCountry:   history.LastCountry,
		Amount:        req.TransactionAmount,
		AvgAmount:     history.AvgAmount,
		HasTxnHistory: history.HasTxnHistory,
	})

	// Only allowed transactions update the user's baseline (devices,
	// last_country, average amount); review/block attempts go to a separate
	// audit table so a fraudster can't launder a risky device or location
	// into the baseline by repeating the attempt.
	if result.Recommendation == "allow" {
		err = s.store.RecordTransaction(
			req.UserID, req.IPAddress, ipCountry, req.DeviceFingerprint, req.TransactionAmount,
		)
	} else {
		err = s.store.RecordFlaggedTransaction(
			req.UserID, req.IPAddress, ipCountry, req.DeviceFingerprint, req.TransactionAmount,
			result.Recommendation, result.Flags,
		)
	}
	if err != nil {
		log.Printf("verify: record %s outcome for %s: %v", result.Recommendation, req.UserID, err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleFlagged(w http.ResponseWriter, r *http.Request) {
	flagged, err := s.store.RecentFlaggedTransactions(20)
	if err != nil {
		log.Printf("flagged: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if flagged == nil {
		flagged = []db.FlaggedTransaction{} // serialize as [] rather than null
	}
	writeJSON(w, http.StatusOK, flagged)
}

func validate(req VerifyRequest) string {
	switch {
	case req.UserID == "":
		return "user_id is required"
	case req.IPAddress == "":
		return "ip_address is required"
	case net.ParseIP(req.IPAddress) == nil:
		return "ip_address is not a valid IP address"
	case req.DeviceFingerprint == "":
		return "device_fingerprint is required"
	case req.TransactionAmount <= 0:
		return "transaction_amount must be greater than 0"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}
