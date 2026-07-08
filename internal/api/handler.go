// Package api exposes the HTTP interface for SecurePay Verify.
package api

import (
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
	store *db.Store
}

// NewServer returns a Server backed by the given store.
func NewServer(store *db.Store) *Server {
	return &Server{store: store}
}

// Routes returns the HTTP handler with all API routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/verify", s.handleVerify)
	return mux
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

	// Record every verification (regardless of outcome) so the user's
	// baseline evolves. v2 could restrict this to allowed transactions.
	if err := s.store.RecordTransaction(
		req.UserID, req.IPAddress, ipCountry, req.DeviceFingerprint, req.TransactionAmount,
	); err != nil {
		log.Printf("verify: record transaction for %s: %v", req.UserID, err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, result)
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
