// Package rules implements the v1 fraud-scoring rules engine.
package rules

// Risk weights and decision thresholds for the v1 rules.
const (
	ScoreNewDevice        = 30
	ScoreLocationMismatch = 40
	ScoreUnusualAmount    = 25

	AmountMultiplier = 3.0 // amount > 3x historical average is unusual

	ThresholdBlock  = 70 // score >= 70 -> block
	ThresholdReview = 40 // score >= 40 -> review, otherwise allow
)

// Input is the set of facts the engine evaluates. Callers derive these from
// the incoming request and the user's stored history.
type Input struct {
	KnownDevice   bool    // fingerprint previously seen for this user
	IPCountry     string  // country resolved from the request IP, "" if unresolvable
	LastCountry   string  // user's last known country, "" if none
	Amount        float64 // transaction amount under evaluation
	AvgAmount     float64 // user's historical average amount
	HasTxnHistory bool    // user has prior transactions to average over
}

// Result is the scored outcome.
type Result struct {
	RiskScore      int      `json:"risk_score"`
	Flags          []string `json:"flags"`
	Recommendation string   `json:"recommendation"`
}

// Evaluate applies the v1 rules and returns a capped 0-100 risk score,
// triggered flags, and a recommendation.
func Evaluate(in Input) Result {
	score := 0
	flags := []string{} // non-nil so it serializes as [] rather than null

	if !in.KnownDevice {
		score += ScoreNewDevice
		flags = append(flags, "new_device")
	}

	// Only compare countries when both sides are known; a user with no
	// location baseline (or an unresolvable IP) can't mismatch.
	if in.IPCountry != "" && in.LastCountry != "" && in.IPCountry != in.LastCountry {
		score += ScoreLocationMismatch
		flags = append(flags, "location_mismatch")
	}

	if in.HasTxnHistory && in.Amount > AmountMultiplier*in.AvgAmount {
		score += ScoreUnusualAmount
		flags = append(flags, "unusual_amount")
	}

	if score > 100 {
		score = 100
	}

	return Result{
		RiskScore:      score,
		Flags:          flags,
		Recommendation: recommend(score),
	}
}

func recommend(score int) string {
	switch {
	case score >= ThresholdBlock:
		return "block"
	case score >= ThresholdReview:
		return "review"
	default:
		return "allow"
	}
}
