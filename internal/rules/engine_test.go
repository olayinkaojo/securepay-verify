package rules

import (
	"reflect"
	"testing"
)

func TestEvaluate(t *testing.T) {
	base := Input{
		KnownDevice:   true,
		IPCountry:     "US",
		LastCountry:   "US",
		Amount:        50,
		AvgAmount:     50,
		HasTxnHistory: true,
	}

	tests := []struct {
		name   string
		modify func(*Input)
		score  int
		flags  []string
		rec    string
	}{
		{"clean transaction", func(in *Input) {}, 0, []string{}, "allow"},
		{"new device only", func(in *Input) { in.KnownDevice = false }, 30, []string{"new_device"}, "allow"},
		{"location mismatch only", func(in *Input) { in.IPCountry = "BR" }, 40, []string{"location_mismatch"}, "review"},
		{"unusual amount only", func(in *Input) { in.Amount = 151 }, 25, []string{"unusual_amount"}, "allow"},
		{"amount exactly 3x is not unusual", func(in *Input) { in.Amount = 150 }, 0, []string{}, "allow"},
		{"new device + unusual amount", func(in *Input) {
			in.KnownDevice = false
			in.Amount = 200
		}, 55, []string{"new_device", "unusual_amount"}, "review"},
		{"all rules trigger", func(in *Input) {
			in.KnownDevice = false
			in.IPCountry = "NG"
			in.Amount = 500
		}, 95, []string{"new_device", "location_mismatch", "unusual_amount"}, "block"},
		{"new device + location mismatch blocks at threshold", func(in *Input) {
			in.KnownDevice = false
			in.IPCountry = "NG"
		}, 70, []string{"new_device", "location_mismatch"}, "block"},
		{"unresolvable IP skips location rule", func(in *Input) { in.IPCountry = "" }, 0, []string{}, "allow"},
		{"no location baseline skips location rule", func(in *Input) {
			in.LastCountry = ""
			in.IPCountry = "NG"
		}, 0, []string{}, "allow"},
		{"no txn history skips amount rule", func(in *Input) {
			in.HasTxnHistory = false
			in.AvgAmount = 0
			in.Amount = 10000
		}, 0, []string{}, "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			tt.modify(&in)
			got := Evaluate(in)
			if got.RiskScore != tt.score {
				t.Errorf("risk_score = %d, want %d", got.RiskScore, tt.score)
			}
			if !reflect.DeepEqual(got.Flags, tt.flags) {
				t.Errorf("flags = %v, want %v", got.Flags, tt.flags)
			}
			if got.Recommendation != tt.rec {
				t.Errorf("recommendation = %q, want %q", got.Recommendation, tt.rec)
			}
		})
	}
}

func TestCountryForIP(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "US"},
		{"102.89.32.10", "NG"},
		{"81.2.69.142", "GB"},
		{"78.46.10.20", "DE"},
		{"177.12.4.8", "BR"},
		{"192.168.1.1", ""},
	}
	for _, tt := range tests {
		if got := CountryForIP(tt.ip); got != tt.want {
			t.Errorf("CountryForIP(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}
