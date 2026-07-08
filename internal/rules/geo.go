package rules

import "strings"

// geoPrefixes is a stub GeoIP database mapping IP prefixes to ISO country
// codes, sufficient for the MVP demo. Longest prefix wins. Replace with a
// real GeoIP provider (e.g. MaxMind) in production.
var geoPrefixes = map[string]string{
	// United States
	"8.":     "US",
	"4.2.":   "US",
	"64.233": "US",
	// Nigeria
	"102.":    "NG",
	"105.112": "NG",
	// United Kingdom
	"81.2.": "GB",
	"25.":   "GB",
	// Germany
	"78.46.":  "DE",
	"88.198.": "DE",
	// Brazil
	"177.": "BR",
	"189.": "BR",
}

// CountryForIP resolves an IP address to an ISO country code using the stub
// prefix table. Returns "" when the IP doesn't match any known prefix.
func CountryForIP(ip string) string {
	best, bestLen := "", -1
	for prefix, country := range geoPrefixes {
		if strings.HasPrefix(ip, prefix) && len(prefix) > bestLen {
			best, bestLen = country, len(prefix)
		}
	}
	return best
}
