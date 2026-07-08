// Command seed populates the SQLite database with 5 mock users and
// transaction history so the demo has baselines to compare against.
package main

import (
	"flag"
	"log"

	"securepay-verify/internal/db"
	"securepay-verify/internal/rules"
)

type seedUser struct {
	userID      string
	ipAddress   string // resolves to the user's home country via the geo stub
	fingerprint string
	amounts     []float64
}

var seedUsers = []seedUser{
	{"alice-001", "8.8.8.8", "dev-alice-macbook", []float64{45.00, 52.50, 60.00, 48.25}},         // US, avg ~51
	{"bob-002", "102.89.32.10", "dev-bob-android", []float64{110.00, 125.00, 130.50, 118.00}},    // NG, avg ~121
	{"carol-003", "81.2.69.142", "dev-carol-iphone", []float64{290.00, 310.00, 305.75}},          // GB, avg ~302
	{"dan-004", "78.46.10.20", "dev-dan-thinkpad", []float64{70.00, 80.00, 72.30, 77.90, 75.00}}, // DE, avg ~75
	{"eve-005", "177.12.4.8", "dev-eve-pixel", []float64{195.00, 210.00, 200.50}},                // BR, avg ~202
}

func main() {
	dbPath := flag.String("db", "securepay.db", "path to SQLite database")
	flag.Parse()

	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database %s: %v", *dbPath, err)
	}
	defer store.Close()

	for _, u := range seedUsers {
		country := rules.CountryForIP(u.ipAddress)
		for _, amount := range u.amounts {
			if err := store.RecordTransaction(u.userID, u.ipAddress, country, u.fingerprint, amount); err != nil {
				log.Fatalf("seed %s: %v", u.userID, err)
			}
		}
		log.Printf("seeded %s (%s): %d transactions, device %s", u.userID, country, len(u.amounts), u.fingerprint)
	}
	log.Printf("done: %d users seeded into %s", len(seedUsers), *dbPath)
}
