// Command server runs the SecurePay Verify HTTP API.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"securepay-verify/internal/api"
	"securepay-verify/internal/db"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	apiKey := os.Getenv("SECUREPAY_API_KEY")
	if apiKey == "" {
		log.Fatal("SECUREPAY_API_KEY is not set; refusing to start without auth. " +
			"Generate a key (e.g. openssl rand -hex 32) and export SECUREPAY_API_KEY before starting the server.")
	}

	dbURL := os.Getenv("TURSO_DATABASE_URL")
	if dbURL == "" {
		log.Fatal("TURSO_DATABASE_URL is not set. Create a database with `turso db create securepay-verify`, " +
			"then export the URL from `turso db show securepay-verify --url`.")
	}
	authToken := os.Getenv("TURSO_AUTH_TOKEN")
	if authToken == "" {
		log.Fatal("TURSO_AUTH_TOKEN is not set. Generate one with `turso db tokens create securepay-verify` " +
			"and export it before starting the server.")
	}

	store, err := db.Open(dbURL, authToken)
	if err != nil {
		log.Fatalf("open database %s: %v", dbURL, err)
	}
	defer store.Close()

	server := api.NewServer(store, apiKey)
	log.Printf("SecurePay Verify listening on %s (db: %s)", *addr, dbURL)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatal(err)
	}
}
