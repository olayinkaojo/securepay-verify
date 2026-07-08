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
	dbPath := flag.String("db", "securepay.db", "path to SQLite database")
	flag.Parse()

	apiKey := os.Getenv("SECUREPAY_API_KEY")
	if apiKey == "" {
		log.Fatal("SECUREPAY_API_KEY is not set; refusing to start without auth. " +
			"Generate a key (e.g. openssl rand -hex 32) and export SECUREPAY_API_KEY before starting the server.")
	}

	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database %s: %v", *dbPath, err)
	}
	defer store.Close()

	server := api.NewServer(store, apiKey)
	log.Printf("SecurePay Verify listening on %s (db: %s)", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatal(err)
	}
}
