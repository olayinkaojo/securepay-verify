// Command server runs the SecurePay Verify HTTP API.
package main

import (
	"flag"
	"log"
	"net/http"

	"securepay-verify/internal/api"
	"securepay-verify/internal/db"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "securepay.db", "path to SQLite database")
	flag.Parse()

	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database %s: %v", *dbPath, err)
	}
	defer store.Close()

	server := api.NewServer(store)
	log.Printf("SecurePay Verify listening on %s (db: %s)", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatal(err)
	}
}
