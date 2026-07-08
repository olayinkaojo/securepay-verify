# SecurePay Verify

A fraud-detection MVP: a Go REST API that scores payment transactions against
each user's stored history (devices, locations, amounts) using a simple rules
engine — no ML in v1.

## Project layout

```
cmd/server/      HTTP server entrypoint
cmd/seed/        seeds the database with 5 mock users + history
internal/api/    HTTP handlers and request validation
internal/db/     SQLite storage (users, devices, transactions)
internal/rules/  scoring rules engine + stub GeoIP lookup
```

Storage is SQLite via `modernc.org/sqlite` (pure Go — no CGO required).

## Running it

Requires Go 1.22+.

```sh
# 1. Seed the database (creates securepay.db with 5 mock users)
go run ./cmd/seed

# 2. Start the API on :8080
go run ./cmd/server
```

Flags: both commands accept `-db <path>` (default `securepay.db`); the server
also accepts `-addr` (default `:8080`).

Run the tests with `go test ./...`.

## API

### POST /api/verify

Request:

```json
{
  "user_id": "alice-001",
  "ip_address": "8.8.8.8",
  "device_fingerprint": "dev-alice-macbook",
  "transaction_amount": 55.0
}
```

Response:

```json
{
  "risk_score": 0,
  "flags": [],
  "recommendation": "allow"
}
```

Every verification is recorded into the user's history, so baselines evolve
over time (a "new" device is only new once).

### Rules (v1)

| Rule | Condition | Score | Flag |
|---|---|---|---|
| New device | fingerprint never seen for this user | +30 | `new_device` |
| Location mismatch | IP country ≠ user's last known country | +40 | `location_mismatch` |
| Unusual amount | amount > 3× user's historical average | +25 | `unusual_amount` |

Recommendation: score ≥ 70 → `block`, 40–69 → `review`, < 40 → `allow`.
Rules that lack a baseline are skipped: an unknown IP or a user with no
location history can't trigger `location_mismatch`, and a user with no
transactions can't trigger `unusual_amount`.

### GeoIP note

IP-to-country lookup is a stub prefix table in `internal/rules/geo.go`
covering just the demo ranges (US, NG, GB, DE, BR). IPs outside those ranges
resolve to "unknown" and skip the location rule. Swap in a real provider
(e.g. MaxMind GeoLite2) for production.

## Seeded users

| user_id | Country | Device fingerprint | Avg amount |
|---|---|---|---|
| `alice-001` | US | `dev-alice-macbook` | ~$51 |
| `bob-002` | NG | `dev-bob-android` | ~$121 |
| `carol-003` | GB | `dev-carol-iphone` | ~$302 |
| `dan-004` | DE | `dev-dan-thinkpad` | ~$75 |
| `eve-005` | BR | `dev-eve-pixel` | ~$202 |

## Trying it with curl

Clean transaction — known device, home country, normal amount → **allow**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"alice-001","ip_address":"8.8.8.8","device_fingerprint":"dev-alice-macbook","transaction_amount":55.00}'
# {"risk_score":0,"flags":[],"recommendation":"allow"}
```

New device + unusual amount (30 + 25 = 55) → **review**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"alice-001","ip_address":"8.8.8.8","device_fingerprint":"dev-stolen-laptop","transaction_amount":400.00}'
# {"risk_score":55,"flags":["new_device","unusual_amount"],"recommendation":"review"}
```

Everything wrong at once — new device, foreign IP, huge amount (30 + 40 + 25 = 95) → **block**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"bob-002","ip_address":"177.99.1.1","device_fingerprint":"dev-unknown","transaction_amount":5000.00}'
# {"risk_score":95,"flags":["new_device","location_mismatch","unusual_amount"],"recommendation":"block"}
```

Known device but logging in from abroad (40) → **review**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"carol-003","ip_address":"8.8.4.4","device_fingerprint":"dev-carol-iphone","transaction_amount":300.00}'
# {"risk_score":40,"flags":["location_mismatch"],"recommendation":"review"}
```

Note: each call records history, so repeating the "new device" examples will
score lower the second time — the device is known after the first call.
Re-run `go run ./cmd/seed` on a fresh database (`rm securepay.db`) to reset.
