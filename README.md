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
dashboard/       Next.js demo dashboard (form + flagged-transactions table)
```

Storage is [Turso](https://turso.tech) (libSQL) via
`github.com/tursodatabase/libsql-client-go` (pure Go — no CGO required), so
data persists in Turso's cloud independently of wherever the Go API is
deployed. Tests run against a temporary local SQLite file and need no Turso
credentials.

## Running it

Requires Go 1.22+ and a Turso database.

```sh
# 1. One-time Turso setup (see .env.example for the same steps)
brew install tursodatabase/tap/turso
turso auth signup                          # or: turso auth login
turso db create securepay-verify
export TURSO_DATABASE_URL=$(turso db show securepay-verify --url)
export TURSO_AUTH_TOKEN=$(turso db tokens create securepay-verify)

# 2. Seed the database with 5 mock users
go run ./cmd/seed

# 3. Set the API key (see .env.example) — the server refuses to start without it
export SECUREPAY_API_KEY=$(openssl rand -hex 32)

# 4. Start the API on :8080
go run ./cmd/server
```

The server accepts an `-addr` flag (default `:8080`). To reset demo data,
drop and recreate the Turso database (`turso db destroy securepay-verify`,
then repeat the setup), or delete rows directly with `turso db shell`.

### Authentication

Every request must carry the key in an `X-API-Key` header; anything missing
or wrong gets `401 {"error": "missing or invalid API key"}`. This is a single
shared key suitable for an MVP demo — not per-merchant auth.

Run the tests with `go test ./...`.

### Dashboard

A minimal Next.js dashboard lives in `dashboard/` — a form that submits to
`POST /api/verify` (risk score, flag badges, color-coded recommendation) and
a table of recent flagged transactions from `GET /api/flagged`, refreshed on
load and after each submission.

The browser never talks to the Go API directly and never sees the API key:
the page calls the dashboard's own server-side route handlers
(`app/api/verify` and `app/api/flagged`), which hold `SECUREPAY_API_KEY`
server-side and proxy to the Go API with the `X-API-Key` header attached.
The key is not in any client component or `NEXT_PUBLIC_` variable, so it
never ships in a browser bundle.

```sh
cd dashboard
npm install
cp .env.local.example .env.local   # fill in the same key the Go API uses
npm run dev                        # http://localhost:3000 (expects the API on :8080)
```

The API still allows CORS from `http://localhost:3000` only, handy for
direct-from-browser experiments, though the dashboard no longer needs it.

> **Local demo only.** Auth is a single shared API key with no rate limiting
> or per-merchant identity — do not expose this pair on a public interface
> as-is.

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

Only **allowed** verifications are recorded into the user's history, so the
baseline evolves from trusted activity only. Verifications that come back
`review` or `block` are persisted to a separate `flagged_transactions` audit
table (with their recommendation and flags) that never feeds the rules
engine — a fraudster can't launder a risky device or location into the
baseline by repeating the attempt.

### GET /api/flagged

Returns the 20 most recent flagged (review/block) verifications, newest
first, for the dashboard's audit table:

```sh
curl -s localhost:8080/api/flagged -H "X-API-Key: $SECUREPAY_API_KEY"
```

```json
[
  {
    "user_id": "alice-001",
    "ip_address": "8.8.8.8",
    "country": "US",
    "device_fingerprint": "dev-stolen-laptop",
    "amount": 400,
    "recommendation": "review",
    "flags": ["new_device", "unusual_amount"],
    "created_at": "2026-07-08T17:11:37Z"
  }
]
```

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
  -H "X-API-Key: $SECUREPAY_API_KEY" \
  -d '{"user_id":"alice-001","ip_address":"8.8.8.8","device_fingerprint":"dev-alice-macbook","transaction_amount":55.00}'
# {"risk_score":0,"flags":[],"recommendation":"allow"}
```

New device + unusual amount (30 + 25 = 55) → **review**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SECUREPAY_API_KEY" \
  -d '{"user_id":"alice-001","ip_address":"8.8.8.8","device_fingerprint":"dev-stolen-laptop","transaction_amount":400.00}'
# {"risk_score":55,"flags":["new_device","unusual_amount"],"recommendation":"review"}
```

Everything wrong at once — new device, foreign IP, huge amount (30 + 40 + 25 = 95) → **block**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SECUREPAY_API_KEY" \
  -d '{"user_id":"bob-002","ip_address":"177.99.1.1","device_fingerprint":"dev-unknown","transaction_amount":5000.00}'
# {"risk_score":95,"flags":["new_device","location_mismatch","unusual_amount"],"recommendation":"block"}
```

Known device but logging in from abroad (40) → **review**:

```sh
curl -s -X POST localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SECUREPAY_API_KEY" \
  -d '{"user_id":"carol-003","ip_address":"8.8.4.4","device_fingerprint":"dev-carol-iphone","transaction_amount":300.00}'
# {"risk_score":40,"flags":["location_mismatch"],"recommendation":"review"}
```

Note: only `allow` outcomes update the user's baseline. The `review` and
`block` examples above return the same result no matter how many times you
repeat them — the flagged device/location/amount never becomes part of the
user's history (the attempts land in `flagged_transactions` for audit
instead). An allowed transaction *does* record: e.g. a new device on a
clean transaction scores 30 (`allow`) the first time and 0 the next, because
the device joined the baseline. To reset, recreate the Turso database and
re-run `go run ./cmd/seed` (see "Running it").
