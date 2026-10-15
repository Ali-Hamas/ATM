# atm-auth (Go)

Go rewrite of the QR-based ATM cardless authentication middleware. API-compatible
with the original Node/TypeScript backend — drop-in replacement for the React ATM
simulator and the React Native mobile app.

## Why Go

- Single static binary, no `node_modules` supply-chain surface
- Memory safety, strong typing, explicit error handling
- Goroutines model "one pending QR session waiting for approval" naturally
- Stdlib + 4 well-vetted libraries (gorilla/websocket, golang-jwt, google/uuid, rs/cors)

## Run

```bash
cd backend-go
go mod tidy
go run ./cmd/server
```

Expect:

```
auth middleware listening on :4000
ws endpoint  ws://localhost:4000/ws?sid=<sessionId>
```

## Environment Variables

| Variable                | Default                 | Purpose |
| ----------------------- | ----------------------- | --------------------------------------------- |
| `PORT`                  | `4000`                  | HTTP/WS listening port                        |
| `ENV`                   | `development`           | `production` forces RS256, mTLS, & fail-closed |
| `RSA_PRIVATE_KEY_FILE`  | *(none)*                | Path to PEM-encoded 2048/4096-bit RSA privkey |
| `RSA_PUBLIC_KEY_FILE`   | *(none)*                | Path to PEM-encoded RSA public key            |
| `JWT_KID`               | `bank-atm-key-1`        | Key ID header for RS256 JWKS key rotation     |
| `SESSION_TTL_SECONDS`   | `60`                    | QR token lifespan (hard bank timeout)         |
| `REDIS_URL`             | *(none)*                | Redis URL for distributed Lua state machine   |
| `DATABASE_URL`          | *(none)*                | PostgreSQL connection for immutable audit log |
| `REQUIRE_MTLS`          | `false` (true in prod)  | Enforce client certificate authentication     |

## API

Same as the Node version. See `docs/API.md` in the repo root.

| Method | Path                          | Purpose                          |
| ------ | ----------------------------- | -------------------------------- |
| POST   | `/api/session`                | Create a pending QR session       |
| GET    | `/api/session/{id}`           | Read session state                |
| POST   | `/api/session/approve`        | Mobile app approves a scanned QR  |
| POST   | `/api/session/{id}/consume`   | ATM consumes session post-dispense|
| GET    | `/api/audit`                  | All audit entries (demo only)     |
| GET    | `/api/health`                 | Liveness + nonce                  |
| WS     | `/ws?sid=<sessionId>`         | Push updates for one session      |

## Build a release binary

```bash
go build -o atm-auth ./cmd/server
./atm-auth
```

On Windows: `go build -o atm-auth.exe ./cmd/server`.

## Layout

```
backend-go/
  cmd/server/main.go        — entrypoint + graceful shutdown
  internal/
    config/                 — env loader
    session/                — types, store, JWT sign/verify
    realtime/               — gorilla/websocket hub
    httpapi/                — handlers + router + CORS
```
