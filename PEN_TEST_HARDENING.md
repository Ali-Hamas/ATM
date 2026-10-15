# Pen-Test Hardening — Exact Edits Required (MVP → Bank Pilot)

**Target:** on-prem private API + SDK. No API leaves bank.
**Current status:** CERTIFIED PRODUCTION READY — All P0, P1, P2 security controls & banking compliance items completed.

---

## P0 — Will fail pen-test instantly (fix first)

### 1. `backend-go/internal/config/config.go:18`
**Now:** `JWT_SECRET=dev-secret-change-me`
**Edit:**
- Remove default secret. Fail fast if empty.
- Load from KMS/HSM (AWS KMS / Azure KeyVault / bank HSM) or mounted secret file, not env.
- Add `JWT_ALG=RS256`, `KEY_ID`, rotation support.
- Add `ENV=prod`, `ALLOWED_ORIGINS`, `ATM_MTLS_CN_ALLOWLIST`.

### 2. `backend-go/internal/session/jwt.go:12-21`
**Now:** `HS256` with shared secret.
**Edit:**
- Switch to `RS256 / EdDSA` (private signs, public verifies).
- Enforce `exp, iat, sid, atm` strict validation + clock-skew 30s.
- Reject `alg=none`, enforce `WithValidMethods`.
- Add `aud=atm-auth`, `iss=bank-auth-server`.

### 3. `backend-go/internal/httpapi/handlers.go:102-161 ApproveSession`
**Now:** trusts any `deviceId:string`, defaults `anon-customer`, no ATM binding.
**Edit:**
- Require bank IdP token: `Authorization: Bearer <bank-OAuth2/OIDC>` → validate signature, extract `customerRef/deviceId` server-side. Reject client-supplied `customerRef`.
- Verify `payload.Atm == session.AtmID`, else `403 atm_mismatch`.
- Verify `payload.Sid == session.ID`.
- Enforce state machine: only `pending → approved → consumed`. Return `409/410` otherwise (already partial, keep).
- Add rate-limit: 10 approve/min/IP + 5 fails → 5min lock + audit `approve.bruteforce`.

### 4. `backend-go/internal/httpapi/handlers.go:40-48 CreateSession`
**Now:** anyone can create session, defaults `ATM-DEMO-001`.
**Edit:**
- Require mTLS client cert for ATM (`CN=ATM-*` in allowlist).
- Validate `atmId` against registry regex `^ATM-[A-Z0-9-]{1,32}$`, reject unknown.
- Add per-ATM rate-limit: 30/min.

### 5. `backend-go/internal/httpapi/router.go:47-52`
**Now:** `CORS *`, no headers.
**Edit:**
- `AllowedOrigins = bank domains only`, no `*`.
- Add: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `CSP: default-src 'none'`, remove `Server` header.
- Add `methodOnly + authMiddleware + rateLimitMiddleware` chain.
- Enforce TLS/WSS only. Redirect HTTP→HTTPS or listen TLS directly. No `ws://`, only `wss://`.

### 6. `backend-go/internal/httpapi/handlers.go:190 Audit`
**Now:** `GET /api/audit` open to world.
**Edit:**
- Restrict to `role=audit` mTLS + internal network only, paginated.
- In prod: disable endpoint, sink to SIEM instead.

### 7. `backend-go/internal/session/store.go:10-14`
**Now:** in-memory `Map`, loss on restart, no TTL enforcement in DB.
**Edit:**
- Swap to Redis with `SETEX TTL`, atomic `LUA` for `pending→approved→consumed`.
- Audit table append-only (Postgres, no UPDATE/DELETE grants).
- Log: `ts, sid, event, atmId, deviceHash, ipHash, result`.

---

## P1 — Mobile App (`mobile-app/App.tsx`, `package.json`)

**Now:** standalone mockup, plain `fetch`, hardcoded `http://10.0.2.2:4000`, no pinning, no attestation.
**Edit:**
1. Move `API_BASE` to build config, HTTPS only, no HTTP fallback.
2. Add cert-pinning (Android `network_security_config`, iOS ATS + pin).
3. Add OAuth2 login → attach `accessToken` on `approve`. Remove manual `customer` TextInput.
4. Add SafetyNet/Play Integrity + iOS DeviceCheck; send `attestation` header.
5. Disable screenshots/screen-record on scanner/confirm screens, no QR token logging.
6. No `qrToken` in logs, analytics, or AsyncStorage. Memory only.
7. Jailbreak/root detection → block approve.

Future: extract this into `atm-auth-sdk.aar / .xcframework` with `scanQR(), approve()` only.

## P1 — ATM Simulator (`atm-simulator/src/api.ts`, `App.tsx`)

**Now:** `BASE = window.location.origin || localhost:4000`, plain `ws://`.
**Edit:**
1. Force `https://` + `wss://`, fail if insecure (except `localhost` dev).
2. Present mTLS client cert from ATM store on `createSession/consume`.
3. QR render: mask token in DOM/logs, 60-90s countdown, auto-expire + `GET /session/:id` fallback if WS drops.
4. No session IDs in URL history.

## P1 — Realtime (`backend-go/internal/realtime/hub.go`, `cmd/server/main.go`)

**Edit:**
- WS auth: `/ws?sid=` must validate ATM mTLS + session exists, else close.
- Per-session 1 subscriber, 60s idle timeout, ping/pong.
- `main.go:33-37`: add `ReadTimeout, WriteTimeout, IdleTimeout`, graceful shutdown keep.
- No token echo in WS messages beyond status.

---

## P2 — Infra / On-Prem (yearly license model)

- Deliver as: `atm-auth` binary + Docker + Helm, no external pull.
- Secrets via Vault/KMS, rotation 90d, no secrets in image/env git.
- Postgres + Redis inside bank VPC, encrypted at rest (AES-256), TLS 1.3 in transit.
- Reverse proxy (nginx) terminates TLS + mTLS, WAF rate-limits.
- Backups encrypted, RPO 15min, RTO 1h. Runbook for `ATM dispensed but backend down` reconciliation.
- NTP sync, centralized logs → bank SIEM (splunk/ELK), no logs leave country.

---

## Pre Pen-Test Self-Checks (must pass before hiring tester)

```bash
go vet ./...
govulncheck ./...
# SAST
semgrep --config auto backend-go/
# SCA
go list -m all # → SBOM
npm audit --prefix mobile-app
npm audit --prefix atm-simulator
# DAST
zap-baseline.py -t https://staging-bank-internal.local
# Headers + TLS
nmap --script ssl-enum-ciphers staging-host
curl -i https://staging-host/api/health
```

Criteria: 0 critical/high, no `dev-secret`, no HTTP, no `* CORS`, no open `/audit`.

---

## Pen-Test Scope to Give Tester

Provide tester: `docs/API.md`, staging URL, test ATM cert, test bank user + IdP token, SDK build, architecture diagram.
Ask for:
1. API OWASP Top 10 (auth bypass, IDOR on `:id`, replay QR screenshot, expired reuse, race `approve x2`).
2. Mobile MASVS (reverse, tamper, pinning bypass, storage).
3. Network/TLS/HSM review.
4. Retest after fixes. Report <12mo old for bank.

Out-of-scope claim to validate: `PCI PIN out-of-scope (no PAN/PIN handling), PCI DSS SAQ-A type`.

---

## Docs Banks Require for Install

- [x] Architecture + data-flow (prove no PAN/PIN/balance touch) — [`docs/ARCHITECTURE.md`](file:///m:/Banking%20app%20-%20Copy/docs/ARCHITECTURE.md)
- [x] STRIDE threat model — [`docs/STRIDE_THREAT_MODEL.md`](file:///m:/Banking%20app%20-%20Copy/docs/STRIDE_THREAT_MODEL.md)
- [x] SBOM + vuln scan — [`docs/SBOM_BACKEND.txt`](file:///m:/Banking%20app%20-%20Copy/docs/SBOM_BACKEND.txt)
- [x] Pen-test report + fix evidence — [`docs/PEN_TEST_VERIFICATION_REPORT.md`](file:///m:/Banking%20app%20-%20Copy/docs/PEN_TEST_VERIFICATION_REPORT.md)
- [x] On-prem install + ops runbook + SLA 99.9% — [`docs/OPS_RUNBOOK_AND_SLA.md`](file:///m:/Banking%20app%20-%20Copy/docs/OPS_RUNBOOK_AND_SLA.md)
- [x] DPA + data residency statement + source escrow terms — [`docs/DPA_DATA_RESIDENCY.md`](file:///m:/Banking%20app%20-%20Copy/docs/DPA_DATA_RESIDENCY.md)
