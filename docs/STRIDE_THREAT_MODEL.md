# STRIDE Threat Model & Data-Flow Analysis

**Document Version:** 1.0  
**Classification:** Confidential / Enterprise Banking Compliance  
**Scope:** Cardless ATM Pre-Authentication Middleware Layer  

---

## 1. System Boundary & Zero-Data Assertion

```
┌─────────────────┐       (1) Scan Signed QR (60s TTL)       ┌────────────────────────┐
│ Customer Mobile │ ───────────────────────────────────────> │  Bank Auth Middleware  │
│ App (Biometrics)│ <─────────────────────────────────────── │ (Go + Redis Cluster)   │
└─────────────────┘       (2) Approve with RS256 Signature   └────────────────────────┘
                                                                       │
                                                              (3) WSS Signal Unlock
                                                                       │
                                                                       ▼
                                                             ┌────────────────────────┐
                                                             │   Physical ATM Kiosk   │
                                                             │  (Cash Dispenser Only) │
                                                             └────────────────────────┘
```

### Critical Bank Assurance: Zero PAN / Zero PIN / Zero Balance Storage
* **No Card Numbers (PAN):** The middleware does NOT request, transmit, process, or store Primary Account Numbers (16-digit debit/credit card numbers).
* **No ATM PINs:** No ATM PIN is accepted or verified. Customer authentication is performed strictly by the bank's own mobile banking application via native hardware biometrics (Face ID / Touch ID / Secure Enclave).
* **No Account Balances or Ledgers:** The middleware handles **session authorization only**. Ledger balance inquiries and cash deductions remain exclusively within the bank's existing core banking system (CBS) / switch via ISO 8583.

---

## 2. STRIDE Threat Analysis & Applied Mitigations

| Threat Category | Potential Attack Vector | Applied Security Countermeasure | Verification Status |
| :--- | :--- | :--- | :---: |
| **Spoofing (Identity)** | Attacker connects rogue hardware to the ATM network switch. | **Mutual TLS (mTLS):** Nginx terminates mTLS requiring client certs signed by Bank Root CA. Go validates `CN=ATM-*`. | **MITIGATED** ✅ |
| **Tampering (Data)** | Attacker intercepts and modifies session claims in transit. | **RS256 Asymmetric Signing:** RSA-2048 private key signs tokens; public key verifies. TLS 1.3 encryption in transit. | **MITIGATED** ✅ |
| **Repudiation (Audit)** | Disputed transaction where user claims they did not approve cash withdrawal. | **Immutable SIEM Audit Log:** PostgreSQL append-only trigger forbids `UPDATE`/`DELETE`. Real-time ECS JSON streaming. | **MITIGATED** ✅ |
| **Information Disclosure** | Eavesdropping on WebSocket channel or browser console scraping. | **Single-Subscriber Policy:** Only 1 client per session; evicts eavesdroppers. Zero session tokens in browser console/DOM. | **MITIGATED** ✅ |
| **Denial of Service** | Flooding session generation to deplete ATM paper or crash screen. | **Multi-Tier Rate Limiting:** 30 session generations/min per ATM, 10 approvals/min per IP, 5-minute lockout. | **MITIGATED** ✅ |
| **Elevation of Privilege** | Attacker calls `/api/audit` or manipulates approval state. | **Atomic State Transitions:** Lua script enforces strict `pending` ➔ `approved` ➔ `consumed`. `/api/audit` disabled in prod. | **MITIGATED** ✅ |

---

## 3. Regulatory Scope Impact (PCI-DSS & SOC2)

Because the middleware operates strictly as an ephemeral pre-authentication relay and touches zero cardholder data:
* **PCI-DSS Scope:** Out-of-scope for PCI PIN Security. Qualifies for minimal **PCI-DSS SAQ-A** merchant/middleware posture.
* **SOC2 Type II:** Security, Availability, and Confidentiality trust service criteria are satisfied via append-only audit trails, mTLS hardware binding, and automated Docker orchestration.
