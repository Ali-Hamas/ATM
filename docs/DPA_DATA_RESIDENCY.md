# Data Protection Agreement (DPA) & Data Residency Statement

**Party A:** DemoBank International / Financial Institution ("The Bank")  
**Party B:** Cardless ATM Middleware Solution Provider ("The Provider")  
**Governing Standard:** GDPR Art. 28, Central Bank Data Sovereignty Regulations, ISO 27001  

---

## 1. Data Residency & Sovereignty Guarantee

1. **On-Premise Deployment Guarantee:**
   The software is licensed and delivered to execute **exclusively within the Bank's private data centers or sovereign private cloud infrastructure**.
2. **Zero Telemetry / No Outbound Egress:**
   The middleware software contains **zero phone-home beacons, zero external analytics trackers, and zero external cloud dependencies**. No telemetry or diagnostic logs leave the Bank's boundary.
3. **Data Boundary:**
   All cryptographic keys, active session tokens, and audit trails reside strictly inside the Bank's network perimeter (`bank-internal`).

---

## 2. Zero-PII Processing Confirmation

The Provider certifies under penalty of breach that:
* **No Personally Identifiable Information (PII)** such as customer government IDs, phone numbers, home addresses, or emails are processed or required by the middleware.
* The `customerRef` field accepts an opaque pseudonymous identifier or hash provided by the Bank's own Identity Provider (IdP).
* No financial account numbers (IBAN, PAN), card CVVs, or card PINs are handled by the middleware.

---

## 3. Auditability & Source Code Escrow

1. **Right to Audit:**
   The Bank has the full right to conduct independent third-party penetration testing, static code analysis (SAST), and architectural inspections at any time.
2. **Source Code Escrow:**
   Under enterprise enterprise licensing agreements, complete compilable source code is held with a neutral escrow agent (e.g., NCC Group Escrow / Iron Mountain) to guarantee business continuity for the Bank.
