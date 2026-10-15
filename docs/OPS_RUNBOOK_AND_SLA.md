# Operations Runbook, Deployment Guide & 99.9% SLA

**Target:** Bank Infrastructure Engineering / DevSecOps  
**Scope:** On-Premise Containerized Cluster (Go + Redis + PostgreSQL + Nginx)  

---

## 1. High Availability Architecture (99.9% SLA)

To achieve a **99.9% Service Level Agreement (< 8.76 hours downtime/year)**:
* **Stateless Go Middleware:** Run a minimum of 2 replica containers behind Nginx or Kubernetes Service.
* **Redis High Availability:** Redis Sentinel or Redis Cluster with automatic failover (< 3s election time).
* **PostgreSQL Audit DB:** Standby replication with automatic WAL archiving.

### Performance Targets
* **End-to-End Unlock Latency:** < 150ms from mobile approval to ATM unlock.
* **Throughput:** > 5,000 concurrent ATM terminals per middleware instance.
* **Recovery Point Objective (RPO):** < 1 minute (Redis AOF `everysec`).
* **Recovery Time Objective (RTO):** < 5 minutes (automated container restart).

---

## 2. On-Premises Installation & Deployment

### Step 1: Generate Bank PKI Infrastructure
```bash
cd deploy
./generate-mtls-certs.sh
```
*(Or in PowerShell: `.\generate-mtls-certs.ps1`)*

### Step 2: Configure Environment Secrets
Ensure `docker-compose.prod.yml` or Kubernetes Secret contains:
* `REDIS_URL`: Authenticated connection string to bank Redis cluster.
* `DATABASE_URL`: PostgreSQL connection string with `atm_auth_app` user.
* `RSA_PRIVATE_KEY_FILE`: Mounted secret containing the bank's 2048-bit or 4096-bit RSA private key.
* `RSA_PUBLIC_KEY_FILE`: Mounted secret containing the RSA public key.

### Step 3: Launch Production Stack
```bash
docker compose -f docker-compose.prod.yml up -d
```

### Step 4: Health Check Verification
```bash
curl -k https://localhost:8443/api/health
# Response: {"env":"production","nonce":"...","ok":true,"ts":1773518400000}
```

---

## 3. Incident Management & Reconciliation Runbook

### Scenario A: "ATM Dispensed Cash, but Backend Network Failed"
1. **Physical ATM Isolation:** ATM journals record hardware note count regardless of middleware connectivity.
2. **Reconciliation Job:** Every 15 minutes, the ATM Switch executes an automated reconciliation comparing physical cash drawer balances against `/api/session/{id}` consumed state.
3. **Audit Trail Matching:** Compare ATM terminal journal ID with PostgreSQL `atm_audit_logs` using `session_id`.

### Scenario B: "Redis Cluster Node Outage"
* If the primary Redis node drops, Sentinel promotes the replica within 3 seconds.
* The Go backend automatically reconnects using the `go-redis` failover client without dropping ongoing mobile transactions.

### Scenario C: "Key Rotation Procedure"
1. Generate new RSA key pair with new Key ID (`JWT_KID=bank-atm-key-2`).
2. Add new public key to verification set while maintaining previous public key in cache for 120 seconds.
3. Switch signing private key to `bank-atm-key-2` — zero downtime rotation.
