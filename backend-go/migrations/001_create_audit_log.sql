-- ============================================================================
-- Migration: 001_create_audit_log.sql
-- Description: Immutable, append-only audit trail for ATM pre-authentication
-- Target: Enterprise PostgreSQL with strict SIEM compliance & tamper-resistance
-- ============================================================================

-- 1. Create audit_logs table
CREATE TABLE IF NOT EXISTS atm_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ts_milli BIGINT NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    atm_id VARCHAR(32) NOT NULL,
    event VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL DEFAULT 'success', -- 'success' | 'failure' | 'rejected'
    client_ip VARCHAR(45),                          -- IPv4 or IPv6
    device_id VARCHAR(128),
    customer_ref VARCHAR(128),
    failure_reason TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 2. Indexes for fast regulatory compliance lookups and SIEM log queries
CREATE INDEX IF NOT EXISTS idx_atm_audit_session_id ON atm_audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_atm_audit_atm_id ON atm_audit_logs(atm_id);
CREATE INDEX IF NOT EXISTS idx_atm_audit_ts ON atm_audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_atm_audit_event ON atm_audit_logs(event);
CREATE INDEX IF NOT EXISTS idx_atm_audit_outcome ON atm_audit_logs(outcome);

-- 3. IMMUTABILITY ENFORCEMENT: Trigger function preventing any UPDATE or DELETE
-- Under banking compliance (PCI-DSS 10.5, SOC2 Type II, ISO 27001), audit logs
-- must be strictly append-only. No application role or DBA should alter history.
CREATE OR REPLACE FUNCTION forbid_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: atm_audit_logs is append-only. UPDATE and DELETE operations are strictly forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_update ON atm_audit_logs;
CREATE TRIGGER trg_prevent_audit_update
    BEFORE UPDATE OR DELETE ON atm_audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION forbid_audit_modification();

-- 4. Minimal privilege grant script for production bank deployment
-- Run this block with bank DBA credentials:
--
-- CREATE ROLE atm_auth_app WITH LOGIN PASSWORD 'strong-vault-password';
-- GRANT USAGE ON SCHEMA public TO atm_auth_app;
-- GRANT INSERT, SELECT ON atm_audit_logs TO atm_auth_app;
-- GRANT USAGE, SELECT ON SEQUENCE atm_audit_logs_id_seq TO atm_auth_app;
-- -- Note: UPDATE, DELETE, TRUNCATE are explicitly NOT granted.
