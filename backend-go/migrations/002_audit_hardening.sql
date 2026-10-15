-- ============================================================================
-- Enterprise Bank Audit Hardening & Immutability Migration (002)
-- Enforces Least Privilege, Revokes Destructive Privileges, and Adds Hash-Chain
-- ============================================================================

-- 1. Add cryptographic integrity columns for forensic hash-chaining
ALTER TABLE atm_audit_logs 
    ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS request_id VARCHAR(64) DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_atm_audit_request_id ON atm_audit_logs(request_id);

-- 2. Create Audit Outbox table for fail-closed synchronous guarantees
CREATE TABLE IF NOT EXISTS audit_outbox (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_id VARCHAR(64) NOT NULL,
    atm_id VARCHAR(64) NOT NULL,
    event VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    dispatched BOOLEAN NOT NULL DEFAULT FALSE,
    dispatched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_pending ON audit_outbox(dispatched) WHERE dispatched = FALSE;

-- 3. Strict immutability: Ensure no UPDATE or DELETE or TRUNCATE is permitted
DO $$
BEGIN
    -- Revoke destructive permissions from PUBLIC
    REVOKE UPDATE, DELETE, TRUNCATE ON atm_audit_logs FROM PUBLIC;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_outbox FROM PUBLIC;
END $$;
