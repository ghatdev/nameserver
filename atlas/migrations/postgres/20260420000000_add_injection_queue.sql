-- injection_queue: work queue for the resolution injector. When autopull
-- ingests a new indicator_domains row (identified by added_at > prior
-- pull), the injector enqueues a row here. A background scheduler dequeues
-- pending rows, sends a synthetic DoH query to our own resolver, and (via
-- a NATS consumer on ns.dns.flow) reconciles the returned flow_id back
-- onto this row. Continuous label acquisition. See memory:
-- project_resolution_injector.md.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'injection_status') THEN
        CREATE TYPE injection_status AS ENUM (
            'pending',      -- not yet attempted
            'in_flight',    -- DoH query sent, waiting for flow reconciliation
            'resolved',     -- reconciled to a flow_id
            'failed',       -- attempt ended in error; may retry up to attempt_count
            'abandoned'     -- exceeded retry budget; will not be attempted again
        );
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS injection_queue (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain            TEXT NOT NULL,
    source_slug       TEXT NOT NULL,
    label_verdict     TEXT NOT NULL,  -- 'malicious' | 'benign'
    enqueued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_for     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_attempt_at   TIMESTAMPTZ,
    status            injection_status NOT NULL DEFAULT 'pending',
    resolved_flow_id  UUID,
    resolved_at       TIMESTAMPTZ,
    last_error        TEXT
);

-- Scheduler hot query: find next pending entries whose scheduled_for is due.
CREATE INDEX IF NOT EXISTS idx_iq_pending_sched
    ON injection_queue (scheduled_for)
    WHERE status = 'pending';

-- Reconciliation by domain (matching returning flows to queue rows).
CREATE INDEX IF NOT EXISTS idx_iq_domain_status
    ON injection_queue (domain, status)
    WHERE status IN ('pending', 'in_flight');

-- Enforce single in-flight job per (domain, source) to avoid duplicate
-- queries for the same enqueue. Partial unique index allows multiple
-- historical rows for the same (domain, source) once resolved/failed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iq_active_uniq
    ON injection_queue (domain, source_slug)
    WHERE status IN ('pending', 'in_flight');

GRANT SELECT, INSERT, UPDATE, DELETE ON injection_queue TO nameserver;
GRANT USAGE ON TYPE injection_status TO nameserver;
