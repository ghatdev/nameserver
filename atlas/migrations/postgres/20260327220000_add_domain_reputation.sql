-- Domain reputation (pre-computed, one row per registrable domain)
CREATE TABLE domain_reputation (
    registrable_domain    TEXT PRIMARY KEY,
    total_flow_count      INTEGER NOT NULL DEFAULT 0,
    first_seen            TIMESTAMPTZ NOT NULL,
    last_seen             TIMESTAMPTZ NOT NULL,
    tld                   TEXT,
    tld_type              TEXT,
    ns_trust              TEXT NOT NULL DEFAULT 'unknown',
    ns_domains            JSONB NOT NULL DEFAULT '[]',
    ns_observation_count  INTEGER NOT NULL DEFAULT 0,
    infra_fingerprint     vector(27),
    avg_auth_ttl          REAL,
    min_auth_ttl          REAL,
    avg_resolve_ms        REAL,
    avg_chain_depth       REAL,
    has_cname             BOOLEAN NOT NULL DEFAULT FALSE,
    cname_targets         JSONB DEFAULT '[]',
    delegation_ns         JSONB DEFAULT '[]',
    has_dnssec            BOOLEAN NOT NULL DEFAULT FALSE,
    has_mx                BOOLEAN NOT NULL DEFAULT FALSE,
    unique_ip_count       SMALLINT NOT NULL DEFAULT 0,
    a_record_count        SMALLINT NOT NULL DEFAULT 0,
    primary_asn           INTEGER,
    primary_country       CHAR(2),
    is_cdn                BOOLEAN NOT NULL DEFAULT FALSE,
    is_nrd                BOOLEAN NOT NULL DEFAULT FALSE,
    nrd_source            TEXT,
    is_well_known         BOOLEAN NOT NULL DEFAULT FALSE,
    is_trusted            BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at            TIMESTAMPTZ,
    trusted_fingerprint   vector(27),
    trust_source          TEXT,
    updated_at            TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_dr_infra ON domain_reputation
    USING hnsw (infra_fingerprint vector_cosine_ops)
    WHERE infra_fingerprint IS NOT NULL;
CREATE INDEX idx_dr_trusted ON domain_reputation (is_trusted)
    WHERE is_trusted = TRUE;

-- Reputation anomalies (hijack/drift detection)
CREATE TABLE reputation_anomalies (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    registrable_domain    TEXT NOT NULL,
    detected_at           TIMESTAMPTZ NOT NULL,
    flow_fingerprint      vector(27),
    trusted_fingerprint   vector(27),
    cosine_distance       REAL NOT NULL,
    flow_ns               JSONB,
    flow_ips              JSONB,
    resolved              BOOLEAN NOT NULL DEFAULT FALSE,
    resolution            TEXT
);
CREATE INDEX idx_ra_domain ON reputation_anomalies (registrable_domain, detected_at DESC);
