-- Roles
-- nameserver_admin: runs migrations (DDL), owns all objects.
-- nameserver: application user (DML only).
CREATE ROLE nameserver_admin WITH LOGIN;
CREATE ROLE nameserver WITH LOGIN;

-- Permissions: nameserver gets full DML access to public schema objects.
GRANT USAGE ON SCHEMA public TO nameserver;
GRANT ALL ON SCHEMA public TO nameserver_admin;

-- Extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Enums
CREATE TYPE indicator_type AS ENUM ('domain', 'ip', 'asn', 'geo', 'suffix');
CREATE TYPE enrichment_type AS ENUM ('nrd', 'well_known', 'bulletproof');
CREATE TYPE filter_type AS ENUM ('block', 'allow');
CREATE TYPE output_format AS ENUM ('xor', 'fst', 'ipf');
CREATE TYPE list_type AS ENUM ('allowlist', 'blocklist');
CREATE TYPE block_mode AS ENUM ('nxdomain', 'redirect_ip');

-- Domains observed via flow processing
CREATE TABLE domains (
    domain      TEXT PRIMARY KEY,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL
);
-- Partial expression index used by similarity::search_exact_label.
-- Mirrors idx_ind_domains_label on indicator_domains; the partial
-- predicate matches the query_count >= 5 filter so only the hot subset
-- is indexed.
CREATE INDEX idx_domains_split_label_hot
    ON domains (split_part(domain, '.', 1))
    WHERE query_count >= 5;

-- DNS resolution history (append-only)
CREATE TABLE resolution_history (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain             TEXT NOT NULL,
    resolved_at        TIMESTAMPTZ NOT NULL,
    ips                JSONB NOT NULL,
    ttl                INTEGER NOT NULL,
    cname_chain        JSONB,
    ns_servers         JSONB,
    mx_records         JSONB,
    dnssec_status      TEXT NOT NULL,
    resolve_ms         INTEGER NOT NULL,
    a_record_count     SMALLINT NOT NULL DEFAULT 0,
    has_txt            BOOLEAN NOT NULL DEFAULT FALSE,
    referral_hop_count SMALLINT NOT NULL DEFAULT 0,
    soa_json           JSONB
);
CREATE INDEX idx_rh_domain ON resolution_history (domain, resolved_at DESC);

-- IP intelligence
CREATE TABLE ips (
    ip              INET PRIMARY KEY,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    geo_country     CHAR(2),
    geo_city        TEXT,
    asn_number      INTEGER,
    asn_org         TEXT,
    is_cdn          BOOLEAN NOT NULL DEFAULT FALSE,
    is_bulletproof  BOOLEAN NOT NULL DEFAULT FALSE,
    ptr_record      TEXT,
    ptr_matches     BOOLEAN,
    domain_count    INTEGER NOT NULL DEFAULT 0,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    blocklist_json  JSONB,
    updated_at      TIMESTAMPTZ NOT NULL
);

-- Domain-to-IP mapping (junction table)
CREATE TABLE domain_ips (
    domain     TEXT NOT NULL,
    ip         INET NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (domain, ip)
);
-- Secondary index for ip-first lookups. The PK `(domain, ip)` can't
-- serve `WHERE ip = $1` queries — notably the `INSERT INTO ips …
-- (SELECT COUNT(DISTINCT domain) FROM domain_ips WHERE ip = $1)`
-- that fires on every flow with a new resolved IP. Without this
-- index PG falls back to parallel seq scans over the full table
-- (~900k rows as of 2026-04-23) and pegs the control plane.
CREATE INDEX idx_domain_ips_ip ON domain_ips (ip);

-- Sources (pull registry for all external + infrastructure data)
CREATE TABLE sources (
    id                    UUID PRIMARY KEY DEFAULT uuidv7(),
    slug                  TEXT UNIQUE NOT NULL,
    indicator_type        indicator_type NOT NULL,
    url                   TEXT NOT NULL,
    categories            TEXT[] NOT NULL DEFAULT '{}',
    fetch_config          JSONB NOT NULL DEFAULT '{}',
    parse_config          JSONB NOT NULL DEFAULT '{"type": "lines"}',
    validate_config       JSONB NOT NULL DEFAULT '{}',
    refresh_interval_secs INTEGER NOT NULL DEFAULT 86400,
    enabled               BOOLEAN NOT NULL DEFAULT FALSE,
    last_pull_at          TIMESTAMPTZ,
    last_checksum         TEXT,
    last_entry_count      INTEGER,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indicator data: domains
CREATE TABLE indicator_domains (
    source   UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    domain   TEXT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL,
    extra    JSONB NOT NULL DEFAULT '{}',
    -- Generated: hot-path fields surfaced from extra for typed queries
    rank     INTEGER GENERATED ALWAYS AS (JSON_VALUE(extra, '$.rank' RETURNING int)) STORED,
    PRIMARY KEY (source, domain)
);
CREATE INDEX idx_ind_domains_domain ON indicator_domains (domain);
CREATE INDEX idx_ind_domains_rank ON indicator_domains (rank) WHERE rank IS NOT NULL;
CREATE INDEX idx_ind_domains_label ON indicator_domains ((split_part(domain, '.', 1)));

-- Indicator data: IPs and CIDRs
CREATE TABLE indicator_ips (
    source   UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    ip       INET NOT NULL,
    added_at TIMESTAMPTZ NOT NULL,
    extra    JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (source, ip)
);
CREATE INDEX idx_ind_ips_ip ON indicator_ips (ip);
CREATE INDEX idx_ind_ips_gist ON indicator_ips USING gist (ip inet_ops);

-- Indicator data: ASNs
CREATE TABLE indicator_asns (
    source   UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    asn      INTEGER NOT NULL,
    added_at TIMESTAMPTZ NOT NULL,
    extra    JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (source, asn)
);

-- Indicator data: public suffixes (PSL + custom)
CREATE TABLE indicator_suffixes (
    source    UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    suffix    TEXT NOT NULL,
    rule_type TEXT NOT NULL DEFAULT 'exact',
    added_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source, suffix, rule_type)
);
CREATE INDEX idx_ind_suffixes_suffix ON indicator_suffixes (suffix);

-- Compiled filters (artifacts for the resolver)
CREATE TABLE filters (
    id                   UUID PRIMARY KEY DEFAULT uuidv7(),
    slug                 TEXT UNIQUE NOT NULL,
    display_name         TEXT NOT NULL,
    source_id            UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    filter_type          filter_type NOT NULL,
    output_format        output_format NOT NULL,
    compiled_checksum    TEXT,
    compiled_entry_count INTEGER,
    compiled_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enrichment bindings (which sources drive reputation enrichment)
CREATE TABLE enrichment_bindings (
    source_id       UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    enrichment_type enrichment_type NOT NULL,
    PRIMARY KEY (source_id, enrichment_type)
);

-- GeoIP data (RIR delegations + iptoasn)
CREATE TABLE geo_entries (
    start_ip   INET NOT NULL,
    end_ip     INET NOT NULL,
    country    CHAR(2) NOT NULL,
    ip_version SMALLINT NOT NULL,
    rir        TEXT NOT NULL,
    asn        INTEGER NOT NULL DEFAULT 0,
    asn_desc   TEXT,
    PRIMARY KEY (start_ip, ip_version)
);
CREATE INDEX idx_geo_lookup ON geo_entries (ip_version, start_ip);

-- RDAP (registration data) cache
CREATE TABLE rdap_cache (
    registrable_domain TEXT PRIMARY KEY,
    creation_date      TEXT,
    expiration_date    TEXT,
    registrar          TEXT,
    status_json        JSONB,
    nameservers_json   JSONB,
    privacy_protected  BOOLEAN DEFAULT FALSE,
    lookup_method      TEXT NOT NULL,
    retry_count        INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT,
    fetched_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL
);

-- Filtering profiles
CREATE TABLE profiles (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    block_mode   block_mode NOT NULL DEFAULT 'nxdomain',
    redirect_ip  INET,
    is_default   BOOLEAN NOT NULL DEFAULT FALSE,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

-- Profile-to-filter subscriptions
CREATE TABLE profile_filters (
    profile_id TEXT NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    filter_id  UUID NOT NULL REFERENCES filters (id) ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, filter_id)
);

-- Per-profile custom allow/block entries
CREATE TABLE profile_custom_entries (
    profile_id TEXT NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    list_type  list_type NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (profile_id, domain, list_type)
);

-- Domain-to-NS mapping (scoring chain)
CREATE TABLE domain_ns_map (
    registrable_domain TEXT NOT NULL,
    ns_domain          TEXT NOT NULL,
    first_seen         TIMESTAMPTZ NOT NULL,
    last_seen          TIMESTAMPTZ NOT NULL,
    observation_count  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (registrable_domain, ns_domain)
);
CREATE INDEX idx_ns_map_ns ON domain_ns_map (ns_domain);

-- Domain label embeddings for similarity search.
-- Requires: CREATE EXTENSION vector;
--
-- Two embeddings per label, produced by two distinct CNNs:
--
--   * `embedding` (32-dim) — classification CNN (`detector_cnn_v1`).
--     Trained with BCE loss; geometry clusters by class (mal/benign).
--     Consumed by LightGBM as a lexical feature; NOT useful for
--     similarity retrieval because the geometry is class-clustered.
--
--   * `sim_embedding` (64-dim) — contrastive CNN (`detector_cnn_sim_v1`).
--     Trained with InfoNCE on synthetic char perturbations; geometry
--     clusters by lexical similarity. Drives tier-2 similarity lookup
--     in `similarity::search_sim_neighbors` via HNSW cosine ANN.
--     Replaced the pg_trgm + levenshtein prefilter previously shipped
--     in migration 20260424000000_pg_trgm_label_index, which is in
--     turn dropped by 20260425000100_drop_levenshtein_tier2.
--
-- `sim_embedding` is nullable so existing rows can be backfilled
-- incrementally; once the backfill is complete the production query
-- skips rows with NULL sim_embedding.
CREATE TABLE domain_label_embeddings (
    label         TEXT PRIMARY KEY,
    embedding     vector(32) NOT NULL,
    sim_embedding vector(64),
    domains       JSONB NOT NULL DEFAULT '[]',
    ns_domains    JSONB NOT NULL DEFAULT '[]',
    updated_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_dle_embedding ON domain_label_embeddings USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_dle_sim_embedding ON domain_label_embeddings USING hnsw (sim_embedding vector_cosine_ops);

-- Domain reputation (pre-computed, one row per registrable domain)
-- incident_labels: post-hoc ground-truth labels for detector evaluation.
-- See docs/zero-second-detection-eval.md.
--
-- Joined to ClickHouse flows by domain (FQDN). One row per (domain, source);
-- multiple sources can label the same domain independently. `labeled_at` is
-- when the label landed in our system; `first_seen_at` is when the source
-- itself first observed the IOC (key for measuring detection latency vs.
-- our own first observation in flows/domain_reputation).
--
-- `layer` records which abstraction the source operates at:
--   'dns' — the FQDN itself is the IOC (Hagezi TIF, Spamhaus DBL, manual).
--           Directly usable as DNS-level ground truth.
--   'url' — source flags URL paths; FQDN may be an abuse-hosting domain
--           (github.com, cdn.discordapp.com). DNS-layer detectors cannot
--           reproduce the signal. Kept for reference, excluded from DNS
--           detector eval by default.
CREATE TABLE incident_labels (
    domain        TEXT NOT NULL,
    source        TEXT NOT NULL,
    layer         TEXT NOT NULL DEFAULT 'dns' CHECK (layer IN ('dns', 'url')),
    labeled_at    TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ,
    verdict       TEXT NOT NULL,
    confidence    REAL,
    threat_type   TEXT,
    extra         JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (domain, source)
);
CREATE INDEX idx_incident_labels_labeled_at ON incident_labels (labeled_at);
CREATE INDEX idx_incident_labels_verdict    ON incident_labels (verdict);
CREATE INDEX idx_incident_labels_first_seen ON incident_labels (first_seen_at);
CREATE INDEX idx_incident_labels_layer      ON incident_labels (layer);

-- injection_queue: work queue for the resolution injector. When autopull
-- ingests a new indicator_domains row (identified by added_at > prior
-- pull), the injector enqueues a row here. A background scheduler
-- dequeues pending rows, sends a synthetic DoH query to our own resolver
-- (mimicking organic traffic — rotating profile pool, jittered timing),
-- and reconciles the returned flow_id via a NATS consumer on
-- ns.dns.flow. See memory: project_resolution_injector.md.
CREATE TYPE injection_status AS ENUM (
    'pending',      -- not yet attempted
    'in_flight',    -- DoH query sent, waiting for flow reconciliation
    'resolved',     -- reconciled to a flow_id
    'failed',       -- attempt ended in error; may retry
    'abandoned'     -- exceeded retry budget
);

CREATE TABLE injection_queue (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain            TEXT NOT NULL,
    source_slug       TEXT NOT NULL,
    label_verdict     TEXT NOT NULL,
    -- Drain priority, lower = sooner. TIF/DGA go ahead of pro because
    -- malicious label freshness is the load-bearing signal for the
    -- detector; pro is an ad/tracker list and could starve TIF if it
    -- shared an enqueue-order FIFO.
    priority          INTEGER NOT NULL DEFAULT 100,
    enqueued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_for     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_attempt_at   TIMESTAMPTZ,
    status            injection_status NOT NULL DEFAULT 'pending',
    resolved_flow_id  UUID,
    resolved_at       TIMESTAMPTZ,
    last_error        TEXT
);
CREATE INDEX idx_iq_pending_sched
    ON injection_queue (priority, scheduled_for)
    WHERE status = 'pending';
CREATE INDEX idx_iq_domain_status
    ON injection_queue (domain, status)
    WHERE status IN ('pending', 'in_flight');
CREATE UNIQUE INDEX idx_iq_active_uniq
    ON injection_queue (domain, source_slug)
    WHERE status IN ('pending', 'in_flight');

CREATE TABLE domain_reputation (
    registrable_domain    TEXT PRIMARY KEY,

    -- Traffic
    total_flow_count      INTEGER NOT NULL DEFAULT 0,
    first_seen            TIMESTAMPTZ NOT NULL,
    last_seen             TIMESTAMPTZ NOT NULL,

    -- TLD
    tld                   TEXT,
    tld_type              TEXT,

    -- NS (pre-classified). Canonical NS list lives in domain_ns_map; this row
    -- only stores the summary trust classification and observation count.
    ns_trust              TEXT NOT NULL DEFAULT 'unknown',
    ns_observation_count  INTEGER NOT NULL DEFAULT 0,

    -- Infrastructure fingerprint (pgvector, 27-dim)
    infra_fingerprint     vector(27),

    -- Resolution chain (EMA-smoothed aggregates + structure)
    avg_auth_ttl          REAL,
    min_auth_ttl          REAL,
    avg_resolve_ms        REAL,
    avg_chain_depth       REAL,
    has_cname             BOOLEAN NOT NULL DEFAULT FALSE,
    cname_targets         JSONB DEFAULT '[]',
    has_dnssec            BOOLEAN NOT NULL DEFAULT FALSE,
    has_mx                BOOLEAN NOT NULL DEFAULT FALSE,
    unique_ip_count       SMALLINT NOT NULL DEFAULT 0,
    a_record_count        SMALLINT NOT NULL DEFAULT 0,

    -- IP summary
    primary_asn           INTEGER,
    primary_country       CHAR(2),
    is_cdn                BOOLEAN NOT NULL DEFAULT FALSE,

    -- External intelligence (batch-updated)
    is_nrd                BOOLEAN NOT NULL DEFAULT FALSE,
    nrd_source            TEXT,
    is_well_known         BOOLEAN NOT NULL DEFAULT FALSE,

    -- NS continuity tracking (Phase 2: stability requires NS unchanged for 30d)
    last_ns_change_at     TIMESTAMPTZ,

    -- Trust anchoring
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

-- A fresh installation applies migrations independently of host provisioning.
-- Grant the application DML access and identity-sequence access after all tables exist.
REVOKE CREATE ON SCHEMA public FROM nameserver;
GRANT USAGE ON SCHEMA public TO nameserver;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nameserver;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nameserver;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nameserver;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO nameserver;
ALTER DEFAULT PRIVILEGES FOR ROLE nameserver_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nameserver;
ALTER DEFAULT PRIVILEGES FOR ROLE nameserver_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO nameserver;
