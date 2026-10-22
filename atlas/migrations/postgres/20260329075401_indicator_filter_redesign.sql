-- ============================================================
-- Indicator / Filter Schema Redesign Migration
--
-- Production data (2026-03-29):
--   filter_lists:       19 rows (including 3 sentinels)
--   blocklist:          590K rows (no trailing dots, includes 9.8K IPs from threatview-ips bug)
--   threat_feed:        583K rows (trailing dots)
--   well_known_domains: 1.5M rows (trailing dots, has rank column)
--   nrd:                2M rows (trailing dots)
--   threat_ips:         254 rows
--   allowlist:          0 rows
--   profile_filters:    10 rows (TEXT filter_id)
--   indicator_type enum: domain, ip (no asn/geo yet)
--
-- Strategy: pause control plane → backup → run this → deploy new binary
-- ============================================================

-- Phase 1: Add new enum values (must be before any DML using them)
-- PG12+: allowed in transaction, but can't use new values until committed.
-- We don't INSERT any 'asn' or 'geo' rows in this migration — safe.
-- ============================================================

ALTER TYPE "public"."indicator_type" ADD VALUE 'asn';
ALTER TYPE "public"."indicator_type" ADD VALUE 'geo';

CREATE TYPE "public"."enrichment_type" AS ENUM ('nrd', 'well_known', 'bulletproof');

-- Phase 2: Create new tables
-- ============================================================

CREATE TABLE "public"."indicator_sources" (
  "id" uuid NOT NULL DEFAULT uuidv7(),
  "slug" text NOT NULL,
  "indicator_type" "public"."indicator_type" NOT NULL,
  "url" text NOT NULL,
  "categories" text[] NOT NULL DEFAULT '{}',
  "fetch_config" jsonb NOT NULL DEFAULT '{}',
  "parse_config" jsonb NOT NULL DEFAULT '{"type": "lines"}',
  "validate_config" jsonb NOT NULL DEFAULT '{}',
  "refresh_interval_secs" integer NOT NULL DEFAULT 86400,
  "enabled" boolean NOT NULL DEFAULT false,
  "last_pull_at" timestamptz NULL,
  "last_checksum" text NULL,
  "last_entry_count" integer NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "indicator_sources_slug_key" UNIQUE ("slug")
);

CREATE TABLE "public"."indicator_domains" (
  "source" uuid NOT NULL,
  "domain" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  "extra" jsonb NOT NULL DEFAULT '{}',
  "rank" integer NULL GENERATED ALWAYS AS (JSON_VALUE(extra, '$."rank"' RETURNING integer)) STORED,
  PRIMARY KEY ("source", "domain"),
  CONSTRAINT "indicator_domains_source_fkey" FOREIGN KEY ("source") REFERENCES "public"."indicator_sources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
CREATE INDEX "idx_ind_domains_domain" ON "public"."indicator_domains" ("domain");
CREATE INDEX "idx_ind_domains_rank" ON "public"."indicator_domains" ("rank") WHERE (rank IS NOT NULL);

CREATE TABLE "public"."indicator_ips" (
  "source" uuid NOT NULL,
  "ip" inet NOT NULL,
  "added_at" timestamptz NOT NULL,
  "extra" jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY ("source", "ip"),
  CONSTRAINT "indicator_ips_source_fkey" FOREIGN KEY ("source") REFERENCES "public"."indicator_sources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
CREATE INDEX "idx_ind_ips_ip" ON "public"."indicator_ips" ("ip");
CREATE INDEX "idx_ind_ips_gist" ON "public"."indicator_ips" USING GIST ("ip" inet_ops);

CREATE TABLE "public"."indicator_asns" (
  "source" uuid NOT NULL,
  "asn" integer NOT NULL,
  "added_at" timestamptz NOT NULL,
  "extra" jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY ("source", "asn"),
  CONSTRAINT "indicator_asns_source_fkey" FOREIGN KEY ("source") REFERENCES "public"."indicator_sources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);

CREATE TABLE "public"."filters" (
  "id" uuid NOT NULL DEFAULT uuidv7(),
  "slug" text NOT NULL,
  "display_name" text NOT NULL,
  "source_id" uuid NOT NULL,
  "filter_type" text NOT NULL,
  "output_format" text NOT NULL,
  "compiled_checksum" text NULL,
  "compiled_entry_count" integer NULL,
  "compiled_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "filters_slug_key" UNIQUE ("slug"),
  CONSTRAINT "filters_source_id_fkey" FOREIGN KEY ("source_id") REFERENCES "public"."indicator_sources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "filters_filter_type_check" CHECK (filter_type = ANY (ARRAY['block'::text, 'allow'::text])),
  CONSTRAINT "filters_output_format_check" CHECK (output_format = ANY (ARRAY['xor'::text, 'fst'::text, 'ipf'::text]))
);

CREATE TABLE "public"."enrichment_bindings" (
  "source_id" uuid NOT NULL,
  "enrichment_type" "public"."enrichment_type" NOT NULL,
  PRIMARY KEY ("source_id", "enrichment_type"),
  CONSTRAINT "enrichment_bindings_source_id_fkey" FOREIGN KEY ("source_id") REFERENCES "public"."indicator_sources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);

-- Phase 3: Migrate data
-- ============================================================

-- 3a. filter_lists → indicator_sources
-- Skip sentinels: _geoip, _rdap, nameserver-threats (id starts with _ or has no URL)
INSERT INTO indicator_sources (slug, indicator_type, url, refresh_interval_secs, enabled,
                               last_pull_at, last_checksum, last_entry_count, created_at, updated_at)
SELECT id, indicator_type, url, refresh_interval_secs, enabled,
       last_pull_at, last_checksum, last_entry_count, created_at, updated_at
FROM filter_lists
WHERE id NOT LIKE '\_%'
  AND url != ''
  AND format != 'internal';

-- 3b. Create filters rows for compilable sources.
-- PRESERVE existing UUIDs from filter_lists.uuid so resolver cache stays valid.
-- Domain blocklists + threat feeds → output_format 'xor'
INSERT INTO filters (id, slug, display_name, source_id, filter_type, output_format, created_at, updated_at)
SELECT fl.uuid, s.slug, fl.display_name, s.id, 'block', 'xor', now(), now()
FROM filter_lists fl
JOIN indicator_sources s ON s.slug = fl.id
WHERE fl.list_type IN ('blocklist', 'threat_feed')
  AND fl.indicator_type = 'domain'
  AND fl.uuid IS NOT NULL;

-- IP threat feeds → output_format 'ipf'
INSERT INTO filters (id, slug, display_name, source_id, filter_type, output_format, created_at, updated_at)
SELECT fl.uuid, s.slug, fl.display_name, s.id, 'block', 'ipf', now(), now()
FROM filter_lists fl
JOIN indicator_sources s ON s.slug = fl.id
WHERE fl.list_type IN ('blocklist', 'threat_feed')
  AND fl.indicator_type = 'ip'
  AND fl.uuid IS NOT NULL;

-- 3c. Create enrichment_bindings for NRD and well-known sources.
INSERT INTO enrichment_bindings (source_id, enrichment_type)
SELECT s.id, 'nrd'::enrichment_type
FROM filter_lists fl
JOIN indicator_sources s ON s.slug = fl.id
WHERE fl.list_type = 'nrd';

INSERT INTO enrichment_bindings (source_id, enrichment_type)
SELECT s.id, 'well_known'::enrichment_type
FROM filter_lists fl
JOIN indicator_sources s ON s.slug = fl.id
WHERE fl.list_type = 'well_known';

-- 3d. blocklist → indicator_domains
-- Production data: blocklist has NO trailing dots.
-- SKIP source='threatview-ips' — those are IPs that ended up in the domain table (data bug).
-- RTRIM is safe: strips dot if present, no-op if not.
INSERT INTO indicator_domains (source, domain, added_at)
SELECT s.id, RTRIM(b.domain, '.'), b.added_at
FROM blocklist b
JOIN indicator_sources s ON s.slug = b.source
WHERE b.source != 'threatview-ips'
ON CONFLICT DO NOTHING;

-- 3e. threat_feed → indicator_domains
-- Production data: threat_feed HAS trailing dots.
INSERT INTO indicator_domains (source, domain, added_at)
SELECT s.id, RTRIM(tf.domain, '.'), tf.added_at
FROM threat_feed tf
JOIN indicator_sources s ON s.slug = tf.source
ON CONFLICT DO NOTHING;

-- 3f. well_known_domains → indicator_domains (with rank in extra JSONB)
-- Production data: HAS trailing dots, has rank column.
INSERT INTO indicator_domains (source, domain, added_at, extra)
SELECT s.id, RTRIM(wk.domain, '.'), wk.added_at,
       CASE WHEN wk.rank IS NOT NULL THEN jsonb_build_object('rank', wk.rank) ELSE '{}'::jsonb END
FROM well_known_domains wk
JOIN indicator_sources s ON s.slug = wk.source
ON CONFLICT DO NOTHING;

-- 3g. nrd → indicator_domains
-- Production data: HAS trailing dots.
INSERT INTO indicator_domains (source, domain, added_at)
SELECT s.id, RTRIM(n.domain, '.'), n.added_at
FROM nrd n
JOIN indicator_sources s ON s.slug = n.source
ON CONFLICT DO NOTHING;

-- 3h. threat_ips → indicator_ips
INSERT INTO indicator_ips (source, ip, added_at)
SELECT s.id, ti.ip, ti.added_at
FROM threat_ips ti
JOIN indicator_sources s ON s.slug = ti.source
ON CONFLICT DO NOTHING;

-- 3i. Migrate profile_filters: TEXT filter_id → UUID from filters.id
-- Old PK is (profile_id, filter_id) with filter_id as TEXT.
-- Need to: drop old PK+FK → add UUID column → map → swap → recreate PK+FK.

-- Drop old constraints
ALTER TABLE "public"."profile_filters"
  DROP CONSTRAINT "profile_filters_pkey";
ALTER TABLE "public"."profile_filters"
  DROP CONSTRAINT "profile_filters_filter_id_fkey";

-- Rename old column
ALTER TABLE "public"."profile_filters"
  RENAME COLUMN "filter_id" TO "old_filter_id";

-- Add new UUID column
ALTER TABLE "public"."profile_filters"
  ADD COLUMN "filter_id" uuid;

-- Map old TEXT → new UUID (filter_lists.id = slug in filters table, filter_lists.uuid = id in filters table)
UPDATE profile_filters pf
SET filter_id = f.id
FROM filters f
WHERE f.slug = pf.old_filter_id;

-- Delete unmapped rows (subscriptions to non-compilable sources like NRD/well-known)
DELETE FROM profile_filters WHERE filter_id IS NULL;

-- Drop old column, set NOT NULL, recreate constraints
ALTER TABLE "public"."profile_filters"
  DROP COLUMN "old_filter_id";
ALTER TABLE "public"."profile_filters"
  ALTER COLUMN "filter_id" SET NOT NULL;
ALTER TABLE "public"."profile_filters"
  ALTER COLUMN "added_at" SET DEFAULT now();
ALTER TABLE "public"."profile_filters"
  ADD CONSTRAINT "profile_filters_pkey" PRIMARY KEY ("profile_id", "filter_id");
ALTER TABLE "public"."profile_filters"
  ADD CONSTRAINT "profile_filters_filter_id_fkey"
  FOREIGN KEY ("filter_id") REFERENCES "public"."filters" ("id") ON DELETE CASCADE;

-- Phase 4: Drop old tables and enum
-- ============================================================

DROP TABLE IF EXISTS "public"."threat_asns";
DROP TABLE IF EXISTS "public"."threat_ips";
DROP TABLE IF EXISTS "public"."threat_feed";
DROP TABLE IF EXISTS "public"."nrd";
DROP TABLE IF EXISTS "public"."well_known_domains";
DROP TABLE IF EXISTS "public"."blocklist";
DROP TABLE IF EXISTS "public"."allowlist";
DROP TABLE IF EXISTS "public"."filter_lists";
DROP TYPE IF EXISTS "public"."filter_list_type";
