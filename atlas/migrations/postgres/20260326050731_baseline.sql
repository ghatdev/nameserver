-- Create "geo_entries" table
CREATE TABLE "public"."geo_entries" (
  "start_ip" text NOT NULL,
  "end_ip" text NOT NULL,
  "country" character(2) NOT NULL,
  "ip_version" smallint NOT NULL,
  "rir" text NOT NULL,
  "asn" integer NOT NULL DEFAULT 0,
  "asn_desc" text NULL,
  PRIMARY KEY ("start_ip", "ip_version")
);
-- Create index "idx_geo_lookup" to table: "geo_entries"
CREATE INDEX "idx_geo_lookup" ON "public"."geo_entries" ("ip_version", "start_ip");
-- Create "ips" table
CREATE TABLE "public"."ips" (
  "ip" inet NOT NULL,
  "first_seen" timestamptz NOT NULL,
  "last_seen" timestamptz NOT NULL,
  "geo_country" character(2) NULL,
  "geo_city" text NULL,
  "asn_number" integer NULL,
  "asn_org" text NULL,
  "is_cdn" boolean NOT NULL DEFAULT false,
  "is_bulletproof" boolean NOT NULL DEFAULT false,
  "ptr_record" text NULL,
  "ptr_matches" boolean NULL,
  "domain_count" integer NOT NULL DEFAULT 0,
  "malicious_count" integer NOT NULL DEFAULT 0,
  "blocklist_json" jsonb NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("ip")
);
-- Create enum type "block_mode"
CREATE TYPE "public"."block_mode" AS ENUM ('nxdomain', 'redirect_ip');
-- Create "allowlist" table
CREATE TABLE "public"."allowlist" (
  "domain" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  "source" text NOT NULL DEFAULT 'manual',
  PRIMARY KEY ("domain")
);
-- Create "blocklist" table
CREATE TABLE "public"."blocklist" (
  "domain" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  "source" text NOT NULL,
  PRIMARY KEY ("domain")
);
-- Create "domain_ips" table
CREATE TABLE "public"."domain_ips" (
  "domain" text NOT NULL,
  "ip" inet NOT NULL,
  "first_seen" timestamptz NOT NULL,
  "last_seen" timestamptz NOT NULL,
  PRIMARY KEY ("domain", "ip")
);
-- Create "domain_ns_map" table
CREATE TABLE "public"."domain_ns_map" (
  "registrable_domain" text NOT NULL,
  "ns_domain" text NOT NULL,
  "first_seen" timestamptz NOT NULL,
  "last_seen" timestamptz NOT NULL,
  "observation_count" integer NOT NULL DEFAULT 1,
  PRIMARY KEY ("registrable_domain", "ns_domain")
);
-- Create index "idx_ns_map_ns" to table: "domain_ns_map"
CREATE INDEX "idx_ns_map_ns" ON "public"."domain_ns_map" ("ns_domain");
-- Create "domains" table
CREATE TABLE "public"."domains" (
  "domain" text NOT NULL,
  "first_seen" timestamptz NOT NULL,
  "last_seen" timestamptz NOT NULL,
  "query_count" integer NOT NULL DEFAULT 0,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("domain")
);
-- Create enum type "indicator_type"
CREATE TYPE "public"."indicator_type" AS ENUM ('domain', 'ip');
-- Create "feeds" table
CREATE TABLE "public"."feeds" (
  "id" bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
  "source" text NOT NULL,
  "fetched_at" timestamptz NOT NULL,
  "indicator" text NOT NULL,
  "ind_type" "public"."indicator_type" NOT NULL DEFAULT 'domain',
  "category" text NOT NULL,
  "confidence" real NULL,
  "processed" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id")
);
-- Create index "idx_feeds_indicator" to table: "feeds"
CREATE INDEX "idx_feeds_indicator" ON "public"."feeds" ("indicator");
-- Create "well_known_domains" table
CREATE TABLE "public"."well_known_domains" (
  "domain" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  "source" text NOT NULL,
  PRIMARY KEY ("domain")
);
-- Create index "idx_well_known_source" to table: "well_known_domains"
CREATE INDEX "idx_well_known_source" ON "public"."well_known_domains" ("source");
-- Create "nrd" table
CREATE TABLE "public"."nrd" (
  "domain" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  "source" text NOT NULL,
  PRIMARY KEY ("domain")
);
-- Create index "idx_nrd_source" to table: "nrd"
CREATE INDEX "idx_nrd_source" ON "public"."nrd" ("source");
-- Create enum type "filter_list_type"
CREATE TYPE "public"."filter_list_type" AS ENUM ('allowlist', 'blocklist', 'threat_feed', 'well_known', 'nrd', 'internal');
-- Create "threat_ips" table
CREATE TABLE "public"."threat_ips" (
  "ip" inet NOT NULL,
  "source" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  PRIMARY KEY ("ip", "source")
);
-- Create index "idx_threat_ips_ip" to table: "threat_ips"
CREATE INDEX "idx_threat_ips_ip" ON "public"."threat_ips" ("ip");
-- Create "threat_feed" table
CREATE TABLE "public"."threat_feed" (
  "domain" text NOT NULL,
  "source" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  PRIMARY KEY ("domain", "source")
);
-- Create index "idx_threat_feed_domain" to table: "threat_feed"
CREATE INDEX "idx_threat_feed_domain" ON "public"."threat_feed" ("domain");
-- Create "profiles" table
CREATE TABLE "public"."profiles" (
  "id" text NOT NULL,
  "display_name" text NOT NULL,
  "block_mode" "public"."block_mode" NOT NULL DEFAULT 'nxdomain',
  "redirect_ip" inet NULL,
  "is_default" boolean NOT NULL DEFAULT false,
  "enabled" boolean NOT NULL DEFAULT true,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("id")
);
-- Create "rdap_cache" table
CREATE TABLE "public"."rdap_cache" (
  "registrable_domain" text NOT NULL,
  "creation_date" text NULL,
  "expiration_date" text NULL,
  "registrar" text NULL,
  "status_json" jsonb NULL,
  "nameservers_json" jsonb NULL,
  "privacy_protected" boolean NULL DEFAULT false,
  "lookup_method" text NOT NULL,
  "fetched_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("registrable_domain")
);
-- Create "resolution_history" table
CREATE TABLE "public"."resolution_history" (
  "id" bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
  "domain" text NOT NULL,
  "resolved_at" timestamptz NOT NULL,
  "ips" jsonb NOT NULL,
  "ttl" integer NOT NULL,
  "cname_chain" jsonb NULL,
  "ns_servers" jsonb NULL,
  "mx_records" jsonb NULL,
  "dnssec_status" text NOT NULL,
  "resolve_ms" integer NOT NULL,
  "a_record_count" smallint NOT NULL DEFAULT 0,
  "has_txt" boolean NOT NULL DEFAULT false,
  "referral_hop_count" smallint NOT NULL DEFAULT 0,
  "soa_json" jsonb NULL,
  PRIMARY KEY ("id")
);
-- Create index "idx_rh_domain" to table: "resolution_history"
CREATE INDEX "idx_rh_domain" ON "public"."resolution_history" ("domain", "resolved_at" DESC);
-- Create "profile_custom_entries" table
CREATE TABLE "public"."profile_custom_entries" (
  "profile_id" text NOT NULL,
  "domain" text NOT NULL,
  "list_type" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  PRIMARY KEY ("profile_id", "domain", "list_type"),
  CONSTRAINT "profile_custom_entries_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "profile_custom_entries_list_type_check" CHECK (list_type = ANY (ARRAY['allowlist'::text, 'blocklist'::text]))
);
-- Create "filter_lists" table
CREATE TABLE "public"."filter_lists" (
  "id" text NOT NULL,
  "display_name" text NOT NULL,
  "url" text NOT NULL,
  "list_type" "public"."filter_list_type" NOT NULL,
  "format" text NOT NULL DEFAULT 'domains',
  "refresh_interval_secs" integer NOT NULL DEFAULT 86400,
  "last_pull_at" timestamptz NULL,
  "last_checksum" text NULL,
  "last_entry_count" integer NULL,
  "enabled" boolean NOT NULL DEFAULT true,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "categories" text NOT NULL DEFAULT '',
  "indicator_type" "public"."indicator_type" NOT NULL DEFAULT 'domain',
  "uuid" uuid NULL,
  PRIMARY KEY ("id")
);
-- Create "profile_filters" table
CREATE TABLE "public"."profile_filters" (
  "profile_id" text NOT NULL,
  "filter_id" text NOT NULL,
  "added_at" timestamptz NOT NULL,
  PRIMARY KEY ("profile_id", "filter_id"),
  CONSTRAINT "profile_filters_filter_id_fkey" FOREIGN KEY ("filter_id") REFERENCES "public"."filter_lists" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "profile_filters_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
