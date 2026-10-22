-- Create user "nameserver"
CREATE ROLE "nameserver" WITH LOGIN;
-- Create user "nameserver_admin"
CREATE ROLE "nameserver_admin" WITH LOGIN;
-- Grant on schema "public" to "nameserver"
GRANT CREATE, USAGE ON SCHEMA "public" TO "nameserver";
-- Grant on schema "public" to "nameserver_admin"
GRANT CREATE, USAGE ON SCHEMA "public" TO "nameserver_admin";
-- Create enum type "filter_type"
CREATE TYPE "public"."filter_type" AS ENUM ('block', 'allow');
-- Create enum type "output_format"
CREATE TYPE "public"."output_format" AS ENUM ('xor', 'fst', 'ipf');
-- Create enum type "list_type"
CREATE TYPE "public"."list_type" AS ENUM ('allowlist', 'blocklist');
-- Modify "filters" table
ALTER TABLE "public"."filters" DROP CONSTRAINT "filters_filter_type_check", DROP CONSTRAINT "filters_output_format_check", ALTER COLUMN "filter_type" TYPE "public"."filter_type" USING "filter_type"::"public"."filter_type", ALTER COLUMN "output_format" TYPE "public"."output_format" USING "output_format"::"public"."output_format";
-- Modify "profile_custom_entries" table
ALTER TABLE "public"."profile_custom_entries" DROP CONSTRAINT "profile_custom_entries_list_type_check", ALTER COLUMN "list_type" TYPE "public"."list_type" USING "list_type"::"public"."list_type";
