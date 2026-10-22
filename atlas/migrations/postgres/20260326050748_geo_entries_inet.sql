-- Modify "geo_entries" table: TEXT -> INET for correct IP range comparison
ALTER TABLE "public"."geo_entries" ALTER COLUMN "start_ip" TYPE inet USING start_ip::inet, ALTER COLUMN "end_ip" TYPE inet USING end_ip::inet;
