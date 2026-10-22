-- Drop legacy feeds table (replaced by filter list system → threat_feed table).
-- All 5.3K rows were urlhaus entries with processed=false, never consumed.
DROP TABLE IF EXISTS feeds;
