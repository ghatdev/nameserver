ALTER TABLE `flows` ADD COLUMN IF NOT EXISTS `servfail_reason` LowCardinality(String) DEFAULT '' AFTER `dnssec_failure_reason`;
