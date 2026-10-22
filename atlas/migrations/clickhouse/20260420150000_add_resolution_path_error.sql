ALTER TABLE `flows` ADD COLUMN IF NOT EXISTS `resolution_path.error` Array(LowCardinality(String)) AFTER `resolution_path.ms`;
