ALTER TABLE `ml_predictions` ADD COLUMN `ns_trust` LowCardinality(String) DEFAULT '' AFTER `override_rule`;
ALTER TABLE `ml_predictions` ADD COLUMN `dnssec_adj` Float32 DEFAULT 0 AFTER `ns_trust`;
ALTER TABLE `ml_predictions` ADD COLUMN `ns_adj` Float32 DEFAULT 0 AFTER `dnssec_adj`;
ALTER TABLE `ml_predictions` ADD COLUMN `similarity_adj` Float32 DEFAULT 0 AFTER `ns_adj`;
ALTER TABLE `ml_predictions` ADD COLUMN `hosting_adj` Float32 DEFAULT 0 AFTER `similarity_adj`;
ALTER TABLE `ml_predictions` ADD COLUMN `nrd_adj` Float32 DEFAULT 0 AFTER `hosting_adj`;
ALTER TABLE `ml_predictions` ADD COLUMN `temporal_adj` Float32 DEFAULT 0;
