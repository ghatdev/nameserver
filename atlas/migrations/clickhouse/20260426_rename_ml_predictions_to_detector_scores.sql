-- Unify the ML-based detector storage under a single canonical table.
--
-- Before: ml_predictions (live writer, ~90 days of MlPrediction rows) +
--         a legacy detector_scores from the deleted multi-detector
--         framework (PR#2 deleted the writer; rows are dormant noise
--         from the placeholder NoveltyHeuristicV0).
-- After:  detector_scores carries the renamed ml_predictions content;
--         the legacy detector_scores is dropped.
--
-- Atomic at the SQL level via CH's two-table RENAME. The brief writer-
-- down window between this DROP+RENAME and the new binary's deploy is
-- the only data-loss risk: the running binary's CH inserter will fail
-- INSERT INTO ml_predictions for ~5-30s, retry, and recover once the
-- new binary lands. Acceptable because predictions are derived data
-- (regenerable from CH `flows` if ever needed); core flow data is
-- untouched.

DROP TABLE IF EXISTS nameserver.detector_scores;

RENAME TABLE nameserver.ml_predictions TO nameserver.detector_scores;
