-- Add drain-priority column to injection_queue and make the pending-row
-- scan index composite on (priority, scheduled_for) so the scheduler's
-- ORDER BY picks TIF before pro without a sort step.
--
-- Priority scheme: lower = sooner. Values are aligned with
-- autopull::slug_to_priority in the control binary:
--   10 — hagezi-tif, hagezi-dga-*        (direct malicious signal)
--   50 — reserved for benign-injected    (tranco sampler, PR-C)
--  100 — hagezi-pro and everything else  (default)

ALTER TABLE injection_queue
    ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

-- Backfill existing rows so the current backlog respects the new
-- ordering on the very next scheduler tick.
UPDATE injection_queue
   SET priority = 10
 WHERE source_slug IN ('hagezi-tif', 'hagezi-dga-7d', 'hagezi-dga-14d', 'hagezi-dga-30d')
   AND priority <> 10;

-- Rebuild the pending-scan index to include priority as the leading
-- column. The drain query's new ORDER BY is (priority, scheduled_for);
-- a single composite partial index covers it without a sort.
DROP INDEX IF EXISTS idx_iq_pending_sched;
CREATE INDEX IF NOT EXISTS idx_iq_pending_sched
    ON injection_queue (priority, scheduled_for)
    WHERE status = 'pending';
