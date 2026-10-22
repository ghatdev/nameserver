-- Mark the pending hagezi-pro backlog as abandoned.
--
-- hagezi-pro is an ad/tracker blocklist. Draining it with
-- label_verdict = 'malicious' teaches the detector that CDN edges and
-- doubleclock-style domains are malicious, which is the exact
-- false-positive class we're trying to eliminate. PR-C removes
-- hagezi-pro from the injection slug map in autopull.rs, but the
-- ~31k rows already queued from 2026-04-20's initial pulls would
-- still drain through the new binary's scheduler and pollute training
-- unless we also clear the backlog. `abandoned` is the right terminal
-- state: no retries, visible to operators, reversible via a later UPDATE
-- if we ever decide to reinstate pro as a label source.
UPDATE injection_queue
   SET status = 'abandoned'::injection_status,
       last_error = 'source removed from injection (see PR-C, 2026-04-23)'
 WHERE source_slug = 'hagezi-pro'
   AND status IN ('pending', 'in_flight');
