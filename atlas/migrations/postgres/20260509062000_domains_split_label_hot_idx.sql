-- atlas:txmode none

-- Partial expression index for similarity::search_exact_label.
-- The IN-subquery already hits idx_ind_domains_label on
-- indicator_domains, but the UNION's other branch was seqscanning
-- ~3M rows in `domains` to find <10 matches per call. EXPLAIN ANALYZE
-- showed Parallel Seq Scan filtering ~994k rows per worker.
--
-- Built CONCURRENTLY to avoid blocking writes on the hot domains
-- table (~5M+ writes/day from flow processing). txmode=none required
-- because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_domains_split_label_hot
    ON domains (split_part(domain, '.', 1))
    WHERE query_count >= 5;
