"""Extract hard-negative FQDNs from real traffic for detector training.

Generic popularity lists (Tranco/Majestic) cover registrables but not the
lexically-complex FQDNs those registrables host — `r1---sn-oguelnl7.
googlevideo.com`, `e96071.a.akamaiedge.net`, `d1h1lmbujtfe.cloudfront.net`
and so on. Without these as explicit negatives, a supervised detector
over-fires on lexical weirdness. This is the CDN-subdomain FP class the
existing phishing scorer has been fighting.

Criteria (per docs/detector-lightgbm-design.md §4.2):
- `registrable ∈ Tranco top 10k` (strong popularity floor)
- FQDN seen in ≥ 20 flows
- FQDN seen from ≥ 2 profiles (real use, not one-off)
- `length(fqdn) > 30` OR lexically non-trivial (digit-heavy or high entropy)
- FQDN not in incident_labels as malicious (safety check)

Cap: 50k FQDNs total, max 500 per registrable (stratified — no single CDN
dominates).

Writes to `incident_labels` as (domain, source='realtraffic',
verdict='benign', layer='dns', confidence=1.0). Idempotent via ON CONFLICT.

Run:
    uv run ml/extract_realtraffic_benign.py
    uv run ml/extract_realtraffic_benign.py --dry-run
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

import clickhouse_connect
import psycopg2
import psycopg2.extras

DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
SOURCE_NAME = "realtraffic"
TRANCO_SLUG = "tranco-100k"
TRANCO_RANK_CAP = 10_000
FQDN_CAP = 50_000
PER_REGISTRABLE_CAP = 500


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    h = 0.0
    for k in counts.values():
        p = k / n
        h -= p * math.log2(p)
    return h


def is_lexically_nontrivial(fqdn: str) -> bool:
    """Filter for FQDNs that would trip a lexical detector — the ones
    whose appearance as benign in training matters most."""
    if len(fqdn) > 30:
        return True
    leftmost = fqdn.split(".", 1)[0]
    if not leftmost:
        return False
    digit_ratio = sum(c.isdigit() for c in leftmost) / max(1, len(leftmost))
    if digit_ratio > 0.3:
        return True
    if shannon_entropy(leftmost) > 3.5:
        return True
    return False


def load_tranco_top_10k(pg_url: str) -> list[str]:
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM sources WHERE slug = %s", (TRANCO_SLUG,))
            row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"source slug not found: {TRANCO_SLUG}")
            tranco_id = row[0]
            cur.execute(
                """
                SELECT domain FROM indicator_domains
                 WHERE source = %s
                   AND rank IS NOT NULL
                   AND rank <= %s
                 ORDER BY rank
                """,
                (tranco_id, TRANCO_RANK_CAP),
            )
            return [r[0] for r in cur.fetchall()]


def load_malicious_set(pg_url: str) -> set[str]:
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT domain FROM incident_labels "
                "WHERE verdict='malicious' AND layer='dns'"
            )
            return {r[0] for r in cur.fetchall()}


def fetch_candidates(
    ch_client,
    tranco10k: list[str],
) -> list[tuple[str, str, int, int]]:
    """Return (fqdn_cleaned, registrable, flow_count, profile_count).

    10k-element IN list is too large for clickhouse-connect's parameter
    encoding (HTTP form limit). Work around it by materializing
    tranco10k as a temporary CH table, joining, and dropping."""
    ch_client.command(
        "CREATE TABLE IF NOT EXISTS tmp_tranco10k (d String) ENGINE = Memory"
    )
    ch_client.command("TRUNCATE TABLE tmp_tranco10k")
    try:
        ch_client.insert(
            "tmp_tranco10k",
            [[d] for d in tranco10k],
            column_names=["d"],
        )

        query = """
            SELECT
                n.domain          AS domain,
                n.registrable     AS registrable,
                count()           AS flow_count,
                uniqExact(profile_id) AS profile_count
              FROM flow_novelty n
             WHERE registrable IN (SELECT d FROM tmp_tranco10k)
               AND profile_id != ''
          GROUP BY domain, registrable
            HAVING flow_count >= 20
               AND profile_count >= 2
          ORDER BY flow_count DESC
        """
        result = ch_client.query(query)
        return [(row[0], row[1], row[2], row[3]) for row in result.result_rows]
    finally:
        ch_client.command("DROP TABLE IF EXISTS tmp_tranco10k")


def stratify_and_cap(
    candidates: list[tuple[str, str, int, int]],
    malicious: set[str],
) -> list[tuple[str, str]]:
    """Apply lexical filter + malicious exclusion + per-registrable cap +
    global cap. Returns (fqdn_cleaned, registrable) tuples."""
    per_reg: dict[str, int] = defaultdict(int)
    selected: list[tuple[str, str]] = []

    for fqdn_dotted, registrable, _flow_count, _profile_count in candidates:
        if len(selected) >= FQDN_CAP:
            break
        fqdn = fqdn_dotted.rstrip(".")
        if fqdn in malicious:
            continue
        if not is_lexically_nontrivial(fqdn):
            continue
        if per_reg[registrable] >= PER_REGISTRABLE_CAP:
            continue
        per_reg[registrable] += 1
        selected.append((fqdn, registrable))

    return selected


def upsert_labels(pg_url: str, rows: list[tuple[str, str]]) -> int:
    now = datetime.now(timezone.utc)
    upsert_q = """
        INSERT INTO incident_labels
            (domain, source, layer, labeled_at, first_seen_at,
             verdict, confidence, threat_type, extra)
        VALUES %s
        ON CONFLICT (domain, source) DO UPDATE SET
            layer       = EXCLUDED.layer,
            labeled_at  = EXCLUDED.labeled_at,
            verdict     = EXCLUDED.verdict,
            confidence  = EXCLUDED.confidence,
            extra       = EXCLUDED.extra
    """
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            values = [
                (
                    fqdn,
                    SOURCE_NAME,
                    "dns",
                    now,
                    None,
                    "benign",
                    1.0,
                    "hard_negative",
                    psycopg2.extras.Json(
                        {"source_list": "realtraffic", "registrable": reg}
                    ),
                )
                for fqdn, reg in rows
            ]
            psycopg2.extras.execute_values(cur, upsert_q, values, page_size=5000)
        conn.commit()
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute but don't write.")
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    ch = clickhouse_connect.get_client(
        host="localhost", port=18123, database="nameserver",
    )

    print("[1/4] loading tranco top 10k ...", flush=True)
    tranco10k = load_tranco_top_10k(pg_url)
    print(f"     {len(tranco10k):,} registrables", flush=True)

    print("[2/4] loading malicious FQDN set ...", flush=True)
    malicious = load_malicious_set(pg_url)
    print(f"     {len(malicious):,} malicious FQDNs (for exclusion)", flush=True)

    print("[3/4] fetching candidate FQDNs from CH ...", flush=True)
    candidates = fetch_candidates(ch, tranco10k)
    print(f"     {len(candidates):,} candidates "
          f"(≥20 flows ∧ ≥2 profiles ∧ registrable ∈ tranco-10k)",
          flush=True)

    print("[4/4] applying lexical filter + stratified cap ...", flush=True)
    selected = stratify_and_cap(candidates, malicious)
    per_reg = defaultdict(int)
    for _, reg in selected:
        per_reg[reg] += 1
    print(f"     selected {len(selected):,} FQDNs across "
          f"{len(per_reg):,} registrables", flush=True)
    print(f"     top 10 registrables by count:", flush=True)
    for reg, n in sorted(per_reg.items(), key=lambda x: -x[1])[:10]:
        print(f"       {reg:<40} {n:>5}", flush=True)

    if args.dry_run:
        print("\n[dry-run] not writing to incident_labels", flush=True)
        return 0

    upserted = upsert_labels(pg_url, selected)
    print(f"\nDONE upserted {upserted:,} rows into incident_labels "
          f"(source='realtraffic', layer='dns', verdict='benign')",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
