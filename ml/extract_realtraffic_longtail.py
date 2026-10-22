"""Extract long-tail benign REGISTRABLES from real traffic.

Companion to `extract_realtraffic_benign.py`. That script harvests
hard-negative FQDNs from CDN sub-spaces of well-known registrables
(googlevideo subshards, akamai edge nodes, etc.). This script harvests
the *other* missing benign class: registrables that are neither in any
threat list NOR in Tranco/Majestic — long-tail Korean / business / niche
domains that show up in our own traffic and behave benignly across
many days.

Why this exists: the current detector dataset has ~96K negative
registrables, ALL of which are in Tranco ∪ Majestic (verified
2026-04-19). That makes `rep_is_well_known` a perfect shortcut for the
negative class. A model trained on it learns "well-known → benign"
rather than the §3.9 context-gate role intended in the design. Adding
high-confidence non-well-known benign registrables forces the model to
learn from inherent reputation features (days_since_first_seen,
total_flow_count, ns_observation_count, ns_trust) instead of the
list-membership shortcut.

Selection criteria (registrable-level):
- NOT in any of: hagezi-tif, hagezi-pro, hagezi-{light,normal},
  hagezi-dga-{7,14,30}d, hagezi-nrd-{7,14,21,28,35}d,
  digitalside-domains, phishing-db, threatview-c2, certpl,
  oisd-{big,small}
- NOT in tranco-100k or majestic-1m (those are already negatives via
  `import_benign_labels.py`)
- ≥ 7 distinct calendar days seen
- ≥ 50 PASS flows
- ≥ 1 distinct non-empty profile
- NOERROR-rate ≥ 50% (excludes pure-NXDOMAIN squat patterns)
- NOT already in incident_labels with verdict=malicious

Cap: 50k registrables, sorted by flow_count DESC. That gives a
roughly 1:2 ratio against the existing ~96K Tranco/Majestic negatives —
enough to break the perfect correlation without overwhelming the
popularity-based negatives.

Writes incident_labels (source='realtraffic_longtail', verdict='benign',
layer='dns'). The build_detector_dataset.py label-assignment treats any
benign source other than 'realtraffic' as registrable-level — so this
source name is intentionally NOT 'realtraffic'.

Run:
    uv run ml/extract_realtraffic_longtail.py
    uv run ml/extract_realtraffic_longtail.py --dry-run
    uv run ml/extract_realtraffic_longtail.py --cap 30000
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any

import clickhouse_connect
import psycopg2
import psycopg2.extras

DEFAULT_PG_URL = (
    "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
)
DEFAULT_CH_HOST = "localhost"
DEFAULT_CH_PORT = 18123
DEFAULT_CH_DB = "nameserver"

SOURCE_NAME = "realtraffic_longtail"

# Slugs whose member registrables are EXCLUDED from candidates. These
# are: every threat-list flavor we ingest + the popularity lists (which
# already carry benign labels).
EXCLUDE_SLUGS: list[str] = [
    "hagezi-tif",
    "hagezi-pro",
    "hagezi-light",
    "hagezi-normal",
    "hagezi-dga-7d",
    "hagezi-dga-14d",
    "hagezi-dga-30d",
    "hagezi-nrd-7d",
    "hagezi-nrd-14d",
    "hagezi-nrd-21d",
    "hagezi-nrd-28d",
    "hagezi-nrd-35d",
    "digitalside-domains",
    "phishing-db",
    "threatview-c2",
    "certpl",
    "oisd-big",
    "oisd-small",
    "tranco-100k",
    "majestic-1m",
]

DEFAULT_MIN_DAYS = 7
DEFAULT_MIN_FLOWS = 50
DEFAULT_MIN_PROFILES = 1
DEFAULT_MIN_NOERROR_RATIO = 0.5
DEFAULT_CAP = 50_000


def load_excluded_registrables(pg_url: str) -> set[str]:
    """Union of domains across every excluded slug."""
    excluded: set[str] = set()
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, slug FROM sources WHERE slug = ANY(%s)",
                (EXCLUDE_SLUGS,),
            )
            slug_ids = cur.fetchall()
            for src_id, slug in slug_ids:
                cur.execute(
                    "SELECT domain FROM indicator_domains WHERE source = %s",
                    (src_id,),
                )
                added = 0
                for (d,) in cur.fetchall():
                    if d not in excluded:
                        excluded.add(d)
                        added += 1
                print(f"     {slug:<22}  +{added:>8,}  (total {len(excluded):,})",
                      flush=True)
    return excluded


def load_malicious_registrables(pg_url: str) -> set[str]:
    """Belt-and-suspenders: also exclude anything anyone has labeled malicious."""
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT domain FROM incident_labels "
                "WHERE verdict = 'malicious' AND layer = 'dns'"
            )
            return {r[0] for r in cur.fetchall()}


def fetch_candidates(
    ch_client: Any,
    *,
    days: int,
    min_days: int,
    min_flows: int,
    min_profiles: int,
    min_noerror_ratio: float,
) -> list[tuple[str, int, int, int, float]]:
    """Aggregate flow_novelty x flows by registrable. Returns rows of:
    (registrable, flow_count, profile_count, distinct_days, noerror_ratio).

    Filters at CH level for efficiency; further set-membership filtering
    happens in Python.
    """
    query = f"""
        SELECT
            n.registrable                                        AS registrable,
            count()                                              AS flow_count,
            uniqExact(n.profile_id)                              AS profile_count,
            uniqExact(toDate(n.started_at))                      AS distinct_days,
            avg(if(f.rcode = 'NOERROR', 1.0, 0.0))               AS noerror_ratio
          FROM flow_novelty n
    INNER JOIN flows f ON n.flow_id = f.flow_id
         WHERE f.list_action = 'PASS'
           AND n.profile_id != ''
           AND n.registrable != ''
           AND n.started_at >= now() - INTERVAL {days} DAY
      GROUP BY n.registrable
        HAVING flow_count >= {min_flows}
           AND distinct_days >= {min_days}
           AND profile_count >= {min_profiles}
           AND noerror_ratio >= {min_noerror_ratio}
      ORDER BY flow_count DESC
    """
    print(f"[CH] querying flow_novelty x flows (days={days}, "
          f"min_flows={min_flows}, min_days={min_days}, "
          f"min_profiles={min_profiles}, min_noerror_ratio={min_noerror_ratio}) ...",
          flush=True)
    result = ch_client.query(query)
    return [
        (r[0], int(r[1]), int(r[2]), int(r[3]), float(r[4]))
        for r in result.result_rows
    ]


def filter_candidates(
    candidates: list[tuple[str, int, int, int, float]],
    excluded: set[str],
    malicious: set[str],
    cap: int,
) -> list[tuple[str, int, int, int, float]]:
    """Apply set-membership filters and cap, preserving flow_count DESC order."""
    selected: list[tuple[str, int, int, int, float]] = []
    n_excluded_listed = 0
    n_excluded_malicious = 0
    for reg, flows, profiles, days, noerror in candidates:
        if reg in excluded:
            n_excluded_listed += 1
            continue
        if reg in malicious:
            n_excluded_malicious += 1
            continue
        selected.append((reg, flows, profiles, days, noerror))
        if len(selected) >= cap:
            break
    print(f"[filter] dropped {n_excluded_listed:,} listed registrables, "
          f"{n_excluded_malicious:,} malicious-flagged",
          flush=True)
    return selected


def upsert_labels(
    pg_url: str,
    rows: list[tuple[str, int, int, int, float]],
) -> int:
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
                    reg,
                    SOURCE_NAME,
                    "dns",
                    now,
                    None,
                    "benign",
                    1.0,
                    "longtail_negative",
                    psycopg2.extras.Json(
                        {
                            "source_list": "realtraffic_longtail",
                            "flow_count": flows,
                            "profile_count": profiles,
                            "distinct_days": days,
                            "noerror_ratio": noerror,
                        }
                    ),
                )
                for reg, flows, profiles, days, noerror in rows
            ]
            psycopg2.extras.execute_values(cur, upsert_q, values, page_size=5000)
        conn.commit()
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute but don't write to incident_labels.")
    parser.add_argument("--days", type=int, default=90,
                        help="Window for CH aggregation (default 90, matches CH TTL)")
    parser.add_argument("--min-days", type=int, default=DEFAULT_MIN_DAYS)
    parser.add_argument("--min-flows", type=int, default=DEFAULT_MIN_FLOWS)
    parser.add_argument("--min-profiles", type=int, default=DEFAULT_MIN_PROFILES)
    parser.add_argument("--min-noerror-ratio", type=float,
                        default=DEFAULT_MIN_NOERROR_RATIO)
    parser.add_argument("--cap", type=int, default=DEFAULT_CAP)
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    ch = clickhouse_connect.get_client(
        host=os.environ.get("CH_HOST", DEFAULT_CH_HOST),
        port=int(os.environ.get("CH_PORT", str(DEFAULT_CH_PORT))),
        database=os.environ.get("CH_DB", DEFAULT_CH_DB),
    )

    print("[1/4] loading excluded registrable sets ...", flush=True)
    excluded = load_excluded_registrables(pg_url)
    print(f"     total exclusion set: {len(excluded):,} registrables",
          flush=True)

    print("[2/4] loading malicious incident labels ...", flush=True)
    malicious = load_malicious_registrables(pg_url)
    print(f"     {len(malicious):,} malicious DNS labels", flush=True)

    print("[3/4] fetching candidate registrables from CH ...", flush=True)
    candidates = fetch_candidates(
        ch,
        days=args.days,
        min_days=args.min_days,
        min_flows=args.min_flows,
        min_profiles=args.min_profiles,
        min_noerror_ratio=args.min_noerror_ratio,
    )
    print(f"     {len(candidates):,} CH-eligible registrables", flush=True)

    print("[4/4] applying exclusion + cap ...", flush=True)
    selected = filter_candidates(candidates, excluded, malicious, args.cap)
    print(f"     selected {len(selected):,} registrables (cap={args.cap:,})",
          flush=True)
    print("     top 10 by flow_count:", flush=True)
    for reg, flows, profiles, days, noerror in selected[:10]:
        print(f"       {reg:<40}  flows={flows:>6}  profiles={profiles}  "
              f"days={days:>3}  noerr={noerror:.2%}",
              flush=True)
    if selected:
        median_idx = len(selected) // 2
        med = selected[median_idx]
        tail = selected[-1]
        print(f"     median: {med[0]} (flows={med[1]}, days={med[3]})", flush=True)
        print(f"     tail:   {tail[0]} (flows={tail[1]}, days={tail[3]})", flush=True)

    if args.dry_run:
        print("\n[dry-run] not writing to incident_labels", flush=True)
        return 0

    upserted = upsert_labels(pg_url, selected)
    print(f"\nDONE upserted {upserted:,} rows into incident_labels "
          f"(source='{SOURCE_NAME}', layer='dns', verdict='benign')",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
