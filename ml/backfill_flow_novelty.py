"""Retroactively compute flow_novelty rows for historical flows.

flow_novelty is written by the Rust pipeline at ingest time (see
`processing.rs::spawn_novelty_inserter`), so only flows observed after the
pipeline deployed on 2026-04-18 22:52 KST have novelty rows. Historical
flows (~3.6M, going back to 2026-03-07) are not covered, which blocks
Pillar 3 eval: TIF-intersecting flows are overwhelmingly historical.

This script backfills flow_novelty for the gap:

 1. Compute per-domain (first_started_at, first_flow_id) via a CH window
    query. This is the source of truth for "network first contact" — PG
    `domains.first_seen` was bulk-bootstrapped on 2026-03-13 and is older
    than CH flows (Mar 7), so PG timestamps are unreliable.
 2. Pull distinct CH flow domains and compute registrable via tldextract
    with `include_psl_private_domains=True`. Matches Rust's SuffixSet for
    98.3% of live domains; 1.7% disagree on AWS/CDN private-suffix edge
    cases (documented trade-off, acceptable for one-time backfill).
 3. Stream (flow_id, started_at, domain, profile_id, geo_asn) from CH for
    flows NOT yet in flow_novelty.
 4. Derive per row:
      is_first_contact      = (flow_id == domain.first_flow_id)     # exactly 1 per domain
      first_seen_in_network = domain.first_started_at
      age_minutes_at_flow   = max(0, (started_at − first_started_at) / 60)
 5. Batch INSERT into flow_novelty via clickhouse-connect.

Idempotent — processes only flows missing from flow_novelty. Safe to re-run.

Run from your local machine via PG (5433, unused) + CH HTTP (18123) tunnels:
    uv run ml/backfill_flow_novelty.py --dry-run --limit 1000
    uv run ml/backfill_flow_novelty.py
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any

import clickhouse_connect
import tldextract

DEFAULT_CH_HOST = "localhost"
DEFAULT_CH_PORT = 18123
DEFAULT_CH_DB = "nameserver"

BATCH_SIZE = 20_000


def load_first_flow_per_domain(
    ch_client: Any,
) -> dict[str, tuple[str, datetime]]:
    """Return domain → (first_flow_id, first_started_at).

    Earliest (started_at, flow_id) pair per domain. flow_id is the tiebreaker
    when multiple flows share the same started_at (rare but possible for
    concurrent queries from different clients)."""
    print("[ch] computing first flow per domain ...", flush=True)
    q = """
        SELECT
            domain,
            argMin(flow_id, (started_at, flow_id)) AS first_flow_id,
            min(started_at) AS first_started_at
          FROM flows
      GROUP BY domain
    """
    res = ch_client.query(q)
    mapping: dict[str, tuple[str, datetime]] = {
        row[0]: (str(row[1]), row[2]) for row in res.result_rows
    }
    print(f"[ch] mapped {len(mapping):,} domains", flush=True)
    return mapping


def build_registrable_map(
    ch_client: Any, ext: tldextract.TLDExtract
) -> dict[str, str]:
    """Precompute registrable for every distinct CH-flows domain. Faster
    than per-row tldextract since many flows repeat the same domain."""
    print("[ch] pulling distinct flow domains ...", flush=True)
    q = "SELECT DISTINCT domain FROM flows"
    res = ch_client.query(q)
    domains = [row[0] for row in res.result_rows]
    print(f"[ch] {len(domains):,} distinct domains — computing registrables",
          flush=True)
    mapping: dict[str, str] = {}
    for d in domains:
        clean = d.rstrip(".")
        e = ext(clean)
        if e.suffix:
            mapping[d] = f"{e.domain}.{e.suffix}"
        else:
            mapping[d] = e.domain or ""
    return mapping


def stream_missing_flows(
    ch_client: Any, limit: int | None
) -> Any:
    """Yield per-row tuples for flows not yet in flow_novelty. Uses a
    streaming query so memory stays bounded regardless of flow volume."""
    null_uuid = "toUUID('00000000-0000-0000-0000-000000000000')"
    q = f"""
        SELECT
            f.flow_id,
            f.started_at,
            f.domain,
            f.profile_id,
            f.geo_asn
          FROM flows f
     LEFT JOIN flow_novelty n ON f.flow_id = n.flow_id
         WHERE n.flow_id = {null_uuid}
    """
    if limit is not None:
        q += f" LIMIT {limit}"
    return ch_client.query_rows_stream(q)


def insert_batch(ch_client: Any, rows: list[tuple]) -> None:
    if not rows:
        return
    ch_client.insert(
        "flow_novelty",
        rows,
        column_names=[
            "flow_id", "started_at", "domain", "registrable",
            "profile_id", "geo_asn", "is_first_contact",
            "first_seen_in_network", "age_minutes_at_flow",
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None,
                        help="Cap rows processed for smoke tests.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute rows but don't insert.")
    args = parser.parse_args()

    ch_host = os.environ.get("CH_HOST", DEFAULT_CH_HOST)
    ch_port = int(os.environ.get("CH_PORT", str(DEFAULT_CH_PORT)))
    ch_db = os.environ.get("CH_DB", DEFAULT_CH_DB)

    ch = clickhouse_connect.get_client(host=ch_host, port=ch_port, database=ch_db)
    ch_writer = clickhouse_connect.get_client(
        host=ch_host, port=ch_port, database=ch_db,
    )
    ext = tldextract.TLDExtract(include_psl_private_domains=True)

    first_by_domain = load_first_flow_per_domain(ch)
    reg_map = build_registrable_map(ch, ext)

    batch: list[tuple] = []
    processed = 0
    inserted = 0
    first_contact_count = 0

    print("[ch] streaming flows missing from flow_novelty ...", flush=True)
    with stream_missing_flows(ch, args.limit) as rows:
        for flow_id, started_at, domain, profile_id, geo_asn in rows:
            processed += 1
            registrable = reg_map.get(domain, "")
            mapping = first_by_domain.get(domain)
            if mapping is None:
                # Shouldn't happen — CH has the flow so CH-derived first must exist.
                continue
            first_flow_id, first_started_at = mapping

            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            if first_started_at.tzinfo is None:
                first_started_at = first_started_at.replace(tzinfo=timezone.utc)

            is_first_contact = 1 if str(flow_id) == first_flow_id else 0
            age_min = max(
                0,
                int((started_at - first_started_at).total_seconds() // 60),
            )

            if is_first_contact:
                first_contact_count += 1

            batch.append((
                flow_id,
                started_at,
                domain,
                registrable,
                profile_id or "",
                int(geo_asn or 0),
                is_first_contact,
                first_started_at,
                age_min,
            ))

            if len(batch) >= BATCH_SIZE:
                if not args.dry_run:
                    insert_batch(ch_writer, batch)
                inserted += len(batch)
                batch.clear()
                print(f"  processed={processed:,} inserted={inserted:,} "
                      f"first_contacts={first_contact_count:,}", flush=True)

    if batch:
        if not args.dry_run:
            insert_batch(ch_writer, batch)
        inserted += len(batch)

    print(f"\nDONE processed={processed:,} inserted={inserted:,} "
          f"first_contacts={first_contact_count:,} dry_run={args.dry_run}",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
