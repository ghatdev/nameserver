"""Import Hagezi TIF domains from indicator_domains into incident_labels.

Hagezi TIF (Threat Intelligence Feed) is already auto-pulled into
`indicator_domains` for blocklist use. For the detection-eval use case
(Pillar 4), we also want a copy in `incident_labels` so the eval framework
has a consistent shape across all label sources.

TIF is DNS-layer ground truth: every entry names an FQDN where the domain
itself is the IOC, not a URL path. Labels land with layer='dns', usable
directly by DNS detector recall + Δt computations.

`first_seen_at` carries the `added_at` from indicator_domains — when Hagezi
first listed the domain, not when we pulled it. This enables latency-gap
measurement: detectors that score a flow malicious before Hagezi listed it
produce a positive Δt (we beat the feed).

Run from your local machine via the PG tunnel:
    uv run ml/import_hagezi_tif.py

Idempotent (ON CONFLICT DO UPDATE).
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
SOURCE_NAME = "hagezi_tif"
SOURCE_SLUG = "hagezi-tif"
BATCH_SIZE = 5000


def resolve_source_id(cur: psycopg2.extensions.cursor, slug: str) -> str:
    cur.execute("SELECT id FROM sources WHERE slug = %s", (slug,))
    row = cur.fetchone()
    if row is None:
        raise RuntimeError(f"source slug not found: {slug}")
    return row[0]


def import_tif(pg_url: str, limit: int | None = None) -> tuple[int, int]:
    """Copy Hagezi TIF entries from indicator_domains -> incident_labels.

    Returns (read, inserted_or_updated)."""
    now = datetime.now(timezone.utc)
    read = 0
    upserted = 0

    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            source_id = resolve_source_id(cur, SOURCE_SLUG)

            count_q = "SELECT COUNT(*) FROM indicator_domains WHERE source = %s"
            cur.execute(count_q, (source_id,))
            count_row = cur.fetchone()
            if count_row is None:
                raise RuntimeError("count query returned no row")
            total = count_row[0]
            print(f"[pg] hagezi-tif has {total:,} domains in indicator_domains",
                  flush=True)

            select_q = """
                SELECT domain, added_at
                  FROM indicator_domains
                 WHERE source = %s
              ORDER BY added_at
            """
            params: tuple = (source_id,)
            if limit is not None:
                select_q += " LIMIT %s"
                params = (source_id, limit)

            cur.execute(select_q, params)

            upsert_q = """
                INSERT INTO incident_labels
                    (domain, source, layer, labeled_at, first_seen_at,
                     verdict, confidence, threat_type, extra)
                VALUES %s
                ON CONFLICT (domain, source) DO UPDATE SET
                    layer         = EXCLUDED.layer,
                    labeled_at    = EXCLUDED.labeled_at,
                    first_seen_at = EXCLUDED.first_seen_at,
                    verdict       = EXCLUDED.verdict,
                    threat_type   = EXCLUDED.threat_type,
                    extra         = EXCLUDED.extra
            """

            with conn.cursor() as write_cur:
                batch: list[tuple] = []
                while True:
                    rows = cur.fetchmany(BATCH_SIZE)
                    if not rows:
                        break
                    for domain, added_at in rows:
                        read += 1
                        batch.append((
                            domain,
                            SOURCE_NAME,
                            "dns",
                            now,
                            added_at,
                            "malicious",
                            None,
                            "threat_intel",
                            psycopg2.extras.Json({"hagezi_list": "tif"}),
                        ))
                    psycopg2.extras.execute_values(
                        write_cur, upsert_q, batch, page_size=BATCH_SIZE,
                    )
                    upserted += len(batch)
                    batch.clear()
                    if read % (BATCH_SIZE * 10) == 0:
                        print(f"  ... {read:,} / {total:,}", flush=True)

        conn.commit()

    return read, upserted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap rows read for smoke tests; omit for full import.",
    )
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    read, upserted = import_tif(pg_url, limit=args.limit)
    print(f"read={read:,} upserted={upserted:,}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
