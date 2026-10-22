"""Import Tranco + Majestic top lists into incident_labels as benign ground truth.

Supervised detectors need both positive (malicious) and negative (benign) classes.
Hagezi TIF gives us 1.11M DNS-layer positives; without an explicit negative class,
the model learns only what's-likely-malicious, not what's-likely-benign. This
script copies the two top-million registrable lists into incident_labels with
verdict='benign' so the eval + future supervised training can treat them as a
clean negative class.

Strategy:
- `tranco-100k` and `majestic-1m` are pulled into `indicator_domains` by the
  autopull cycle. Both list registrables (roughly: the top-ranked domains by
  distinct visits and inbound links respectively).
- Mark every entry layer='dns', verdict='benign', confidence=1.0. Source is
  the list's slug so the same registrable can be labeled by both.
- `first_seen_at` is null — Tranco/Majestic don't carry per-entry dates (the
  rank is the signal).

Idempotent via ON CONFLICT DO UPDATE.

Run:
    uv run ml/import_benign_labels.py
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
BATCH_SIZE = 5000

# (source_slug_in_indicator_domains, incident_labels_source, threat_type)
BENIGN_SOURCES = [
    ("tranco-100k", "tranco", "well_known"),
    ("majestic-1m", "majestic", "well_known"),
]


def resolve_source_id(cur: psycopg2.extensions.cursor, slug: str) -> str:
    cur.execute("SELECT id FROM sources WHERE slug = %s", (slug,))
    row = cur.fetchone()
    if row is None:
        raise RuntimeError(f"source slug not found: {slug}")
    return row[0]


def import_benign(pg_url: str, slug: str, out_source: str,
                  threat_type: str) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    read = 0
    upserted = 0

    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            source_id = resolve_source_id(cur, slug)

            cur.execute(
                "SELECT COUNT(*) FROM indicator_domains WHERE source = %s",
                (source_id,),
            )
            count_row = cur.fetchone()
            if count_row is None:
                raise RuntimeError("count query returned no row")
            total = count_row[0]
            print(f"[pg] {slug} has {total:,} domains", flush=True)

            cur.execute(
                "SELECT domain FROM indicator_domains WHERE source = %s",
                (source_id,),
            )

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
                    threat_type = EXCLUDED.threat_type,
                    extra       = EXCLUDED.extra
            """

            with conn.cursor() as write_cur:
                batch: list[tuple] = []
                while True:
                    rows = cur.fetchmany(BATCH_SIZE)
                    if not rows:
                        break
                    for (domain,) in rows:
                        read += 1
                        batch.append((
                            domain,
                            out_source,
                            "dns",
                            now,
                            None,
                            "benign",
                            1.0,
                            threat_type,
                            psycopg2.extras.Json({"list": slug}),
                        ))
                    psycopg2.extras.execute_values(
                        write_cur, upsert_q, batch, page_size=BATCH_SIZE,
                    )
                    upserted += len(batch)
                    batch.clear()
                    if read % (BATCH_SIZE * 20) == 0:
                        print(f"  ... {read:,} / {total:,}", flush=True)
        conn.commit()
    return read, upserted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", type=str, default=None,
                        help="Comma-separated source slugs to import (default: all).")
    args = parser.parse_args()

    selected: list[tuple[str, str, str]] = BENIGN_SOURCES
    if args.only:
        wanted = set(s.strip() for s in args.only.split(","))
        selected = [s for s in BENIGN_SOURCES if s[0] in wanted]

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)

    totals = {"read": 0, "upserted": 0}
    for slug, out_source, threat_type in selected:
        print(f"\n=== importing {slug} -> source='{out_source}' ===",
              flush=True)
        read, upserted = import_benign(pg_url, slug, out_source, threat_type)
        totals["read"] += read
        totals["upserted"] += upserted
        print(f"  done: read={read:,} upserted={upserted:,}", flush=True)

    print(f"\nTOTAL read={totals['read']:,} upserted={totals['upserted']:,}",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
