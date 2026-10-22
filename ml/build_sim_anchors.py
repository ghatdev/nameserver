"""Materialize the contrastive embedder's anchor pool.

Pulls labels from PostgreSQL into a single parquet that
`train_cnn_sim.py` and `build_sim_eval.py` consume.

Anchors come from two sources merged + deduplicated:

  1. `domain_label_embeddings.label` — the production corpus that
     `similarity::search_edit_distance` actually queries against.
     Whatever lives in this table is what the embedder will need to
     find neighbors *of*. Filtered to length>=4 and DNS-legal.

  2. Tranco top-100k registrable labels (via `indicator_domains` /
     `sources.slug = 'tranco-100k'`). Densely populates the
     "labels worth defending" neighborhood — these are the
     impersonation targets that matter most.

Train/val/test split is **registrable-stratified** at write time.
Each anchor gets a deterministic bucket (90/5/5) keyed by the SHA-256
hash of its registrable family. Subdomain labels (those that don't
appear as their own registrable) get bucketed by the label itself,
which is fine because pure subdomain labels rarely appear in multiple
registrables to begin with — and even when they do, sharing the bucket
across registrables can only *help* contrastive training.

Output:
    data/sim_anchors.parquet     # columns: label (str), bucket (str)
    data/sim_anchors.meta.json   # generation metadata + counts

Run:
    uv run ml/build_sim_anchors.py
    uv run ml/build_sim_anchors.py --tranco-top 50000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import psycopg2

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"

DEFAULT_PG_URL = (
    "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
)

LABEL_RE = re.compile(r"^[a-z0-9-]{4,63}$")
PURE_NUMERIC_OR_HYPHEN_RE = re.compile(r"^[0-9-]+$")


def is_acceptable_label(label: str) -> bool:
    """DNS-legal, length >= 4, not pure numeric/hyphen."""
    if not LABEL_RE.match(label):
        return False
    if PURE_NUMERIC_OR_HYPHEN_RE.match(label):
        return False
    return True


def fetch_dle_labels(pg_url: str) -> list[str]:
    """All `label` values from `domain_label_embeddings`."""
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT lower(label) FROM domain_label_embeddings",
            )
            rows = [r[0] for r in cur.fetchall() if r[0]]
    return rows


def fetch_tranco_labels(pg_url: str, top_n: int) -> list[tuple[str, str]]:
    """Tranco registrable labels up to rank `top_n`. Returns (label, registrable)."""
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM sources WHERE slug = 'tranco-100k'",
            )
            row = cur.fetchone()
            if row is None:
                print("[warn] sources.slug='tranco-100k' not found, "
                      "Tranco anchors will be skipped", flush=True)
                return []
            source_id = row[0]
            cur.execute(
                "SELECT lower(domain), rank FROM indicator_domains "
                "WHERE source = %s AND rank IS NOT NULL AND rank <= %s",
                (source_id, top_n),
            )
            rows = cur.fetchall()
    out: list[tuple[str, str]] = []
    for domain, _rank in rows:
        # Pull the leftmost label (registrable's first label).
        # `tldextract` would be more correct but Tranco data is already
        # registrable-form (e.g. "google.com"), so split_part is fine.
        parts = domain.split(".")
        if not parts:
            continue
        label = parts[0]
        out.append((label, domain))
    return out


def bucket_for(key: str) -> str:
    """Deterministic 90/5/5 train/val/test split keyed by `key`.

    Hashing on the *key* (not the label) means we can pass a
    registrable family for proper stratification, or pass the label
    itself when no registrable is available. Same key always lands in
    the same bucket regardless of run.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    # First 4 bytes give us a 32-bit unsigned int — plenty of resolution
    # for percentile splits.
    n = int.from_bytes(digest[:4], "big")
    pct = n % 100
    if pct < 90:
        return "train"
    if pct < 95:
        return "val"
    return "test"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=DATA_DIR / "sim_anchors.parquet",
    )
    parser.add_argument(
        "--meta", type=Path, default=DATA_DIR / "sim_anchors.meta.json",
    )
    parser.add_argument(
        "--tranco-top", type=int, default=100_000,
        help="Augment the anchor pool with Tranco registrable labels up to this rank",
    )
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[pg] connecting to {pg_url.replace(' ', '')[:60]}...", flush=True)

    # --- Source 1: production embedding corpus ----------------------------
    dle_labels = fetch_dle_labels(pg_url)
    print(f"[src] domain_label_embeddings: {len(dle_labels):,} raw labels", flush=True)

    # We don't have registrable info for these — bucket by the label
    # itself. Acceptable because (a) subdomain labels rarely appear under
    # multiple registrables, (b) any cross-bucket leakage hurts the eval
    # numbers but doesn't bias them in our favor.
    rows: list[tuple[str, str]] = []  # (label, bucket)
    seen_labels: set[str] = set()
    n_rejected_dns = 0
    for label in dle_labels:
        if not is_acceptable_label(label):
            n_rejected_dns += 1
            continue
        if label in seen_labels:
            continue
        seen_labels.add(label)
        rows.append((label, bucket_for(label)))

    # --- Source 2: Tranco registrable labels ------------------------------
    tranco_pairs = fetch_tranco_labels(pg_url, args.tranco_top)
    print(f"[src] tranco-100k (top {args.tranco_top:,}): {len(tranco_pairs):,} raw", flush=True)

    n_tranco_added = 0
    for label, registrable in tranco_pairs:
        if not is_acceptable_label(label):
            n_rejected_dns += 1
            continue
        if label in seen_labels:
            continue
        seen_labels.add(label)
        # Bucket by registrable so all subdomain labels of the same
        # registrable land in the same split (when we ever add them).
        rows.append((label, bucket_for(registrable)))
        n_tranco_added += 1

    if not rows:
        print("[err] no anchors collected — check PG connection / source slugs",
              flush=True, file=sys.stderr)
        return 1

    # --- Write parquet + meta ---------------------------------------------
    df = pd.DataFrame(rows, columns=["label", "bucket"])
    df.to_parquet(args.out, index=False)

    bucket_counts = df["bucket"].value_counts().to_dict()

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "out": str(args.out),
        "tranco_top_n": args.tranco_top,
        "total_anchors": len(df),
        "from_dle": len(dle_labels),
        "from_tranco": n_tranco_added,
        "rejected_dns_legality": n_rejected_dns,
        "bucket_counts": bucket_counts,
    }
    args.meta.write_text(json.dumps(meta, indent=2))

    print(f"[out] {args.out} ({len(df):,} anchors, "
          f"train={bucket_counts.get('train', 0):,} "
          f"val={bucket_counts.get('val', 0):,} "
          f"test={bucket_counts.get('test', 0):,})", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
