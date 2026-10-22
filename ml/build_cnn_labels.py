"""Build the CNN training label set.

Aggregates positive + negative FQDNs from PostgreSQL sources into a
single parquet that `train_cnn.py` consumes. Each row is
`(domain, label, source)` where label ∈ {0=benign, 1=malicious}.

Per `docs/detector-cnn-design.md` §2 + §4.1:

POSITIVES (union, dedup, DGA stratification):
  hagezi-tif                      (threat intel, primary)
  hagezi-pro                      (broad blocklist)
  hagezi-dga-7d / 14d / 30d       (capped at ≤30% of positives)

NEGATIVES (union, dedup):
  tranco-100k registrables
  majestic-1m  registrables
  realtraffic_longtail            (non-well-known benign, from our flows)

DomainRadar is not pulled by this script — that's a separate
large-file ingest (deferred per design §10 Q1). Add when needed.

The `train_cnn.py` label-split happens downstream — we emit FQDNs
here; it splits them into `(label_text, label_y)` with majority
vote. Keeping the split in train_cnn.py means this builder is
idempotent and cheap to re-run.

Run:
    uv run ml/build_cnn_labels.py
    uv run ml/build_cnn_labels.py --dga-cap 0.30 --out data/cnn_labels.parquet
    uv run ml/build_cnn_labels.py --no-dga    # exclude DGA entirely
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import psycopg2

DEFAULT_PG_URL = (
    "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
)

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"

# Source slugs for each class. Ordered: higher-quality / higher-signal
# sources first so the dedup favors those source attributions.
POSITIVE_SLUGS_MAIN: list[str] = [
    "hagezi-tif",
    "hagezi-pro",
]
POSITIVE_SLUGS_DGA: list[str] = [
    "hagezi-dga-7d",
    "hagezi-dga-14d",
    "hagezi-dga-30d",
]
NEGATIVE_SLUGS: list[str] = [
    "tranco-100k",
    "majestic-1m",
]


def fetch_slug_domains(pg_url: str, slug: str) -> list[str]:
    """Return the domains currently in `indicator_domains` for this slug."""
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM sources WHERE slug = %s", (slug,))
            row = cur.fetchone()
            if row is None:
                print(f"[warn] source slug not found: {slug}", flush=True)
                return []
            source_id = row[0]
            cur.execute(
                "SELECT domain FROM indicator_domains WHERE source = %s",
                (source_id,),
            )
            return [r[0] for r in cur.fetchall()]


def fetch_incident_label_domains(
    pg_url: str, source: str, verdict: str,
) -> list[str]:
    """Return FQDNs from incident_labels for a given (source, verdict)."""
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT domain FROM incident_labels "
                "WHERE source = %s AND verdict = %s AND layer = 'dns'",
                (source, verdict),
            )
            return [r[0] for r in cur.fetchall()]


def stratify_dga(
    main_pos: set[str],
    dga_pos: set[str],
    dga_cap: float,
    rng_seed: int = 42,
) -> set[str]:
    """Return the union of main-pos + a DGA sample capped to `dga_cap`
    of the final positive count.

    Example: main_pos=700K, dga_pos=1M, dga_cap=0.30 → keep 300K DGA
    so final positives = 1M (70/30 split). Math: let total be T; main
    is kept in full (=main_pos), DGA kept is dga_cap*T. So
    T = main_pos + dga_cap*T  →  T = main_pos / (1 - dga_cap).
    DGA to keep = dga_cap * T = main_pos * dga_cap / (1 - dga_cap).
    """
    if dga_cap <= 0 or not dga_pos:
        return set(main_pos)
    if dga_cap >= 1.0:
        return set(main_pos) | set(dga_pos)

    dga_only = dga_pos - main_pos  # DGA entries not already in main
    target_dga = int(len(main_pos) * dga_cap / (1.0 - dga_cap))
    if len(dga_only) <= target_dga:
        return set(main_pos) | dga_only

    import random

    rng = random.Random(rng_seed)
    sampled = set(rng.sample(sorted(dga_only), target_dga))
    return set(main_pos) | sampled


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=DATA_DIR / "cnn_labels.parquet",
    )
    parser.add_argument(
        "--dga-cap", type=float, default=0.30,
        help="Max fraction of positives that come from DGA sources "
             "(design §4.2). Use 0 to exclude DGA entirely.",
    )
    parser.add_argument("--no-dga", action="store_true")
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)

    dga_cap = 0.0 if args.no_dga else args.dga_cap

    # --- Positives ----------------------------------------------------
    main_pos: set[str] = set()
    for slug in POSITIVE_SLUGS_MAIN:
        rows = fetch_slug_domains(pg_url, slug)
        print(f"[pos] {slug:<24} +{len(rows):>8,}", flush=True)
        main_pos.update(rows)

    dga_pos: set[str] = set()
    if dga_cap > 0:
        for slug in POSITIVE_SLUGS_DGA:
            rows = fetch_slug_domains(pg_url, slug)
            print(f"[dga] {slug:<24} +{len(rows):>8,}", flush=True)
            dga_pos.update(rows)

    positives = stratify_dga(main_pos, dga_pos, dga_cap)
    print(
        f"[pos] main={len(main_pos):,} dga_total={len(dga_pos):,} "
        f"→ kept positives={len(positives):,} (dga_cap={dga_cap:.0%})",
        flush=True,
    )

    # --- Negatives ----------------------------------------------------
    negatives: set[str] = set()
    for slug in NEGATIVE_SLUGS:
        rows = fetch_slug_domains(pg_url, slug)
        print(f"[neg] {slug:<24} +{len(rows):>8,}", flush=True)
        negatives.update(rows)

    rt_longtail = fetch_incident_label_domains(
        pg_url, "realtraffic_longtail", "benign",
    )
    print(f"[neg] realtraffic_longtail    +{len(rt_longtail):>8,}", flush=True)
    negatives.update(rt_longtail)

    # Collisions between pos and neg: drop from BOTH (unreliable label).
    collisions = positives & negatives
    if collisions:
        print(
            f"[collision] dropped {len(collisions):,} domains that appear "
            f"in BOTH positive and negative sources",
            flush=True,
        )
        positives -= collisions
        negatives -= collisions

    # --- Assemble -----------------------------------------------------
    pairs: list[tuple[str, int]] = []
    pairs.extend((d, 1) for d in positives)
    pairs.extend((d, 0) for d in negatives)

    df = pd.DataFrame(pairs, columns=["domain", "label"])
    df["label"] = df["label"].astype("int8")
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    print(f"[out] wrote {len(df):,} rows to {args.out}", flush=True)

    # --- Sidecar metadata --------------------------------------------
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_rows": int(len(df)),
        "n_positives": int((df["label"] == 1).sum()),
        "n_negatives": int((df["label"] == 0).sum()),
        "dga_cap": dga_cap,
        "positive_slugs_main": POSITIVE_SLUGS_MAIN,
        "positive_slugs_dga": POSITIVE_SLUGS_DGA,
        "negative_slugs": NEGATIVE_SLUGS,
        "negative_incident_sources": ["realtraffic_longtail"],
        "collisions_dropped": int(len(collisions)),
        "fingerprint": hashlib.sha256(
            ("|".join(POSITIVE_SLUGS_MAIN + POSITIVE_SLUGS_DGA + NEGATIVE_SLUGS)
             + f"|dga_cap={dga_cap}").encode()
        ).hexdigest(),
    }
    meta_path = args.out.with_suffix(".meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"[meta] {meta_path}", flush=True)

    print(f"\n[summary] pos={meta['n_positives']:,}  "
          f"neg={meta['n_negatives']:,}  "
          f"ratio={meta['n_negatives'] / max(1, meta['n_positives']):.2f}:1",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
