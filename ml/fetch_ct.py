"""Fetch Certificate Transparency data from crt.sh PostgreSQL database.

Bulk-queries crt.sh's public PostgreSQL replica for certificate
age and count per domain. Results saved as ct_cache.parquet.

This is offline training data enrichment — not used in real-time inference.

Usage:
    uv run python fetch_ct.py
    uv run python fetch_ct.py --domains data/lgb_features.parquet
    uv run python fetch_ct.py --batch-size 500 --resume
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import pandas as pd
import psycopg2

DATA_DIR = Path(__file__).parent / "data"

# crt.sh public PostgreSQL
CRTSH_DSN = "host=crt.sh port=5432 dbname=certwatch user=guest"

# Query: for each domain, get first cert date and total cert count
# Uses certificate_identity table (CN/SAN entries)
QUERY_TEMPLATE = """
SELECT ci.NAME_VALUE AS domain,
       MIN(c.NOT_BEFORE) AS first_cert_date,
       MAX(c.NOT_BEFORE) AS latest_cert_date,
       COUNT(DISTINCT c.ID) AS cert_count
FROM certificate_identity ci
JOIN certificate c ON ci.CERTIFICATE_ID = c.ID
WHERE ci.NAME_TYPE = 'dNSName'
  AND ci.NAME_VALUE = ANY(%s)
GROUP BY ci.NAME_VALUE
"""


def load_domains(path: Path) -> list[str]:
    """Load domain list from parquet or text file."""
    if str(path).endswith(".parquet"):
        df = pd.read_parquet(path, columns=["domain"])
        return df["domain"].tolist()
    else:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]


def fetch_batch(
    conn: psycopg2.extensions.connection,
    domains: list[str],
) -> list[dict]:
    """Query crt.sh for a batch of domains."""
    cur = conn.cursor()
    cur.execute(QUERY_TEMPLATE, (domains,))
    rows = cur.fetchall()
    cur.close()

    results = []
    now = time.time()
    for domain, first_cert, latest_cert, cert_count in rows:
        first_age = (now - first_cert.timestamp()) / 86400 if first_cert else None
        latest_age = (now - latest_cert.timestamp()) / 86400 if latest_cert else None
        results.append({
            "domain": domain,
            "cert_age_days": first_age,
            "cert_latest_age_days": latest_age,
            "cert_count": cert_count,
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CT data from crt.sh PostgreSQL")
    parser.add_argument(
        "--domains", type=str, default=str(DATA_DIR / "lgb_features.parquet"),
        help="Domain list source (parquet or text file)",
    )
    parser.add_argument(
        "--output", type=str, default=str(DATA_DIR / "ct_cache.parquet"),
        help="Output path for CT cache",
    )
    parser.add_argument("--batch-size", type=int, default=200, help="Domains per SQL query")
    parser.add_argument("--resume", action="store_true", help="Resume from existing cache")
    parser.add_argument("--limit", type=int, default=None, help="Max domains to query")
    args = parser.parse_args()

    # Load domains
    all_domains = load_domains(Path(args.domains))
    print(f"Loaded {len(all_domains):,} domains")

    # Resume from existing cache
    existing: dict[str, dict] = {}
    output_path = Path(args.output)
    if args.resume and output_path.exists():
        cached_df = pd.read_parquet(output_path)
        existing = {row["domain"]: row for _, row in cached_df.iterrows()}
        print(f"Resuming: {len(existing):,} domains already cached")

    # Filter to domains not yet cached
    domains_to_fetch = [d for d in all_domains if d not in existing]
    if args.limit:
        domains_to_fetch = domains_to_fetch[:args.limit]
    print(f"Domains to fetch: {len(domains_to_fetch):,}")

    if not domains_to_fetch:
        print("Nothing to fetch.")
        return

    # Connect to crt.sh PostgreSQL
    print(f"Connecting to crt.sh PostgreSQL ...")
    conn = psycopg2.connect(CRTSH_DSN, connect_timeout=30)
    conn.set_session(readonly=True, autocommit=True)
    print("  Connected")

    # Fetch in batches
    all_results: list[dict] = list(existing.values()) if existing else []
    fetched = 0
    errors = 0
    total_batches = (len(domains_to_fetch) + args.batch_size - 1) // args.batch_size

    for i in range(0, len(domains_to_fetch), args.batch_size):
        batch = domains_to_fetch[i : i + args.batch_size]
        batch_num = i // args.batch_size + 1

        try:
            results = fetch_batch(conn, batch)
            all_results.extend(results)
            fetched += len(results)

            # Domains with no cert → record as no-cert
            found_domains = {r["domain"] for r in results}
            for d in batch:
                if d not in found_domains:
                    all_results.append({
                        "domain": d,
                        "cert_age_days": None,
                        "cert_latest_age_days": None,
                        "cert_count": 0,
                    })

            if batch_num % 10 == 0 or batch_num == total_batches:
                print(f"  Batch {batch_num}/{total_batches}: {fetched:,} with certs, {len(all_results):,} total")

        except psycopg2.Error as e:
            errors += 1
            print(f"  Batch {batch_num} error: {e}")
            # Reconnect
            try:
                conn.close()
            except psycopg2.Error as close_error:
                print(f"  Closing failed connection: {close_error}")
            time.sleep(5)
            conn = psycopg2.connect(CRTSH_DSN, connect_timeout=30)
            conn.set_session(readonly=True, autocommit=True)
            continue

        # Save checkpoint every 50 batches
        if batch_num % 50 == 0:
            df = pd.DataFrame(all_results)
            df.to_parquet(output_path, index=False)
            print(f"  Checkpoint saved: {len(df):,} domains")

    conn.close()

    # Final save
    df = pd.DataFrame(all_results)
    df.to_parquet(output_path, index=False)

    with_cert = df["cert_count"].gt(0).sum()
    print(f"\nDone: {len(df):,} domains ({with_cert:,} with certs, {len(df) - with_cert:,} without)")
    print(f"Errors: {errors}")
    print(f"Saved → {output_path}")


if __name__ == "__main__":
    main()
