"""Retry resolution for failed (non-NXDOMAIN) domains and merge into resolved_fresh.parquet.

Usage:
    uv run python retry_resolve.py
    uv run python retry_resolve.py --concurrency 50
"""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path

import pandas as pd

from resolve_data import GeoTable, build_resolution_cache, resolve_batch

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_GEOIP = Path(__file__).parent.parent / "compiled" / "geoip.bin"


def main() -> None:
    parser = argparse.ArgumentParser(description="Retry failed domain resolutions")
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--geoip", type=str, default=str(DEFAULT_GEOIP))
    args = parser.parse_args()

    retry_path = DATA_DIR / "retry_domains.txt"
    if not retry_path.exists():
        print("No retry_domains.txt found. Run the analysis script first.")
        return

    domains = [d.strip() for d in retry_path.read_text().splitlines() if d.strip()]
    print(f"Retrying {len(domains):,} domains (round-robin ns1/ns2, concurrency={args.concurrency})")

    # Load GeoIP
    geo = GeoTable.from_file(Path(args.geoip))

    # Resolve
    start = time.monotonic()
    resolved = asyncio.run(resolve_batch(domains, concurrency=args.concurrency))
    elapsed = time.monotonic() - start

    total = len(resolved)
    success = sum(1 for r in resolved if r.error is None)
    nxdomain = sum(1 for r in resolved if r.error == "NXDOMAIN")
    timeout = sum(1 for r in resolved if r.error == "TIMEOUT")
    other_err = sum(1 for r in resolved if r.error and r.error not in ("NXDOMAIN", "TIMEOUT"))

    print(f"\n  Complete in {elapsed:.1f}s ({total / max(elapsed, 1):.0f} domains/sec)")
    print(f"    Success:  {success:6,} ({success/total*100:.1f}%)")
    print(f"    NXDOMAIN: {nxdomain:6,} ({nxdomain/total*100:.1f}%)")
    print(f"    Timeout:  {timeout:6,} ({timeout/total*100:.1f}%)")
    print(f"    Other:    {other_err:6,} ({other_err/total*100:.1f}%)")

    # Save retry results
    retry_output = DATA_DIR / "resolved_retry.parquet"
    build_resolution_cache(resolved, geo, retry_output)

    # Merge with original
    original = pd.read_parquet(DATA_DIR / "resolved_fresh.parquet")
    retry_df = pd.read_parquet(retry_output)

    # For retried domains: replace original row with retry row (if retry succeeded)
    retry_ok = retry_df[retry_df["error"] == ""]
    retry_domains_set = set(retry_ok["domain"])

    # Keep original rows where domain was NOT retried successfully, plus all successful retries
    kept = original[~original["domain"].isin(retry_domains_set)]
    merged = pd.concat([kept, retry_ok], ignore_index=True)

    # Also keep failed retries that were NXDOMAIN (update error status)
    retry_nxdomain = retry_df[retry_df["error"] == "NXDOMAIN"]
    # Update original TIMEOUT entries to NXDOMAIN if retry confirmed dead
    nxdomain_domains = set(retry_nxdomain["domain"])
    for idx in merged.index:
        if merged.at[idx, "domain"] in nxdomain_domains and merged.at[idx, "error"] != "":
            merged.at[idx, "error"] = "NXDOMAIN"

    merged.to_parquet(DATA_DIR / "resolved_fresh.parquet", index=False)

    new_success = len(merged[merged["error"] == ""])
    old_success = len(original[original["error"] == ""])
    print(f"\n  Merged into resolved_fresh.parquet:")
    print(f"    Before: {old_success:,} resolved")
    print(f"    After:  {new_success:,} resolved (+{new_success - old_success:,})")


if __name__ == "__main__":
    main()
