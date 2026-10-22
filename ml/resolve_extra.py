"""Resolve extra malicious domains from a domain list file and merge into resolved_fresh.parquet.

Usage:
    uv run python resolve_extra.py
    uv run python resolve_extra.py --domains data/malicious_batch2.txt --concurrency 100
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
    parser = argparse.ArgumentParser(description="Resolve extra domains and merge")
    parser.add_argument("--domains", type=str, default=str(DATA_DIR / "malicious_batch2.txt"))
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--geoip", type=str, default=str(DEFAULT_GEOIP))
    parser.add_argument("--output", type=str, default=str(DATA_DIR / "resolved_fresh.parquet"))
    args = parser.parse_args()

    domains_path = Path(args.domains)
    domains = [d.strip() for d in domains_path.read_text().splitlines() if d.strip()]
    print(f"Resolving {len(domains):,} domains (concurrency={args.concurrency})")

    geo = GeoTable.from_file(Path(args.geoip))

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

    # Save batch results
    batch_output = DATA_DIR / "resolved_extra.parquet"
    build_resolution_cache(resolved, geo, batch_output)

    # Merge with existing
    output_path = Path(args.output)
    if output_path.exists():
        existing = pd.read_parquet(output_path)
        extra = pd.read_parquet(batch_output)
        # Only add successfully resolved domains not already in existing
        existing_domains = set(existing["domain"])
        new_ok = extra[(extra["error"] == "") & (~extra["domain"].isin(existing_domains))]
        merged = pd.concat([existing, new_ok], ignore_index=True)
        merged.to_parquet(output_path, index=False)

        old_resolved = len(existing[existing["error"] == ""])
        new_resolved = len(merged[merged["error"] == ""])
        print(f"\n  Merged into {output_path.name}:")
        print(f"    Before: {old_resolved:,} resolved")
        print(f"    Added:  {len(new_ok):,} new")
        print(f"    After:  {new_resolved:,} resolved")
    else:
        extra = pd.read_parquet(batch_output)
        extra.to_parquet(output_path, index=False)
        print(f"\n  Saved to {output_path.name}: {success:,} resolved")


if __name__ == "__main__":
    main()
