"""Resolve NS records for well-known domains → bootstrap domain_ns_map.

Reads well-known domains from the control plane API (Tranco + Majestic stored
in well_known_list table) and resolves NS records for each.
Output is a TSV file ready for import via `nameserver ns-map import`.

Usage:
    uv run python resolve_ns.py --control-url http://localhost:8080
    uv run python resolve_ns.py --control-url http://127.0.0.1:8080 --top 100000
    uv run python resolve_ns.py --control-url http://localhost:8080 --source tranco-100k
"""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import requests

DATA_DIR = Path(__file__).parent / "data"

# Multi-part TLDs (must match scoring_chain::extract_registrable)
MULTI_PART_TLDS = frozenset([
    "co.kr", "or.kr", "go.kr", "ac.kr", "co.uk", "com.au",
    "co.jp", "com.br", "com.mx", "co.in", "co.za", "com.tw",
    "co.nz", "com.sg", "com.hk", "com.ar", "com.tr", "com.pk",
    "co.id", "com.ng", "com.ph", "com.eg", "com.ua",
])


def extract_registrable(domain: str) -> str:
    """Extract registrable domain — mirrors scoring_chain::extract_registrable."""
    domain = domain.rstrip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"

    return last_two


async def resolve_ns_batch(
    domains: list[str],
    concurrency: int = 100,
) -> list[tuple[str, list[str]]]:
    """Resolve NS records for domains in parallel.

    Returns list of (registrable_domain, [ns1, ns2, ...]) tuples.
    Domains that fail resolution are skipped.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 5
    resolver.lifetime = 10

    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, list[str]]] = []
    lock = asyncio.Lock()
    resolved_count = 0
    error_count = 0
    total = len(domains)

    async def resolve_one(domain: str) -> None:
        nonlocal resolved_count, error_count
        async with sem:
            try:
                answer = await resolver.resolve(domain, "NS", lifetime=5)
                ns_list = sorted(
                    str(rr.target).rstrip(".").lower() for rr in answer
                )
                if ns_list:
                    async with lock:
                        results.append((extract_registrable(domain), ns_list))
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                Exception,
            ):
                error_count += 1

            resolved_count += 1
            if resolved_count % 2000 == 0:
                print(
                    f"  {resolved_count:,}/{total:,} "
                    f"(success: {len(results):,}, errors: {error_count:,})"
                )

    tasks = [resolve_one(d) for d in domains]
    await asyncio.gather(*tasks)
    return results


def fetch_well_known(control_url: str, source: str | None) -> list[str]:
    """Fetch well-known domains from control plane API."""
    url = f"{control_url}/api/well-known/domains"
    params = {}
    if source:
        params["source"] = source

    print(f"Fetching well-known domains from {url} ...")
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()

    domains = [line.strip() for line in resp.text.strip().split("\n") if line.strip()]
    print(f"  Received {len(domains):,} domains")
    return domains


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve NS records for well-known domains (bootstrap domain_ns_map)"
    )
    parser.add_argument(
        "--control-url", type=str, required=True,
        help="Control plane API URL (e.g., http://localhost:8080)",
    )
    parser.add_argument(
        "--source", type=str, default=None,
        help="Filter by source (tranco-100k, majestic-1m)",
    )
    parser.add_argument(
        "--top", type=int, default=None,
        help="Limit to first N domains",
    )
    parser.add_argument(
        "--concurrency", type=int, default=100, help="DNS resolution concurrency"
    )
    parser.add_argument(
        "--output", type=str, default=str(DATA_DIR / "ns_bootstrap.tsv"),
        help="Output TSV path",
    )
    args = parser.parse_args()

    # Fetch from control plane
    domains = fetch_well_known(args.control_url, args.source)

    if args.top is not None and args.top < len(domains):
        domains = domains[: args.top]
        print(f"  Limited to top {args.top:,}")

    # Deduplicate by registrable domain
    seen: set[str] = set()
    unique_domains: list[str] = []
    for d in domains:
        reg = extract_registrable(d)
        if reg not in seen:
            seen.add(reg)
            unique_domains.append(d)
    print(f"  Unique registrable domains: {len(unique_domains):,}")

    # Resolve NS
    print(f"\nResolving NS for {len(unique_domains):,} domains (concurrency={args.concurrency}) ...")
    start = time.monotonic()
    results = asyncio.run(resolve_ns_batch(unique_domains, concurrency=args.concurrency))
    elapsed = time.monotonic() - start

    print(f"\n  Complete in {elapsed:.1f}s ({len(unique_domains) / elapsed:.0f} domains/sec)")
    print(f"  Successfully resolved: {len(results):,}")

    # Deduplicate results by registrable domain (keep first seen)
    deduped: dict[str, list[str]] = {}
    for reg_domain, ns_list in results:
        if reg_domain not in deduped:
            deduped[reg_domain] = ns_list

    # Write TSV output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for reg_domain, ns_list in sorted(deduped.items()):
            f.write(f"{reg_domain}\t{','.join(ns_list)}\n")

    print(f"  Written {len(deduped):,} entries → {output_path}")
    print(f"\nNext: nameserver ns-map import {output_path}")


if __name__ == "__main__":
    main()
