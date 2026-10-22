"""Resolve feed domains and enrich with GeoIP data for ML training.

1. Reads geoip.bin (bincode-serialized GeoTable) for IP→country/ASN lookups
2. Resolves a sample of feed malicious domains via DNS (A, MX, NS, TXT)
3. Enriches existing SQLite IPs with GeoIP data
4. Re-exports features with Group B enrichment

Usage:
    uv run python resolve_data.py                             # resolve feed domains + enrich
    uv run python resolve_data.py --sample 2000               # resolve 2000 malicious domains
    uv run python resolve_data.py --enrich-sqlite-only        # only enrich SQLite IPs
    uv run python resolve_data.py --geoip ../compiled/geoip.bin
"""

from __future__ import annotations

import argparse
import os
import asyncio
import csv
import ipaddress
import json
import sqlite3
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import dns.asyncresolver
import dns.nameserver
import dns.resolver

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_GEOIP = Path(__file__).parent.parent / "compiled" / "geoip.bin"

CDN_ASNS = {13335, 209242, 16509, 20940, 16625, 54113, 15169, 8075}


# ---------------------------------------------------------------------------
# GeoIP binary reader (reads Rust bincode-serialized GeoTable)
# ---------------------------------------------------------------------------

@dataclass
class GeoEntry4:
    start: int  # u32 IP as integer
    end: int    # u32 IP as integer
    country: str  # 2-char country code
    asn: int      # u32 ASN


@dataclass
class GeoLookupResult:
    country: str
    asn: int
    is_cdn: bool


class GeoTable:
    """Read-only GeoIP lookup table from geoip.bin."""

    def __init__(self, entries: list[GeoEntry4]) -> None:
        self.entries = entries  # sorted by start IP
        self._starts = [e.start for e in entries]  # for bisect

    @classmethod
    def from_file(cls, path: Path) -> GeoTable:
        """Read bincode-serialized GeoTable.

        Format: u64(v4_len) + v4_entries(14 bytes each) + u64(v6_len) + v6_entries
        GeoEntry4: u32 start, u32 end, [u8;2] country, u32 asn = 14 bytes
        """
        data = path.read_bytes()
        offset = 0

        # Read v4 entries
        v4_len = struct.unpack_from("<Q", data, offset)[0]
        offset += 8

        entries: list[GeoEntry4] = []
        for _ in range(v4_len):
            start, end = struct.unpack_from("<II", data, offset)
            offset += 8
            country_bytes = data[offset : offset + 2]
            offset += 2
            asn = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            country = country_bytes.decode("ascii", errors="replace")
            entries.append(GeoEntry4(start=start, end=end, country=country, asn=asn))

        print(f"  Loaded {len(entries)} IPv4 GeoIP entries")
        # Skip v6 entries for now (not needed for most lookups)
        return cls(entries)

    def lookup(self, ip_str: str) -> GeoLookupResult | None:
        """Binary search for an IPv4 address."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if addr.version != 4:
            return None  # skip IPv6 for now

        ip_int = int(addr)

        # Binary search: find rightmost entry where start <= ip_int
        import bisect
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return None

        entry = self.entries[idx]
        if entry.start <= ip_int <= entry.end:
            return GeoLookupResult(
                country=entry.country,
                asn=entry.asn,
                is_cdn=entry.asn in CDN_ASNS,
            )
        return None


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


@dataclass
class ResolvedDomain:
    domain: str
    # A records
    ips: list[str]
    ttl: int | None
    a_record_count: int
    # AAAA
    aaaa_ips: list[str]
    has_aaaa: bool
    # MX
    has_mx: bool
    mx_exchanges: list[str]
    # TXT
    has_txt: bool
    txt_records: list[str]
    # NS
    ns_servers: list[str]
    # CNAME
    cname_chain: list[str]
    cname_depth: int
    # SOA
    soa_mname: str | None
    soa_rname: str | None
    soa_serial: int | None
    soa_refresh: int | None
    soa_minimum: int | None
    soa_ttl: int | None
    # DNSSEC
    dnssec_status: str  # "secure" / "insecure" / "bogus" / "unknown"
    # Meta
    error: str | None


async def resolve_domain(domain: str, resolver: dns.asyncresolver.Resolver) -> ResolvedDomain:
    """Resolve a domain: A, AAAA, MX, TXT, NS, SOA, CNAME chain."""
    result = ResolvedDomain(
        domain=domain, ips=[], ttl=None, a_record_count=0,
        aaaa_ips=[], has_aaaa=False,
        has_mx=False, mx_exchanges=[],
        has_txt=False, txt_records=[],
        ns_servers=[], cname_chain=[], cname_depth=0,
        soa_mname=None, soa_rname=None, soa_serial=None,
        soa_refresh=None, soa_minimum=None, soa_ttl=None,
        dnssec_status="unknown", error=None,
    )

    # A records
    try:
        answer = await resolver.resolve(domain, "A", lifetime=5)
        result.ips = [rr.address for rr in answer]
        result.a_record_count = len(result.ips)
        result.ttl = answer.rrset.ttl if answer.rrset else None

        # Check for CNAME chain
        if answer.canonical_name and str(answer.canonical_name).rstrip(".") != domain.rstrip("."):
            result.cname_chain = [str(answer.canonical_name).rstrip(".")]
            result.cname_depth = len(result.cname_chain)
    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        result.error = "NOANSWER"
        return result
    except dns.exception.Timeout:
        result.error = "TIMEOUT"
        return result
    except Exception as e:
        result.error = str(type(e).__name__)
        return result

    # AAAA (best effort)
    try:
        aaaa_answer = await resolver.resolve(domain, "AAAA", lifetime=3)
        result.aaaa_ips = [rr.address for rr in aaaa_answer]
        result.has_aaaa = len(result.aaaa_ips) > 0
    except Exception:
        result.aaaa_ips = []

    # MX (best effort)
    try:
        mx_answer = await resolver.resolve(domain, "MX", lifetime=3)
        result.has_mx = True
        result.mx_exchanges = [str(rr.exchange).rstrip(".").lower() for rr in mx_answer]
    except Exception:
        result.has_mx = False

    # TXT (best effort)
    try:
        txt_answer = await resolver.resolve(domain, "TXT", lifetime=3)
        result.has_txt = True
        result.txt_records = [
            b"".join(rr.strings).decode("utf-8", errors="replace")
            for rr in txt_answer
        ]
    except Exception:
        result.has_txt = False

    # NS (best effort)
    try:
        ns_answer = await resolver.resolve(domain, "NS", lifetime=3)
        result.ns_servers = [str(rr.target).rstrip(".").lower() for rr in ns_answer]
    except Exception:
        result.ns_servers = []

    # SOA (best effort)
    try:
        soa_answer = await resolver.resolve(domain, "SOA", lifetime=3)
        for rr in soa_answer:
            result.soa_mname = str(rr.mname).rstrip(".").lower()
            result.soa_rname = str(rr.rname).rstrip(".")
            result.soa_serial = rr.serial
            result.soa_refresh = rr.refresh
            result.soa_minimum = rr.minimum
            result.soa_ttl = soa_answer.rrset.ttl if soa_answer.rrset else None
            break  # only one SOA per zone
    except Exception:
        result.soa_mname = None

    # DNSSEC: check if DNSKEY exists (basic probe)
    try:
        await resolver.resolve(domain, "DNSKEY", lifetime=3)
        result.dnssec_status = "signed"  # has DNSKEY = zone is DNSSEC-signed
    except dns.resolver.NoAnswer:
        result.dnssec_status = "unsigned"  # no DNSKEY
    except Exception:
        result.dnssec_status = "unknown"

    return result


async def resolve_batch(
    domains: list[str],
    concurrency: int = 50,
) -> list[ResolvedDomain]:
    """Resolve domains in parallel with concurrency limit."""
    resolver = dns.asyncresolver.Resolver()
    # Use the system resolver unless an explicit research DoT endpoint is configured.
    address = os.environ.get("NAMESERVER_DOT_ADDRESS")
    if address:
        hostname = os.environ.get("NAMESERVER_DOT_SERVER_NAME")
        if not hostname:
            raise ValueError("NAMESERVER_DOT_SERVER_NAME is required with NAMESERVER_DOT_ADDRESS")
        resolver.nameservers = [dns.nameserver.DoTNameserver(address, port=int(os.environ.get("NAMESERVER_DOT_PORT", "853")), hostname=hostname)]
    resolver.timeout = 10
    resolver.lifetime = 15

    sem = asyncio.Semaphore(concurrency)
    results: list[ResolvedDomain] = []
    total = len(domains)
    resolved_count = 0
    error_count = 0

    async def resolve_one(domain: str) -> ResolvedDomain:
        nonlocal resolved_count, error_count
        async with sem:
            result = await resolve_domain(domain, resolver)
            resolved_count += 1
            if result.error:
                error_count += 1
            if resolved_count % 500 == 0:
                print(f"    Resolved {resolved_count}/{total} (errors: {error_count})")
            return result

    tasks = [resolve_one(d) for d in domains]
    results = await asyncio.gather(*tasks)
    return list(results)


# ---------------------------------------------------------------------------
# SQLite enrichment
# ---------------------------------------------------------------------------


def enrich_sqlite_ips(db_path: Path, geo: GeoTable) -> int:
    """Enrich IPs in SQLite with GeoIP data from geoip.bin."""
    db = sqlite3.connect(str(db_path))
    rows = db.execute("SELECT ip FROM ips WHERE geo_country IS NULL OR geo_country = ''").fetchall()
    print(f"  IPs needing GeoIP enrichment: {len(rows)}")

    enriched = 0
    for (ip_str,) in rows:
        result = geo.lookup(ip_str)
        if result:
            db.execute(
                "UPDATE ips SET geo_country = ?, asn_number = ?, is_cdn = ?, is_bulletproof = ? WHERE ip = ?",
                (result.country, result.asn, int(result.is_cdn), 0, ip_str),
            )
            enriched += 1

    db.commit()
    db.close()
    print(f"  Enriched {enriched} IPs with GeoIP data")
    return enriched


# ---------------------------------------------------------------------------
# Build resolution cache for feed domains
# ---------------------------------------------------------------------------


def build_resolution_cache(
    resolved: list[ResolvedDomain],
    geo: GeoTable,
    output_path: Path,
) -> None:
    """Save resolved domain data as Parquet for feature extraction."""
    rows: list[dict] = []
    for r in resolved:
        # GeoIP for first IP
        ip_country = ""
        ip_asn = 0
        is_cdn = False

        if r.ips:
            geo_result = geo.lookup(r.ips[0])
            if geo_result:
                ip_country = geo_result.country
                ip_asn = geo_result.asn
                is_cdn = geo_result.is_cdn

        rows.append({
            "domain": r.domain,
            "ips": json.dumps(r.ips),
            "ttl": r.ttl,
            "a_record_count": r.a_record_count,
            "has_aaaa": r.has_aaaa,
            "has_mx": r.has_mx,
            "has_txt": r.has_txt,
            "ns_servers": json.dumps(r.ns_servers),
            "mx_exchanges": json.dumps(r.mx_exchanges),
            "txt_records": json.dumps(r.txt_records),
            "cname_chain": json.dumps(r.cname_chain),
            "cname_depth": r.cname_depth,
            "soa_mname": r.soa_mname,
            "soa_rname": r.soa_rname,
            "soa_serial": r.soa_serial,
            "soa_refresh": r.soa_refresh,
            "soa_minimum": r.soa_minimum,
            "soa_ttl": r.soa_ttl,
            "dnssec_status": r.dnssec_status,
            "ip_country": ip_country,
            "ip_asn": ip_asn,
            "is_cdn": is_cdn,
            "unique_ip_count": len(r.ips),
            "error": r.error or "",
        })

    import pandas as pd
    df = pd.DataFrame(rows)

    if str(output_path).endswith(".parquet"):
        df.to_parquet(output_path, index=False)
    else:
        df.to_csv(output_path, index=False)

    resolved_count = df[df["error"] == ""].shape[0]
    print(f"  Saved {len(df)} domains ({resolved_count} resolved) → {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve domains with full feature extraction")
    parser.add_argument("--geoip", type=str, default=str(DEFAULT_GEOIP), help="Path to geoip.bin")
    parser.add_argument(
        "--dataset", type=str, default=str(DATA_DIR / "dataset.parquet"),
        help="Domain source (parquet with domain,label,category columns)",
    )
    parser.add_argument("--sample", type=int, default=100000, help="Domains per label to resolve")
    parser.add_argument("--db", type=str, default=str(DATA_DIR / "nameserver.db"), help="SQLite database path")
    parser.add_argument("--enrich-sqlite-only", action="store_true", help="Only enrich SQLite IPs")
    parser.add_argument("--concurrency", type=int, default=100, help="DNS resolution concurrency")
    parser.add_argument(
        "--output", type=str, default=str(DATA_DIR / "resolved.parquet"),
        help="Output path (unified resolved cache)",
    )
    parser.add_argument("--resume", action="store_true", help="Skip domains already in output")
    args = parser.parse_args()

    import pandas as pd

    geoip_path = Path(args.geoip)
    if not geoip_path.exists():
        print(f"geoip.bin not found at {geoip_path}")
        raise SystemExit(1)

    # Load GeoIP table
    print("Loading GeoIP table ...")
    geo = GeoTable.from_file(geoip_path)

    # Enrich SQLite IPs
    db_path = Path(args.db)
    if db_path.exists():
        print(f"\nEnriching SQLite IPs ({db_path}) ...")
        enrich_sqlite_ips(db_path, geo)

    if args.enrich_sqlite_only:
        print("\nDone (SQLite enrichment only).")
        return

    # Load dataset
    dataset_path = Path(args.dataset)
    if str(dataset_path).endswith(".parquet"):
        ds = pd.read_parquet(dataset_path)
    else:
        ds = pd.read_csv(dataset_path, low_memory=False)
    print(f"\nDataset: {len(ds):,} domains")

    # Sample per label (balanced resolution)
    import random
    random.seed(42)
    mal = ds[ds["label"] == 1]["domain"].tolist()
    ben = ds[ds["label"] == 0]["domain"].tolist()

    mal_sample = random.sample(mal, min(args.sample, len(mal)))
    ben_sample = random.sample(ben, min(args.sample, len(ben)))
    all_domains = mal_sample + ben_sample
    print(f"  Malicious sample: {len(mal_sample):,}")
    print(f"  Benign sample: {len(ben_sample):,}")
    print(f"  Total to resolve: {len(all_domains):,}")

    # Resume support
    output_path = Path(args.output)
    if args.resume and output_path.exists():
        existing = pd.read_parquet(output_path)
        existing_domains = set(existing["domain"])
        all_domains = [d for d in all_domains if d not in existing_domains]
        print(f"  Resuming: {len(existing_domains):,} already resolved, {len(all_domains):,} remaining")

    if not all_domains:
        print("Nothing to resolve.")
        return

    # Resolve
    print(f"\nResolving {len(all_domains):,} domains (concurrency={args.concurrency}) ...")
    start = time.monotonic()
    resolved = asyncio.run(resolve_batch(all_domains, concurrency=args.concurrency))
    elapsed = time.monotonic() - start

    # Stats
    total = len(resolved)
    success = sum(1 for r in resolved if r.error is None)
    nxdomain = sum(1 for r in resolved if r.error == "NXDOMAIN")
    timeout = sum(1 for r in resolved if r.error == "TIMEOUT")
    other_err = sum(1 for r in resolved if r.error and r.error not in ("NXDOMAIN", "TIMEOUT"))

    print(f"\n  Complete in {elapsed:.1f}s ({total / elapsed:.0f} domains/sec)")
    print(f"    Success:  {success:6,} ({success/total*100:.1f}%)")
    print(f"    NXDOMAIN: {nxdomain:6,} ({nxdomain/total*100:.1f}%)")
    print(f"    Timeout:  {timeout:6,} ({timeout/total*100:.1f}%)")
    print(f"    Other:    {other_err:6,} ({other_err/total*100:.1f}%)")

    # Save unified resolution cache
    build_resolution_cache(resolved, geo, output_path)

    # Merge with existing if resuming
    if args.resume and output_path.exists() and 'existing' in dir():
        new = pd.read_parquet(output_path)
        merged = pd.concat([existing, new], ignore_index=True).drop_duplicates(subset=["domain"])
        merged.to_parquet(output_path, index=False)
        print(f"  Merged: {len(merged):,} total domains")

    print(f"\n{'='*50}")
    print(f"Resolution data ready. Re-run features.py to include Group B features.")


if __name__ == "__main__":
    main()
