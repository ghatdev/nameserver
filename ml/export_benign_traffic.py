"""Export benign traffic from ClickHouse flows for ML training.

Extracts unique domains with their infrastructure data (TTL, GeoIP, CDN)
from real DNS traffic. Labels domains as benign if their registrable domain
is in the Tranco top 100K list.

Usage:
    uv run python export_benign_traffic.py
    uv run python export_benign_traffic.py --ch-url http://127.0.0.1:8123
    uv run python export_benign_traffic.py --limit 50000
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path

import requests
import tldextract

DATA_DIR = Path(__file__).parent / "data"

# CDN ASNs (must match resolve_data.py and nameserver-common/src/geo.rs)
CDN_ASNS: set[int] = {13335, 209242, 16509, 20940, 16625, 54113, 15169, 8075}

# Known bulletproof hosting ASNs
BULLETPROOF_ASNS: set[int] = set()


def load_tranco_registrable(path: Path, max_rank: int = 100_000) -> dict[str, int]:
    """Load Tranco benign list and return registrable_domain -> rank mapping."""
    mapping: dict[str, int] = {}
    if not path.exists():
        return mapping
    with open(path) as f:
        for row in csv.DictReader(f):
            domain = row["domain"]
            rank = int(row["rank"])
            if rank > max_rank:
                continue
            # Extract registrable domain
            ext = tldextract.extract(domain)
            registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            # Keep the best (lowest) rank
            if registrable not in mapping or rank < mapping[registrable]:
                mapping[registrable] = rank
    return mapping


def query_clickhouse(
    ch_url: str,
    ch_user: str,
    ch_password: str,
    ch_database: str,
    limit: int,
) -> list[dict[str, str]]:
    """Query ClickHouse for distinct domains with infrastructure data."""
    sql = f"""\
SELECT
    domain,
    avg(response_ttl) as avg_ttl,
    min(response_ttl) as min_ttl,
    length(groupUniqArray(arrayJoin(response_ips))) as unique_ip_count,
    max(length(cname_chain)) as cname_depth,
    any(geo_country) as ip_country,
    any(geo_asn) as ip_asn
FROM flows
WHERE started_at > now() - INTERVAL 7 DAY
  AND list_action != 'BLOCK'
  AND rcode = 'NOERROR'
  AND length(response_ips) > 0
GROUP BY domain
ORDER BY count() DESC
LIMIT {limit}
FORMAT TSVWithNames
"""

    resp = requests.post(
        ch_url,
        params={
            "database": ch_database,
            "user": ch_user,
            "password": ch_password,
        },
        data=sql,
        timeout=120,
    )
    resp.raise_for_status()

    lines = resp.text.strip().split("\n")
    if len(lines) < 2:
        return []

    headers = lines[0].split("\t")
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split("\t")
        rows.append(dict(zip(headers, values)))

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export benign traffic from ClickHouse flows for ML training"
    )
    parser.add_argument(
        "--ch-url",
        type=str,
        default="http://127.0.0.1:8123",
        help="ClickHouse HTTP API URL",
    )
    parser.add_argument(
        "--ch-user",
        type=str,
        default="nameserver",
        help="ClickHouse user",
    )
    parser.add_argument(
        "--ch-password",
        type=str,
        default=None,
        help="ClickHouse password (or set CH_PASSWORD env var)",
    )
    parser.add_argument(
        "--ch-database",
        type=str,
        default="nameserver",
        help="ClickHouse database",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100_000,
        help="Max distinct domains to query from ClickHouse",
    )
    parser.add_argument(
        "--tranco-max-rank",
        type=int,
        default=100_000,
        help="Max Tranco rank to consider as benign",
    )
    args = parser.parse_args()

    # Resolve password
    ch_password = args.ch_password or os.environ.get("CH_PASSWORD", "")
    if not ch_password:
        print("ERROR: ClickHouse password not provided.")
        print("  Use --ch-password or set CH_PASSWORD environment variable.")
        raise SystemExit(1)

    # Load Tranco benign list
    tranco_path = DATA_DIR / "benign_domains.csv"
    print(f"Loading Tranco benign list from {tranco_path} ...")
    tranco_map = load_tranco_registrable(tranco_path, max_rank=args.tranco_max_rank)
    print(f"  {len(tranco_map)} unique registrable domains (rank <= {args.tranco_max_rank})")

    if not tranco_map:
        print("ERROR: No Tranco domains loaded. Run fetch_data.py first.")
        raise SystemExit(1)

    # Query ClickHouse
    print(f"\nQuerying ClickHouse at {args.ch_url} ...")
    rows = query_clickhouse(
        ch_url=args.ch_url,
        ch_user=args.ch_user,
        ch_password=ch_password,
        ch_database=args.ch_database,
        limit=args.limit,
    )
    print(f"  {len(rows)} unique domains from flows")

    # Match against Tranco
    print("\nMatching against Tranco benign list ...")
    benign_rows: list[dict[str, str | float | int | bool]] = []

    for row in rows:
        domain = row["domain"].rstrip(".")
        ext = tldextract.extract(domain)
        registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        rank = tranco_map.get(registrable)
        if rank is None:
            continue

        # Parse numeric fields
        avg_ttl = float(row.get("avg_ttl", "0"))
        min_ttl = float(row.get("min_ttl", "0"))
        unique_ip_count = int(row.get("unique_ip_count", "0"))
        cname_depth = int(row.get("cname_depth", "0"))
        ip_country = row.get("ip_country", "")
        ip_asn_str = row.get("ip_asn", "0")
        ip_asn = int(ip_asn_str) if ip_asn_str else 0

        is_cdn = 1 if ip_asn in CDN_ASNS else 0
        is_bulletproof = 1 if ip_asn in BULLETPROOF_ASNS else 0

        benign_rows.append({
            "domain": domain,
            "avg_ttl": avg_ttl,
            "min_ttl": min_ttl,
            "unique_ip_count": unique_ip_count,
            "cname_depth": cname_depth,
            "ip_country": ip_country,
            "ip_asn": ip_asn,
            "is_cdn": is_cdn,
            "is_bulletproof": is_bulletproof,
            "rank": rank,
        })

    # Save
    out_path = DATA_DIR / "traffic_benign.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "domain", "avg_ttl", "min_ttl", "unique_ip_count", "cname_depth",
                "ip_country", "ip_asn", "is_cdn", "is_bulletproof", "rank",
            ],
        )
        writer.writeheader()
        for row_dict in benign_rows:
            writer.writerow(row_dict)

    print(f"\nSaved -> {out_path}")

    # Stats
    print(f"\n{'='*50}")
    print(f"Statistics:")
    print(f"  Total flows queried:   {len(rows)} unique domains")
    print(f"  Benign matches:        {len(benign_rows)}")
    if rows:
        print(f"  Coverage:              {len(benign_rows)/len(rows)*100:.1f}%")

    # Country distribution
    countries: dict[str, int] = {}
    for r in benign_rows:
        c = str(r.get("ip_country", ""))
        if c:
            countries[c] = countries.get(c, 0) + 1
    if countries:
        print(f"\n  Top hosting countries:")
        for country, count in sorted(countries.items(), key=lambda x: -x[1])[:10]:
            print(f"    {country}: {count}")

    cdn_count = sum(1 for r in benign_rows if r.get("is_cdn"))
    print(f"\n  CDN domains:           {cdn_count} ({cdn_count/max(len(benign_rows),1)*100:.1f}%)")


if __name__ == "__main__":
    main()
