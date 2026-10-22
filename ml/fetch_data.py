"""Download training data from threat feeds (malicious) and Tranco (benign).

Outputs:
    data/malicious_domains.csv  — deduplicated malicious domains with source tags
    data/benign_domains.csv     — Tranco top-N sample as benign labels

Usage:
    uv run python fetch_data.py
    uv run python fetch_data.py --benign-count 50000
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

DATA_DIR = Path(__file__).parent / "data"

HEADERS = {
    "User-Agent": "nameserver-ml/0.1 (threat-research; github.com/seoulvalley/nameserver)"
}

# ---------------------------------------------------------------------------
# Feed downloaders
# ---------------------------------------------------------------------------


def fetch_urlhaus() -> list[dict]:
    """URLhaus recent URLs (last 30 days). Returns [{domain, source, category}].

    JSON format: top-level keys are numeric IDs, each maps to an array of one object.
    """
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    print(f"  Fetching URLhaus from {url} ...")
    resp = requests.get(url, headers=HEADERS, timeout=120)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for _key, entries in data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            raw_url = entry.get("url", "")
            threat = entry.get("threat", "malware_download")
            try:
                parsed = urlparse(raw_url)
                host = parsed.hostname
                if host and not _is_ip(host):
                    results.append(
                        {"domain": host.lower().rstrip("."), "source": "urlhaus", "category": threat}
                    )
            except Exception:
                continue

    print(f"    → {len(results)} domains extracted")
    return results


def fetch_phishtank() -> list[dict]:
    """PhishTank online-valid feed (JSON). Returns [{domain, source, category}]."""
    url = "https://data.phishtank.com/data/online-valid.json"
    print(f"  Fetching PhishTank from {url} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=120)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"    ⚠ PhishTank failed ({e}), trying CSV fallback ...")
        return _fetch_phishtank_csv()

    results = []
    for entry in data:
        raw_url = entry.get("url", "")
        try:
            parsed = urlparse(raw_url)
            host = parsed.hostname
            if host and not _is_ip(host):
                results.append(
                    {"domain": host.lower().rstrip("."), "source": "phishtank", "category": "phishing"}
                )
        except Exception:
            continue

    print(f"    → {len(results)} domains extracted")
    return results


def _fetch_phishtank_csv() -> list[dict]:
    """Fallback: PhishTank CSV format."""
    url = "https://data.phishtank.com/data/online-valid.csv"
    resp = requests.get(url, headers=HEADERS, timeout=120)
    resp.raise_for_status()

    results = []
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        raw_url = row.get("url", "")
        try:
            parsed = urlparse(raw_url)
            host = parsed.hostname
            if host and not _is_ip(host):
                results.append(
                    {"domain": host.lower().rstrip("."), "source": "phishtank", "category": "phishing"}
                )
        except Exception:
            continue

    print(f"    → {len(results)} domains extracted (CSV fallback)")
    return results


def fetch_threatfox() -> list[dict]:
    """ThreatFox recent IOCs (last 30 days). Returns [{domain, source, category}]."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    print(f"  Fetching ThreatFox from {url} ...")
    resp = requests.post(
        url,
        json={"query": "get_iocs", "days": 30},
        headers=HEADERS,
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    results = []
    for entry in data.get("data", []) or []:
        ioc_type = entry.get("ioc_type", "")
        ioc_value = entry.get("ioc", "")
        threat_type = entry.get("threat_type", "")
        malware = entry.get("malware", "unknown")

        domain = None
        if ioc_type == "domain":
            domain = ioc_value.lower().rstrip(".")
        elif ioc_type == "url":
            try:
                parsed = urlparse(ioc_value)
                host = parsed.hostname
                if host and not _is_ip(host):
                    domain = host.lower().rstrip(".")
            except Exception:
                continue

        if domain and not _is_ip(domain):
            category = threat_type if threat_type else "c2"
            results.append(
                {"domain": domain, "source": "threatfox", "category": f"{category}:{malware}"}
            )

    print(f"    → {len(results)} domains extracted")
    return results


def fetch_phishing_database() -> list[dict]:
    """Phishing.Database — large community phishing domain list (~496K)."""
    url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    print(f"  Fetching Phishing.Database from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=120)
    resp.raise_for_status()

    results = []
    for line in resp.text.splitlines():
        domain = line.strip().lower().rstrip(".")
        if domain and not domain.startswith("#") and "." in domain and not _is_ip(domain):
            results.append({"domain": domain, "source": "phishing_database", "category": "phishing"})

    print(f"    → {len(results)} domains extracted")
    return results


def fetch_openphish() -> list[dict]:
    """OpenPhish free feed — small but curated phishing URLs."""
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    print(f"  Fetching OpenPhish from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=60)
    resp.raise_for_status()

    results = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            if host and not _is_ip(host):
                results.append(
                    {"domain": host.lower().rstrip("."), "source": "openphish", "category": "phishing"}
                )
        except Exception:
            continue

    print(f"    → {len(results)} domains extracted")
    return results


def fetch_tranco(n: int = 100_000) -> list[dict]:
    """Download Tranco Top 1M and return top N as benign labels."""
    print("  Fetching Tranco list ...")

    # Get latest list URL
    api_url = "https://tranco-list.eu/top-1m.csv.zip"
    resp = requests.get(api_url, headers=HEADERS, timeout=60)
    resp.raise_for_status()

    # Extract CSV from zip
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_name = zf.namelist()[0]
        csv_data = zf.read(csv_name).decode("utf-8")

    results = []
    for line in csv_data.splitlines():
        if not line.strip():
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        rank, domain = int(parts[0]), parts[1].strip().lower().rstrip(".")
        if rank > n:
            break
        results.append({"domain": domain, "source": "tranco", "rank": rank})

    print(f"    → {len(results)} benign domains (top {n})")
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    """Check if string looks like an IP address."""
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return ":" in host
    return ":" in host  # IPv6


KOREAN_BRAND_KEYWORDS = [
    "naver", "kakao", "shinhan", "kbstar", "woori", "hana",
    "ibk", "nhbank", "kfcc", "epostbank",
    "daum", "kakaocorp",
    "cjlogistics", "hanjin", "lotteglogis", "epost",
    "skt", "lguplus",
    "nhis", "nps", "hira", "wetax", "mois",
    # Common Korean phishing patterns
    "ncafe", "nblog", "npay", "nmail",
    "kpay", "kbank", "ktalk",
]


def deduplicate_malicious(entries: list[dict]) -> list[dict]:
    """Deduplicate by domain, keeping first occurrence + all source tags."""
    seen: dict[str, dict] = {}
    for entry in entries:
        domain = entry["domain"]
        if domain in seen:
            existing = seen[domain]
            if entry["source"] not in existing["sources"]:
                existing["sources"].append(entry["source"])
        else:
            seen[domain] = {
                "domain": domain,
                "sources": [entry["source"]],
                "category": entry["category"],
            }
    return list(seen.values())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Fetch ML training data")
    parser.add_argument(
        "--benign-count",
        type=int,
        default=100_000,
        help="Number of Tranco domains to sample as benign (default: 100000)",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch malicious domains from threat feeds
    print("Fetching malicious domains from threat feeds:")
    all_malicious: list[dict] = []

    for fetch_fn in [fetch_urlhaus, fetch_phishtank, fetch_threatfox, fetch_phishing_database, fetch_openphish]:
        try:
            all_malicious.extend(fetch_fn())
        except Exception as e:
            print(f"    ⚠ {fetch_fn.__name__} failed: {e}")

    # Deduplicate
    deduped = deduplicate_malicious(all_malicious)
    print(f"\nTotal malicious: {len(deduped)} unique domains (from {len(all_malicious)} raw entries)")

    # Save malicious
    mal_path = DATA_DIR / "malicious_domains.csv"
    with open(mal_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "sources", "category"])
        for entry in deduped:
            writer.writerow([entry["domain"], "|".join(entry["sources"]), entry["category"]])
    print(f"Saved → {mal_path}")

    # Fetch benign domains from Tranco
    print(f"\nFetching benign domains (Tranco top {args.benign_count}):")
    benign = fetch_tranco(args.benign_count)

    # Remove any overlap (domain in both malicious and Tranco)
    malicious_set = {e["domain"] for e in deduped}
    benign_clean = [e for e in benign if e["domain"] not in malicious_set]
    removed = len(benign) - len(benign_clean)
    if removed:
        print(f"  Removed {removed} domains that appear in malicious set")

    ben_path = DATA_DIR / "benign_domains.csv"
    with open(ben_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "rank"])
        for entry in benign_clean:
            writer.writerow([entry["domain"], entry["rank"]])
    print(f"Saved → {ben_path}")

    # Korean keyword analysis
    korean_matches = [
        e for e in deduped
        if any(kw in e["domain"] for kw in KOREAN_BRAND_KEYWORDS)
    ]
    if korean_matches:
        print(f"\nKorean brand-related malicious domains: {len(korean_matches)}")
        for entry in korean_matches[:20]:
            print(f"  {entry['domain']:50s} sources={','.join(entry['sources'])}")
        if len(korean_matches) > 20:
            print(f"  ... and {len(korean_matches) - 20} more")

    # Summary
    print(f"\n{'='*50}")
    print(f"Training data ready:")
    print(f"  Malicious: {len(deduped):>8} domains")
    print(f"  Benign:    {len(benign_clean):>8} domains")
    print(f"  Korean:    {len(korean_matches):>8} malicious with Korean keywords")
    print(f"  Ratio:     1:{len(benign_clean) // max(len(deduped), 1)}")


if __name__ == "__main__":
    main()
