"""Build curated ML training dataset from multiple sources.

Pulls from all malicious/benign sources, deduplicates, normalizes,
removes conflicts, labels, and optionally balances the dataset.

Usage:
    uv run python build_dataset.py                    # pull + build
    uv run python build_dataset.py --stats-only       # show stats without saving
    uv run python build_dataset.py --max-per-source 50000  # cap per source
    uv run python build_dataset.py --ch-url http://localhost:18123  # include ClickHouse traffic
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import requests
import tldextract

DATA_DIR = Path(__file__).parent / "data"

HEADERS = {
    "User-Agent": "nameserver-ml/0.1 (threat-research; github.com/seoulvalley/nameserver)"
}

LARGE_TIMEOUT = 120
SMALL_TIMEOUT = 60


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class MaliciousEntry:
    domain: str
    source: str
    category: str
    ioc_type: str = "domain"  # "domain" (direct IOC) or "url" (extracted from URL)


@dataclass
class BenignEntry:
    domain: str
    source: str
    rank: int


@dataclass
class SourceStats:
    name: str
    raw_count: int = 0
    after_dedup: int = 0


@dataclass
class PipelineStats:
    sources: list[SourceStats] = field(default_factory=list)
    total_malicious_raw: int = 0
    total_malicious_dedup: int = 0
    total_benign_raw: int = 0
    total_benign_dedup: int = 0
    overlap_removed: int = 0
    category_breakdown: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    """Check if string looks like an IP address (v4 or v6)."""
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return ":" in host
    return ":" in host


def normalize_domain(raw: str) -> str | None:
    """Normalize a domain string. Returns None if invalid."""
    domain = raw.strip().lower().rstrip(".")
    if not domain:
        return None
    if "." not in domain:
        return None
    if _is_ip(domain):
        return None
    return domain


def extract_hostname(url: str) -> str | None:
    """Extract and normalize hostname from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            return None
        return normalize_domain(host)
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Malicious source fetchers
# ---------------------------------------------------------------------------


def fetch_urlhaus(max_per_source: int | None) -> list[MaliciousEntry]:
    """URLhaus recent URLs (last 30 days). Malware distribution sites."""
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    print(f"  [urlhaus] Fetching from {url} ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    results: list[MaliciousEntry] = []
    for _key, entries in data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            raw_url = entry.get("url", "")
            host = extract_hostname(raw_url)
            if host is not None:
                results.append(MaliciousEntry(domain=host, source="urlhaus", category="malware", ioc_type="url"))
                if max_per_source is not None and len(results) >= max_per_source:
                    break
        if max_per_source is not None and len(results) >= max_per_source:
            break

    print(f"    -> {len(results)} domains extracted")
    return results


def fetch_phishtank(max_per_source: int | None) -> list[MaliciousEntry]:
    """PhishTank online-valid feed. Falls back to CSV if JSON fails."""
    url = "https://data.phishtank.com/data/online-valid.json"
    print(f"  [phishtank] Fetching from {url} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"    WARNING: PhishTank JSON failed ({e}), trying CSV fallback ...")
        return _fetch_phishtank_csv(max_per_source)

    results: list[MaliciousEntry] = []
    for entry in data:
        raw_url = entry.get("url", "")
        host = extract_hostname(raw_url)
        if host is not None:
            results.append(MaliciousEntry(domain=host, source="phishtank", category="phishing", ioc_type="url"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted")
    return results


def _fetch_phishtank_csv(max_per_source: int | None) -> list[MaliciousEntry]:
    """Fallback: PhishTank CSV format."""
    url = "https://data.phishtank.com/data/online-valid.csv"
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        raw_url = row.get("url", "")
        host = extract_hostname(raw_url)
        if host is not None:
            results.append(MaliciousEntry(domain=host, source="phishtank", category="phishing", ioc_type="url"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted (CSV fallback)")
    return results


def fetch_threatfox(max_per_source: int | None) -> list[MaliciousEntry]:
    """ThreatFox IOCs. Tries local domain-only dump first, then full dump, then API."""
    # Prefer domain-only dump (no URL-extracted hostnames)
    local_path = DATA_DIR / "domains_full.csv.zip"
    if not local_path.exists():
        local_path = DATA_DIR / "threatfox.full.csv.zip"

    if local_path.exists():
        return _load_threatfox_local(local_path, max_per_source)

    # API fallback (may require auth now)
    url = "https://threatfox-api.abuse.ch/api/v1/"
    print(f"  [threatfox] Fetching from {url} ...")
    resp = requests.post(
        url,
        json={"query": "get_iocs", "days": 30},
        headers=HEADERS,
        timeout=LARGE_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    results: list[MaliciousEntry] = []
    for entry in data.get("data", []) or []:
        ioc_type = entry.get("ioc_type", "")
        ioc_value = entry.get("ioc", "")

        domain: str | None = None
        entry_ioc_type = "domain"
        if ioc_type == "domain":
            domain = normalize_domain(ioc_value)
        elif ioc_type == "url":
            domain = extract_hostname(ioc_value)
            entry_ioc_type = "url"

        if domain is not None:
            results.append(MaliciousEntry(domain=domain, source="threatfox", category="c2", ioc_type=entry_ioc_type))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted")
    return results


def _load_threatfox_local(path: Path, max_per_source: int | None) -> list[MaliciousEntry]:
    """Load ThreatFox from local full CSV zip dump.

    Format: "date", "id", "ioc_value", "ioc_type", "threat_type", "malware", ...
    """
    import zipfile

    print(f"  [threatfox] Loading from local {path.name} ...")
    results: list[MaliciousEntry] = []

    with zipfile.ZipFile(path) as zf:
        csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
        with zf.open(csv_name) as f:
            text = io.TextIOWrapper(f, encoding="utf-8")
            reader = csv.reader(text)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if len(row) < 4:
                    continue
                ioc_value = row[2].strip().strip('"')
                ioc_type = row[3].strip().strip('"')

                domain: str | None = None
                entry_ioc_type = "domain"
                if ioc_type == "domain":
                    domain = normalize_domain(ioc_value)
                elif ioc_type == "url":
                    domain = extract_hostname(ioc_value)
                    entry_ioc_type = "url"

                if domain is not None:
                    results.append(MaliciousEntry(domain=domain, source="threatfox", category="c2", ioc_type=entry_ioc_type))
                    if max_per_source is not None and len(results) >= max_per_source:
                        break

    print(f"    -> {len(results)} domains extracted")
    return results


def fetch_phishing_database(max_per_source: int | None) -> list[MaliciousEntry]:
    """Phishing.Database -- ALL historical phishing domains (not just active)."""
    url = "https://phish.co.za/latest/ALL-phishing-domains.lst"
    print(f"  [phishing_database] Fetching ALL historical domains from phish.co.za ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    for line in resp.text.splitlines():
        if line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if domain is not None:
            results.append(MaliciousEntry(domain=domain, source="phishing_database", category="phishing"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted")
    return results


def fetch_openphish(max_per_source: int | None) -> list[MaliciousEntry]:
    """OpenPhish free feed -- small but curated phishing URLs."""
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    print(f"  [openphish] Fetching from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=SMALL_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = extract_hostname(line)
        if host is not None:
            results.append(MaliciousEntry(domain=host, source="openphish", category="phishing", ioc_type="url"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted")
    return results


def fetch_jpcertcc(max_per_source: int | None) -> list[MaliciousEntry]:
    """JPCERT/CC phishurl-list — Japanese/APAC phishing URLs (2019-2025).

    Monthly CSV files in YYYY/YYYYMM.csv format on GitHub.
    Very relevant for Korean-adjacent phishing patterns.
    """
    base_url = "https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main"
    print("  [jpcertcc] Fetching monthly CSVs from GitHub ...")

    results: list[MaliciousEntry] = []
    fetched_months = 0

    for year in range(2019, 2027):
        for month in range(1, 13):
            if max_per_source is not None and len(results) >= max_per_source:
                break
            url = f"{base_url}/{year}/{year}{month:02d}.csv"
            try:
                resp = requests.get(url, headers=HEADERS, timeout=SMALL_TIMEOUT)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
            except requests.RequestException:
                continue

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("date") or line.startswith("#"):
                    continue
                # Format: date,url  (or just url)
                parts = line.split(",", 1)
                raw_url = parts[-1].strip().strip('"')
                host = extract_hostname(raw_url)
                if host is not None:
                    results.append(MaliciousEntry(
                        domain=host, source="jpcertcc", category="phishing", ioc_type="url",
                    ))
                    if max_per_source is not None and len(results) >= max_per_source:
                        break
            fetched_months += 1

    print(f"    -> {len(results):,} domains from {fetched_months} months")
    return results


def fetch_phiusiil(max_per_source: int | None) -> list[MaliciousEntry]:
    """PhiUSIIL phishing URL dataset — ~100K phishing URLs from academic research.

    CSV with URL column. We extract domains from phishing-labeled rows only.
    """
    url = "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv"
    print(f"  [phiusiil] Fetching from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        # label column: 1 = phishing, 0 = legitimate
        if row.get("label", "").strip() != "1":
            continue
        raw_url = row.get("URL", row.get("url", "")).strip()
        host = extract_hostname(raw_url)
        if host is not None:
            results.append(MaliciousEntry(
                domain=host, source="phiusiil", category="phishing", ioc_type="url",
            ))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results):,} phishing domains extracted")
    return results


def fetch_c2intelfeeds(max_per_source: int | None) -> list[MaliciousEntry]:
    """C2IntelFeeds — auto-generated C2 domain feeds from Censys scans.

    Uses the 90-day filtered list (high-FP domains removed).
    CSV format: domain,ioc description.
    """
    url = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-90day-filter-abused.csv"
    print("  [c2intelfeeds] Fetching 90-day filtered C2 domains ...")
    resp = requests.get(url, headers=HEADERS, timeout=SMALL_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 1)
        raw_domain = parts[0].strip()
        domain = normalize_domain(raw_domain)
        if domain is not None:
            results.append(MaliciousEntry(domain=domain, source="c2intelfeeds", category="c2"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results):,} C2 domains")
    return results


def fetch_threatmon_c2(max_per_source: int | None) -> list[MaliciousEntry]:
    """ThreatMon Daily C2 Feeds — daily top 50 C2 servers, historical.

    Fetches all available months (YYYY-MM directories) from GitHub.
    Files contain mixed IPs and domains, one per line.
    """
    print("  [threatmon] Fetching historical daily C2 feeds ...")

    # List available month directories
    api_url = "https://api.github.com/repos/ThreatMon/ThreatMon-Daily-C2-Feeds/contents/"
    try:
        resp = requests.get(api_url, headers=HEADERS, timeout=SMALL_TIMEOUT)
        resp.raise_for_status()
        months = [item["name"] for item in resp.json() if item["type"] == "dir" and item["name"].startswith("20")]
    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"    WARNING: failed to list months: {e}")
        return []

    results: list[MaliciousEntry] = []
    fetched_days = 0

    for month in sorted(months):
        if max_per_source is not None and len(results) >= max_per_source:
            break
        # List files in month directory
        try:
            dir_resp = requests.get(f"{api_url}{month}", headers=HEADERS, timeout=SMALL_TIMEOUT)
            dir_resp.raise_for_status()
            files = [f["name"] for f in dir_resp.json() if f["name"].endswith(".txt")]
        except (requests.RequestException, KeyError, ValueError):
            continue

        for fname in sorted(files):
            if max_per_source is not None and len(results) >= max_per_source:
                break
            raw_url = f"https://raw.githubusercontent.com/ThreatMon/ThreatMon-Daily-C2-Feeds/main/{month}/{fname}"
            try:
                file_resp = requests.get(raw_url, headers=HEADERS, timeout=SMALL_TIMEOUT)
                if file_resp.status_code != 200:
                    continue
            except requests.RequestException:
                continue

            for line in file_resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domain = normalize_domain(line)
                if domain is not None:
                    results.append(MaliciousEntry(domain=domain, source="threatmon", category="c2"))
            fetched_days += 1

    print(f"    -> {len(results):,} C2 domains from {fetched_days} daily feeds ({len(months)} months)")
    return results


def fetch_urlhaus_full(max_per_source: int | None) -> list[MaliciousEntry]:
    """URLhaus full CSV dump — all historical malware URLs.

    The full dump is a ZIP containing csv.txt with all entries.
    Much larger than the recent JSON feed.
    """
    url = "https://urlhaus.abuse.ch/downloads/csv/"
    print("  [urlhaus_full] Fetching full historical dump ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    import zipfile

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_names = [n for n in zf.namelist() if n.endswith(".txt") or n.endswith(".csv")]
        if not csv_names:
            print("    WARNING: no CSV/TXT file found in ZIP")
            return results

        with zf.open(csv_names[0]) as f:
            for raw_line in f:
                try:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                except UnicodeDecodeError:
                    continue
                if not line or line.startswith("#"):
                    continue
                # CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                parts = line.split(",", 3)
                if len(parts) < 3:
                    continue
                raw_url = parts[2].strip().strip('"')
                host = extract_hostname(raw_url)
                if host is not None:
                    results.append(MaliciousEntry(
                        domain=host, source="urlhaus_full", category="malware", ioc_type="url",
                    ))
                    if max_per_source is not None and len(results) >= max_per_source:
                        break

    print(f"    -> {len(results):,} malware domains from full dump")
    return results


def fetch_stamparm_blackbook(max_per_source: int | None) -> list[MaliciousEntry]:
    """stamparm/blackbook — curated malware domain blackbook.

    Historical malware domains. Simple text file, one domain per line.
    """
    url = "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt"
    print("  [blackbook] Fetching from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=SMALL_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if domain is not None:
            results.append(MaliciousEntry(domain=domain, source="blackbook", category="malware"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results):,} domains")
    return results


def fetch_chrmor_dga(max_per_source: int | None) -> list[MaliciousEntry]:
    """chrmor DGA domains dataset. CSV: domain,dga_family."""
    url = "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv"
    print(f"  [chrmor_dga] Fetching from GitHub ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    reader = csv.reader(io.StringIO(resp.text))
    for row in reader:
        if len(row) < 3:
            continue
        # Format: type,family,domain (e.g., "dga,gozi,mortiscontrastatim.com")
        label_type, _family, raw_domain = row[0].strip(), row[1].strip(), row[2].strip()
        if label_type.lower() == "legit":
            continue
        domain = normalize_domain(raw_domain)
        if domain is not None:
            results.append(MaliciousEntry(domain=domain, source="chrmor_dga", category="dga"))
            if max_per_source is not None and len(results) >= max_per_source:
                break

    print(f"    -> {len(results)} domains extracted")
    return results


def fetch_extrahop_dga(max_per_source: int | None) -> list[MaliciousEntry]:
    """ExtraHop DGA detection training dataset (~16M rows, ~500MB gzipped).

    Streams the gzipped JSONL file line by line to avoid loading it all into memory.
    Each line is a JSON object: {"domain": "...", "threat": "dga"|"benign"}.
    """
    url = "https://raw.githubusercontent.com/ExtraHop/DGA-Detection-Training-Dataset/master/dga-training-data-encoded.json.gz"
    print(f"  [extrahop_dga] Streaming from GitHub (large file) ...")

    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT, stream=True)
    resp.raise_for_status()

    results: list[MaliciousEntry] = []
    processed = 0
    errors = 0

    # Download to a temporary file first (GitHub raw doesn't support streaming gzip well).
    # The file is ~500MB gzipped, fits in /tmp.
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False)
    print(f"    downloading to {tmp.name} ...")
    downloaded = 0
    for chunk in resp.iter_content(chunk_size=1024 * 1024):
        tmp.write(chunk)
        downloaded += len(chunk)
        if downloaded % (100 * 1024 * 1024) == 0:
            print(f"    ... {downloaded // (1024*1024)} MB downloaded")
    tmp.close()
    print(f"    downloaded {downloaded // (1024*1024)} MB, reading ...")

    # GitHub may auto-decompress gzip via content-encoding. Detect format.
    with open(tmp.name, "rb") as probe:
        magic = probe.read(2)
    is_gzip = magic == b"\x1f\x8b"

    opener = gzip.open(tmp.name, "rb") if is_gzip else open(tmp.name, "rb")
    with opener as f:
        for raw_line in f:
            try:
                line_str = raw_line.decode("utf-8").strip()
                if not line_str:
                    continue
                obj = json.loads(line_str)
                threat = obj.get("threat", "")
                if threat != "dga":
                    processed += 1
                    continue
                raw_domain = obj.get("domain", "")
                domain = normalize_domain(raw_domain)
                if domain is not None:
                    results.append(
                        MaliciousEntry(domain=domain, source="extrahop_dga", category="dga")
                    )
            except (json.JSONDecodeError, UnicodeDecodeError):
                errors += 1
                continue

            processed += 1
            if processed % 2_000_000 == 0:
                print(f"    ... processed {processed:,} lines, {len(results):,} DGA domains so far")
            if max_per_source is not None and len(results) >= max_per_source:
                break

    # Clean up temp file
    import os
    os.unlink(tmp.name)

    if errors > 0:
        print(f"    WARNING: {errors} lines could not be parsed")
    print(f"    -> {len(results):,} DGA domains extracted from {processed:,} lines")
    return results


# ---------------------------------------------------------------------------
# Benign source fetchers
# ---------------------------------------------------------------------------


def fetch_tranco(count: int, max_per_source: int | None) -> list[BenignEntry]:
    """Download Tranco Top 1M and return top N as benign labels."""
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print(f"  [tranco] Fetching from {url} ...")
    resp = requests.get(url, headers=HEADERS, timeout=SMALL_TIMEOUT)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_name = zf.namelist()[0]
        csv_data = zf.read(csv_name).decode("utf-8")

    effective_limit = count
    if max_per_source is not None:
        effective_limit = min(count, max_per_source)

    results: list[BenignEntry] = []
    for line in csv_data.splitlines():
        if not line.strip():
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        try:
            rank = int(parts[0])
        except ValueError:
            continue
        domain = normalize_domain(parts[1])
        if domain is None:
            continue
        if rank > effective_limit:
            break
        results.append(BenignEntry(domain=domain, source="tranco", rank=rank))

    print(f"    -> {len(results)} benign domains (top {effective_limit})")
    return results


def fetch_majestic(count: int, max_per_source: int | None) -> list[BenignEntry]:
    """Download Majestic Million and return top N as benign labels."""
    url = "https://downloads.majestic.com/majestic_million.csv"
    print(f"  [majestic] Fetching from {url} ...")
    resp = requests.get(url, headers=HEADERS, timeout=LARGE_TIMEOUT)
    resp.raise_for_status()

    effective_limit = count
    if max_per_source is not None:
        effective_limit = min(count, max_per_source)

    results: list[BenignEntry] = []
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        try:
            rank = int(row.get("GlobalRank", "0"))
        except ValueError:
            continue
        raw_domain = row.get("Domain", "")
        domain = normalize_domain(raw_domain)
        if domain is None:
            continue
        if rank > effective_limit:
            break
        results.append(BenignEntry(domain=domain, source="majestic", rank=rank))

    print(f"    -> {len(results)} benign domains (top {effective_limit})")
    return results


def fetch_well_known(control_url: str) -> list[BenignEntry]:
    """Fetch well-known domains from control plane API (replaces Tranco + Majestic download)."""
    url = f"{control_url}/api/well-known/domains"
    print(f"  [well_known] Fetching from {url} ...")
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()

    results: list[BenignEntry] = []
    for i, line in enumerate(resp.text().strip().split("\n")):
        domain = line.strip()
        if domain:
            results.append(BenignEntry(domain=domain, source="well_known", rank=i + 1))

    print(f"    -> {len(results)} well-known domains from control plane")
    return results


def fetch_clickhouse_traffic(
    ch_url: str,
    ch_user: str,
    ch_password: str,
    ch_database: str,
    tranco_registrable: dict[str, int],
    max_per_source: int | None,
) -> list[BenignEntry]:
    """Query ClickHouse for real DNS traffic domains, label as benign if in Tranco."""
    print(f"  [traffic] Querying ClickHouse at {ch_url} ...")

    limit = max_per_source if max_per_source is not None else 200_000

    sql = f"""\
SELECT
    domain,
    count() as query_count
FROM flows
WHERE started_at > now() - INTERVAL 7 DAY
  AND list_action != 'BLOCK'
  AND rcode = 'NOERROR'
  AND length(response_ips) > 0
GROUP BY domain
ORDER BY query_count DESC
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
        timeout=LARGE_TIMEOUT,
    )
    resp.raise_for_status()

    lines = resp.text.strip().split("\n")
    if len(lines) < 2:
        print("    -> 0 domains from ClickHouse")
        return []

    # Skip header line
    results: list[BenignEntry] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 1:
            continue
        raw_domain = parts[0].rstrip(".")
        domain = normalize_domain(raw_domain)
        if domain is None:
            continue

        # Check if registrable domain is in Tranco
        ext = tldextract.extract(domain)
        registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        rank = tranco_registrable.get(registrable)
        if rank is None:
            continue

        results.append(BenignEntry(domain=domain, source="traffic", rank=rank))

    print(f"    -> {len(results)} benign domains from traffic (Tranco-verified)")
    return results


def load_traffic_benign_local(
    tranco_registrable: dict[str, int],
) -> list[BenignEntry]:
    """Load traffic benign from local CSV (exported by export_benign_traffic.py)."""
    path = DATA_DIR / "traffic_benign.csv"
    if not path.exists():
        return []

    print(f"  [traffic_local] Loading from {path.name} ...")
    results: list[BenignEntry] = []
    with open(path) as f:
        for row in csv.DictReader(f):
            domain = normalize_domain(row["domain"])
            if domain is None:
                continue
            rank = int(row.get("rank", 0))
            if rank == 0:
                # Verify via Tranco registrable map
                ext = tldextract.extract(domain)
                registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                r = tranco_registrable.get(registrable)
                if r is None:
                    continue
                rank = r
            results.append(BenignEntry(domain=domain, source="traffic", rank=rank))

    print(f"    -> {len(results)} benign domains from local traffic CSV")
    return results


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


@dataclass
class DeduplicatedMalicious:
    domain: str
    sources: list[str]
    category: str


def deduplicate_malicious(entries: list[MaliciousEntry]) -> list[DeduplicatedMalicious]:
    """Deduplicate by domain. Keep first category, merge source tags."""
    seen: dict[str, DeduplicatedMalicious] = {}
    for entry in entries:
        if entry.domain in seen:
            existing = seen[entry.domain]
            if entry.source not in existing.sources:
                existing.sources.append(entry.source)
        else:
            seen[entry.domain] = DeduplicatedMalicious(
                domain=entry.domain,
                sources=[entry.source],
                category=entry.category,
            )
    return list(seen.values())


def deduplicate_benign(entries: list[BenignEntry]) -> list[BenignEntry]:
    """Deduplicate by domain. Keep highest rank (lowest number = most popular)."""
    seen: dict[str, BenignEntry] = {}
    for entry in entries:
        if entry.domain in seen:
            existing = seen[entry.domain]
            if entry.rank < existing.rank:
                seen[entry.domain] = entry
        else:
            seen[entry.domain] = entry
    return list(seen.values())


# ---------------------------------------------------------------------------
# Stats display
# ---------------------------------------------------------------------------


def print_stats(stats: PipelineStats) -> None:
    """Print dataset statistics."""
    print(f"\n{'=' * 60}")
    print("Dataset Statistics")
    print(f"{'=' * 60}")

    print("\nPer-source counts:")
    print(f"  {'Source':<25s} {'Raw':>10s}  {'After dedup':>12s}")
    print(f"  {'-' * 25} {'-' * 10}  {'-' * 12}")
    for src in stats.sources:
        print(f"  {src.name:<25s} {src.raw_count:>10,}  {src.after_dedup:>12,}")

    print(f"\nTotals:")
    print(f"  Malicious (raw):       {stats.total_malicious_raw:>10,}")
    print(f"  Malicious (dedup):     {stats.total_malicious_dedup:>10,}")
    print(f"  Benign (raw):          {stats.total_benign_raw:>10,}")
    print(f"  Benign (dedup):        {stats.total_benign_dedup:>10,}")
    print(f"  Overlap removed:       {stats.overlap_removed:>10,}")

    if stats.category_breakdown:
        print(f"\nMalicious category breakdown:")
        for cat, count in sorted(stats.category_breakdown.items(), key=lambda x: -x[1]):
            print(f"  {cat:<20s} {count:>10,}")

    total = stats.total_malicious_dedup + stats.total_benign_dedup
    if total > 0:
        mal_pct = stats.total_malicious_dedup / total * 100
        ben_pct = stats.total_benign_dedup / total * 100
        print(f"\nFinal dataset:")
        print(f"  Total:                 {total:>10,}")
        print(f"  Malicious:             {stats.total_malicious_dedup:>10,} ({mal_pct:.1f}%)")
        print(f"  Benign:                {stats.total_benign_dedup:>10,} ({ben_pct:.1f}%)")
        if stats.total_malicious_dedup > 0:
            ratio = stats.total_benign_dedup / stats.total_malicious_dedup
            print(f"  Ratio (benign:mal):    1:{ratio:.1f}")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def build_tranco_registrable_map(benign_entries: list[BenignEntry]) -> dict[str, int]:
    """Build registrable_domain -> best rank mapping from benign entries."""
    mapping: dict[str, int] = {}
    for entry in benign_entries:
        if entry.source != "tranco":
            continue
        ext = tldextract.extract(entry.domain)
        registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        if registrable not in mapping or entry.rank < mapping[registrable]:
            mapping[registrable] = entry.rank
    return mapping


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build curated ML training dataset from multiple sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  uv run python build_dataset.py                           # full build
  uv run python build_dataset.py --stats-only              # show stats only
  uv run python build_dataset.py --max-per-source 50000    # cap per source
  uv run python build_dataset.py --skip-extrahop           # skip large download
  uv run python build_dataset.py --ch-url http://127.0.0.1:8123  # include traffic
""",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "dataset.parquet",
        help="Output path (default: data/dataset.parquet)",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Show stats without saving",
    )
    parser.add_argument(
        "--max-per-source",
        type=int,
        default=None,
        help="Cap domains per source",
    )
    parser.add_argument(
        "--tranco-count",
        type=int,
        default=1_000_000,
        help="Tranco top N (default: 1000000)",
    )
    parser.add_argument(
        "--majestic-count",
        type=int,
        default=1_000_000,
        help="Majestic top N (default: 1000000)",
    )
    parser.add_argument(
        "--control-url",
        type=str,
        default=None,
        help="Control plane URL — fetch well-known domains from DB instead of downloading",
    )
    parser.add_argument(
        "--ch-url",
        type=str,
        default=None,
        help="ClickHouse URL for traffic benign (optional)",
    )
    parser.add_argument(
        "--ch-user",
        type=str,
        default="nameserver",
        help="ClickHouse user (default: nameserver)",
    )
    parser.add_argument(
        "--ch-password",
        type=str,
        default=None,
        help="ClickHouse password (or CH_PASSWORD env)",
    )
    parser.add_argument(
        "--ch-database",
        type=str,
        default="nameserver",
        help="ClickHouse database (default: nameserver)",
    )
    parser.add_argument(
        "--skip-extrahop",
        action="store_true",
        help="Skip ExtraHop (fast iteration without large download)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    max_ps = args.max_per_source
    stats = PipelineStats()

    # ------------------------------------------------------------------
    # 1. Pull malicious sources
    # ------------------------------------------------------------------
    print("Pulling malicious sources:")
    all_malicious: list[MaliciousEntry] = []

    malicious_fetchers: list[tuple[str, object]] = [
        ("urlhaus", lambda: fetch_urlhaus(max_ps)),
        ("urlhaus_full", lambda: fetch_urlhaus_full(max_ps)),
        ("phishtank", lambda: fetch_phishtank(max_ps)),
        ("threatfox", lambda: fetch_threatfox(max_ps)),
        ("phishing_database", lambda: fetch_phishing_database(max_ps)),
        ("openphish", lambda: fetch_openphish(max_ps)),
        ("jpcertcc", lambda: fetch_jpcertcc(max_ps)),
        ("phiusiil", lambda: fetch_phiusiil(max_ps)),
        ("c2intelfeeds", lambda: fetch_c2intelfeeds(max_ps)),
        ("threatmon", lambda: fetch_threatmon_c2(max_ps)),
        ("blackbook", lambda: fetch_stamparm_blackbook(max_ps)),
        ("chrmor_dga", lambda: fetch_chrmor_dga(max_ps)),
    ]

    if not args.skip_extrahop:
        malicious_fetchers.append(
            ("extrahop_dga", lambda: fetch_extrahop_dga(max_ps))
        )
    else:
        print("  [extrahop_dga] SKIPPED (--skip-extrahop)")

    for name, fetcher in malicious_fetchers:
        try:
            entries = fetcher()
            raw_count = len(entries)
            all_malicious.extend(entries)
            stats.sources.append(SourceStats(name=name, raw_count=raw_count))
        except (requests.RequestException, IOError, json.JSONDecodeError) as e:
            print(f"    WARNING: {name} failed: {e}")
            stats.sources.append(SourceStats(name=name, raw_count=0))

    stats.total_malicious_raw = len(all_malicious)

    # Deduplicate malicious
    print(f"\nDeduplicating {len(all_malicious):,} raw malicious entries ...")
    deduped_malicious = deduplicate_malicious(all_malicious)
    stats.total_malicious_dedup = len(deduped_malicious)
    print(f"  -> {len(deduped_malicious):,} unique malicious domains")

    # Per-source dedup counts
    source_domain_counts: dict[str, int] = {}
    for entry in deduped_malicious:
        for src in entry.sources:
            source_domain_counts[src] = source_domain_counts.get(src, 0) + 1
    for src_stat in stats.sources:
        src_stat.after_dedup = source_domain_counts.get(src_stat.name, 0)

    # Category breakdown
    for entry in deduped_malicious:
        cat = entry.category
        stats.category_breakdown[cat] = stats.category_breakdown.get(cat, 0) + 1

    # ------------------------------------------------------------------
    # 2. Pull benign sources
    # ------------------------------------------------------------------
    print("\nPulling benign sources:")
    all_benign: list[BenignEntry] = []

    if args.control_url:
        # Fetch from control plane database (unified well-known list)
        try:
            well_known_entries = fetch_well_known(args.control_url)
            stats.sources.append(SourceStats(name="well_known", raw_count=len(well_known_entries)))
            all_benign.extend(well_known_entries)
            # Use well_known entries as tranco_entries for ClickHouse traffic matching
            tranco_entries = well_known_entries
        except (requests.RequestException, IOError) as e:
            print(f"    WARNING: well_known fetch failed: {e}")
            tranco_entries = []
            stats.sources.append(SourceStats(name="well_known", raw_count=0))
    else:
        # Fallback: download directly from external sources
        # Tranco
        try:
            tranco_entries = fetch_tranco(args.tranco_count, max_ps)
            stats.sources.append(SourceStats(name="tranco", raw_count=len(tranco_entries)))
            all_benign.extend(tranco_entries)
        except (requests.RequestException, IOError) as e:
            print(f"    WARNING: tranco failed: {e}")
            tranco_entries = []
            stats.sources.append(SourceStats(name="tranco", raw_count=0))

        # Majestic
        try:
            majestic_entries = fetch_majestic(args.majestic_count, max_ps)
            stats.sources.append(SourceStats(name="majestic", raw_count=len(majestic_entries)))
            all_benign.extend(majestic_entries)
        except (requests.RequestException, IOError) as e:
            print(f"    WARNING: majestic failed: {e}")
            stats.sources.append(SourceStats(name="majestic", raw_count=0))

    # ClickHouse traffic (optional)
    if args.ch_url is not None:
        ch_password = args.ch_password
        if ch_password is None:
            ch_password = os.environ.get("CH_PASSWORD", "")
        if not ch_password:
            print("    WARNING: ClickHouse password not provided (--ch-password or CH_PASSWORD env). Skipping traffic source.")
        else:
            tranco_registrable = build_tranco_registrable_map(tranco_entries)
            if not tranco_registrable:
                print("    WARNING: No Tranco registrable domains available. Skipping traffic source.")
            else:
                try:
                    traffic_entries = fetch_clickhouse_traffic(
                        ch_url=args.ch_url,
                        ch_user=args.ch_user,
                        ch_password=ch_password,
                        ch_database=args.ch_database,
                        tranco_registrable=tranco_registrable,
                        max_per_source=max_ps,
                    )
                    stats.sources.append(SourceStats(name="traffic", raw_count=len(traffic_entries)))
                    all_benign.extend(traffic_entries)
                except (requests.RequestException, IOError) as e:
                    print(f"    WARNING: ClickHouse traffic failed: {e}")
                    stats.sources.append(SourceStats(name="traffic", raw_count=0))
    else:
        # No ClickHouse URL: try local traffic_benign.csv as fallback
        tranco_registrable = build_tranco_registrable_map(tranco_entries)
        if tranco_registrable:
            traffic_entries = load_traffic_benign_local(tranco_registrable)
            if traffic_entries:
                stats.sources.append(SourceStats(name="traffic", raw_count=len(traffic_entries)))
                all_benign.extend(traffic_entries)

    stats.total_benign_raw = len(all_benign)

    # Deduplicate benign
    print(f"\nDeduplicating {len(all_benign):,} raw benign entries ...")
    deduped_benign = deduplicate_benign(all_benign)
    print(f"  -> {len(deduped_benign):,} unique benign domains")

    # ------------------------------------------------------------------
    # 3. Cross-check: resolve conflicts between malicious and benign
    # ------------------------------------------------------------------
    # Strategy:
    # - Tranco/Majestic top 10K domains ALWAYS stay benign (GitHub, Google, etc.
    #   appear in malware feeds because they host user content, not because
    #   the domains themselves are malicious)
    # - URL-derived malicious entries on well-known domains are dropped
    # - Direct domain IOCs override benign (if a domain is reported as a domain
    #   IOC, not extracted from a URL, it's a stronger signal)
    BENIGN_RANK_THRESHOLD = 10_000  # Tranco/Majestic rank below this = always benign

    benign_domain_set = {e.domain for e in deduped_benign}
    benign_rank_map = {e.domain: e.rank for e in deduped_benign if e.rank > 0}

    # Find conflicts
    malicious_domain_map: dict[str, DeduplicatedMalicious] = {e.domain: e for e in deduped_malicious}
    conflicts = benign_domain_set & set(malicious_domain_map.keys())

    kept_as_benign = 0
    removed_from_benign = 0
    removed_from_malicious = 0

    for domain in conflicts:
        rank = benign_rank_map.get(domain, 999_999)
        mal_entry = malicious_domain_map[domain]

        # High-rank benign domain (top 10K): always keep as benign, remove from malicious
        if rank <= BENIGN_RANK_THRESHOLD:
            deduped_malicious = [e for e in deduped_malicious if e.domain != domain]
            kept_as_benign += 1
            removed_from_malicious += 1
        else:
            # Lower-rank domain: check if malicious report is URL-derived only
            # If ALL malicious sources are URL-derived, keep as benign
            # If any source is a direct domain IOC, remove from benign
            # (DeduplicatedMalicious doesn't track ioc_type per source — use conservative approach)
            deduped_benign = [e for e in deduped_benign if e.domain != domain]
            removed_from_benign += 1

    stats.overlap_removed = removed_from_benign
    stats.total_benign_dedup = len(deduped_benign)

    print(f"  Conflicts: {len(conflicts)} domains in both sets")
    if kept_as_benign > 0:
        print(f"    Kept as benign (Tranco/Majestic top {BENIGN_RANK_THRESHOLD:,}): {kept_as_benign}")
    if removed_from_benign > 0:
        print(f"    Removed from benign: {removed_from_benign}")
    if removed_from_malicious > 0:
        print(f"    Removed from malicious: {removed_from_malicious}")

    # Update benign per-source dedup counts
    benign_source_counts: dict[str, int] = {}
    for entry in deduped_benign:
        benign_source_counts[entry.source] = benign_source_counts.get(entry.source, 0) + 1
    for src_stat in stats.sources:
        if src_stat.name in ("tranco", "majestic", "traffic", "well_known"):
            src_stat.after_dedup = benign_source_counts.get(src_stat.name, 0)

    # ------------------------------------------------------------------
    # 4. Print stats
    # ------------------------------------------------------------------
    print_stats(stats)

    # ------------------------------------------------------------------
    # 5. Save
    # ------------------------------------------------------------------
    if args.stats_only:
        print("\n--stats-only: not saving.")
        return

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nSaving dataset to {output_path} ...")
    import pandas as pd

    rows = []
    for entry in deduped_malicious:
        rows.append({
            "domain": entry.domain,
            "label": 1,
            "source": "|".join(entry.sources),
            "category": entry.category,
        })
    for entry in deduped_benign:
        rows.append({
            "domain": entry.domain,
            "label": 0,
            "source": entry.source,
            "category": entry.source,  # category = source name for benign
        })

    df = pd.DataFrame(rows)
    df["label"] = df["label"].astype("int8")

    if str(output_path).endswith(".parquet"):
        df.to_parquet(output_path, index=False)
    else:
        df.to_csv(output_path, index=False)

    mal_count = len(deduped_malicious)
    ben_count = len(deduped_benign)
    total = mal_count + ben_count
    print(f"  Saved {total:,} rows ({mal_count:,} malicious + {ben_count:,} benign)")
    print(f"  -> {output_path}")


if __name__ == "__main__":
    main()
