"""Import URLhaus IOCs (abuse.ch) into incident_labels.

URLhaus (https://urlhaus.abuse.ch) publishes recently-seen malware URLs.
We extract the FQDN from each URL and upsert into incident_labels with
verdict='malicious', source='urlhaus'.

Run from your local machine via the PG tunnel:
    uv run ml/import_urlhaus.py

Or from a control-plane shell with direct socket access:
    PGURL='dbname=nameserver user=nameserver host=/run/postgresql' \\
        uv run ml/import_urlhaus.py

The CSV feed updates frequently; running every 30-60 minutes from a cron /
systemd timer keeps the labels fresh. Idempotent (ON CONFLICT DO UPDATE).
"""

from __future__ import annotations

import csv
import io
import os
import sys
from datetime import datetime, timezone
from typing import Iterator

import psycopg2
import psycopg2.extras
import requests

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
SOURCE_NAME = "urlhaus"


def fetch_urlhaus_csv() -> str:
    """Fetch the recent-URLs CSV. Raises on HTTP error."""
    response = requests.get(URLHAUS_RECENT_CSV, timeout=60)
    response.raise_for_status()
    return response.text


def extract_domain(url: str) -> str | None:
    """Pull the host out of an http(s):// URL. Returns lowercase, no port."""
    if "://" not in url:
        return None
    after_scheme = url.split("://", 1)[1]
    host = after_scheme.split("/", 1)[0]
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip().lower()
    if not host or "." not in host:
        return None
    return host


def parse_rows(csv_text: str) -> Iterator[dict[str, str]]:
    """Yield rows from URLhaus CSV.

    URLhaus emits the header as a commented line (`# id,dateadded,url,...`),
    which csv.reader would skip as a comment. We hardcode the schema — it is
    documented and stable.
    """
    headers = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]
    data_lines = [
        line for line in csv_text.splitlines() if line and not line.startswith("#")
    ]
    if not data_lines:
        return
    reader = csv.reader(io.StringIO("\n".join(data_lines)))
    for raw in reader:
        if len(raw) != len(headers):
            continue
        yield dict(zip(headers, (v.strip().strip('"') for v in raw)))


def upsert_labels(pg_url: str, rows: list[dict[str, str]]) -> tuple[int, int]:
    """Upsert into incident_labels. Returns (inserted, skipped) counts."""
    if not rows:
        return 0, 0

    conn = psycopg2.connect(pg_url)
    conn.autocommit = False
    cur = conn.cursor()

    upsert_sql = (
        "INSERT INTO incident_labels "
        "(domain, source, labeled_at, first_seen_at, verdict, confidence, threat_type, extra) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (domain, source) DO UPDATE SET "
        "labeled_at = EXCLUDED.labeled_at, "
        "first_seen_at = LEAST(incident_labels.first_seen_at, EXCLUDED.first_seen_at), "
        "verdict = EXCLUDED.verdict, "
        "threat_type = EXCLUDED.threat_type, "
        "extra = incident_labels.extra || EXCLUDED.extra"
    )

    now = datetime.now(timezone.utc)
    inserted = 0
    skipped = 0
    batch: list[tuple] = []

    for row in rows:
        url = row.get("url", "")
        domain = extract_domain(url)
        if domain is None:
            skipped += 1
            continue
        first_seen_raw = row.get("dateadded", "")
        first_seen_at: datetime | None
        try:
            first_seen_at = datetime.strptime(first_seen_raw, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            first_seen_at = None
        threat = row.get("threat") or "malware_url"
        tags = row.get("tags") or ""
        extra = {
            "url": url,
            "url_status": row.get("url_status"),
            "tags": tags,
            "reporter": row.get("reporter"),
            "urlhaus_link": row.get("urlhaus_link"),
        }
        batch.append((
            domain,
            SOURCE_NAME,
            now,
            first_seen_at if first_seen_at is not None else now,
            "malicious",
            None,
            threat,
            psycopg2.extras.Json(extra),
        ))
        inserted += 1

    psycopg2.extras.execute_batch(cur, upsert_sql, batch, page_size=500)
    conn.commit()
    cur.close()
    conn.close()
    return inserted, skipped


def main() -> int:
    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    print(f"Fetching {URLHAUS_RECENT_CSV} ...", flush=True)
    csv_text = fetch_urlhaus_csv()
    rows = list(parse_rows(csv_text))
    print(f"Parsed {len(rows)} rows", flush=True)
    inserted, skipped = upsert_labels(pg_url, rows)
    print(f"Upserted {inserted} labels (skipped {skipped} unparseable URLs)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
