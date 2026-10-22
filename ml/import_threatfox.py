"""Import ThreatFox IOCs (abuse.ch) into incident_labels.

ThreatFox (https://threatfox.abuse.ch) publishes IOCs by category — domain,
url, ip:port, hash. We extract domain-class IOCs (ioc_type='domain' or
'url') and upsert with verdict='malicious', source='threatfox'.

Run from your local machine via the PG tunnel:
    uv run ml/import_threatfox.py

The CSV feed publishes recent IOCs; pair with a 30-60 minute cron / timer.
Idempotent (ON CONFLICT DO UPDATE).
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

THREATFOX_RECENT_CSV = "https://threatfox.abuse.ch/export/csv/recent/"
DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
SOURCE_NAME = "threatfox"


def fetch_threatfox_csv() -> str:
    response = requests.get(THREATFOX_RECENT_CSV, timeout=60)
    response.raise_for_status()
    return response.text


def extract_domain_from_url(url: str) -> str | None:
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


def normalize_domain_ioc(value: str) -> str | None:
    """For ioc_type='domain' the value is `host:port` or `host`. Strip port."""
    value = value.strip().strip('"').lower()
    if not value:
        return None
    if ":" in value:
        value = value.split(":", 1)[0]
    if "." not in value:
        return None
    return value


def parse_rows(csv_text: str) -> Iterator[dict[str, str]]:
    """Yield rows from ThreatFox CSV.

    Like URLhaus, the header is a commented line — we hardcode the column
    schema (documented + stable).
    """
    headers = [
        "first_seen_utc",
        "ioc_id",
        "ioc_value",
        "ioc_type",
        "threat_type",
        "fk_malware",
        "malware_alias",
        "malware_printable",
        "last_seen_utc",
        "confidence_level",
        "is_compromised",
        "reference",
        "tags",
        "anonymous",
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
        "confidence = EXCLUDED.confidence, "
        "threat_type = EXCLUDED.threat_type, "
        "extra = incident_labels.extra || EXCLUDED.extra"
    )

    now = datetime.now(timezone.utc)
    inserted = 0
    skipped = 0
    batch: list[tuple] = []

    for row in rows:
        ioc_type = (row.get("ioc_type") or "").strip().lower()
        ioc_value = row.get("ioc_value") or ""
        if ioc_type == "domain":
            domain = normalize_domain_ioc(ioc_value)
        elif ioc_type == "url":
            domain = extract_domain_from_url(ioc_value)
        else:
            skipped += 1
            continue
        if domain is None:
            skipped += 1
            continue

        first_seen_raw = row.get("first_seen_utc") or ""
        first_seen_at: datetime | None
        try:
            first_seen_at = datetime.strptime(first_seen_raw, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            first_seen_at = None

        confidence_raw = row.get("confidence_level") or ""
        try:
            confidence = float(confidence_raw) / 100.0 if confidence_raw else None
        except ValueError:
            confidence = None

        threat = row.get("threat_type") or row.get("fk_malware") or "ioc"
        extra = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "fk_malware": row.get("fk_malware"),
            "malware_alias": row.get("malware_alias"),
            "malware_printable": row.get("malware_printable"),
            "is_compromised": row.get("is_compromised"),
            "tags": row.get("tags"),
            "reporter": row.get("reporter"),
        }

        batch.append((
            domain,
            SOURCE_NAME,
            now,
            first_seen_at if first_seen_at is not None else now,
            "malicious",
            confidence,
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
    print(f"Fetching {THREATFOX_RECENT_CSV} ...", flush=True)
    csv_text = fetch_threatfox_csv()
    rows = list(parse_rows(csv_text))
    print(f"Parsed {len(rows)} rows", flush=True)
    inserted, skipped = upsert_labels(pg_url, rows)
    print(f"Upserted {inserted} labels (skipped {skipped} non-domain rows)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
