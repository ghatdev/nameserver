"""Build the training dataset for the zero-second detector LightGBM.

See `docs/detector-lightgbm-design.md` for the full feature spec. This
script produces `data/detector_features.parquet` with ~52 tabular feature
columns + a `label` column (0 = benign, 1 = malicious) + the key columns
needed for registrable-stratified splitting.

CNN embedding columns are NOT produced here — they're added in a separate
step (`ml/embed_detector_dataset.py`, future) that loads the CNN ONNX and
embeds each domain's labels. This script emits the raw `domain`,
`registrable`, `cname_chain`, and `ns_names` columns that embedding needs.

Data sources:
- ClickHouse: `flow_novelty`, `flows`, `domain_velocity_5m`
- PostgreSQL: `domain_reputation`, `incident_labels`, `indicator_domains`,
  `sources`

Decisions applied (from design doc §10):
- Q1 Negative sampling: 3× positives (applied Python-side after label
  assignment)
- Q4 Blocked flows: excluded via `list_action = 'PASS'` filter
- Q5 Window: 90 days

Run:
    uv run ml/build_detector_dataset.py
    uv run ml/build_detector_dataset.py --days 30 --out data/detector_features_30d.parquet
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import clickhouse_connect
import numpy as np
import pandas as pd
import psycopg2
import psycopg2.extras

DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
DEFAULT_CH_HOST = "localhost"
DEFAULT_CH_PORT = 18123
DEFAULT_CH_DB = "nameserver"

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"

# Curated CDN / hosting registrable set. Conservative — only include
# registrables where >95% of subdomain traffic is benign CDN infra.
CDN_REGISTRABLES = frozenset(
    [
        "akadns.net",
        "akamaiedge.net",
        "akamaized.net",
        "edgekey.net",
        "edgesuite.net",
        "cloudfront.net",
        "cloudflare.com",
        "cloudflare.net",
        "fastly.net",
        "1e100.net",
        "googlevideo.com",
        "ytimg.com",
        "apple-dns.net",
        "aaplimg.com",
        "amazonaws.com",
        "azureedge.net",
        "llnwd.net",
        "stackpathcdn.com",
        "kxcdn.com",
        "jsdelivr.net",
        "unpkg.com",
        "gstatic.com",
        "gscdn.net",
    ]
)


# ---------------------------------------------------------------------------
# CH fetch — per-flow tabular features
# ---------------------------------------------------------------------------


def fetch_ch_flows(ch_client, days: int, limit: int | None) -> pd.DataFrame:
    """Join flow_novelty + flows + domain_velocity_5m. One row per flow.
    Excludes blocked flows per Q4 decision."""
    limit_clause = f"LIMIT {limit}" if limit else ""
    query = f"""
        SELECT
            n.flow_id                                       AS flow_id,
            n.started_at                                    AS started_at,
            n.domain                                        AS domain,
            n.registrable                                   AS registrable,
            n.profile_id                                    AS profile_id,
            n.geo_asn                                       AS geo_asn,
            n.is_first_contact                              AS is_first_contact,
            n.age_minutes_at_flow                           AS age_minutes_at_flow,
            f.total_ms                                      AS total_ms,
            f.response_auth_ttl                             AS auth_ttl,
            f.response_ttl                                  AS min_ttl,
            f.dnssec_status                                 AS dnssec_status,
            f.dnssec_algorithm                              AS dnssec_algorithm,
            f.dnssec_ds_present                             AS ds_present,
            f.dnssec_rrsig_expiry                           AS dnssec_rrsig_expiry,
            length(f.cname_chain)                           AS cname_chain_length,
            f.cname_chain                                   AS cname_chain,
            length(f.response_ips)                          AS response_ip_count,
            f.response_ips                                  AS response_ips,
            f.all_records_json                              AS all_records_json,
            f.rcode                                         AS rcode,
            f.qtype                                         AS qtype,
            -- resolution path stats
            length(f.resolution_path.step)                  AS path_depth,
            arrayReduce('sum',    f.resolution_path.ms)     AS path_ms_total,
            arrayReduce('max',    f.resolution_path.ms)     AS path_ms_max,
            arrayReduce(
                'quantileExactIf', f.resolution_path.ms,
                arrayMap(x -> 1, f.resolution_path.ms)
            )                                               AS path_ms_median,
            arrayReduce('stddevPop', f.resolution_path.ms)  AS path_ms_stddev,
            arrayCount(x -> x = 'Referral', f.resolution_path.response_type) AS n_referrals,
            arrayCount(x -> x = 'Answer',   f.resolution_path.response_type) AS n_answers,
            arrayCount(x -> x = 'NxDomain', f.resolution_path.response_type) AS n_nxdomains,
            -- NS names returned (for future CNN embedding)
            f.`resolution_path.server_name`                 AS path_server_names,
            -- velocity
            coalesce(v.query_count_5m, 0)                   AS query_count_5m,
            coalesce(v.distinct_profiles_5m, 0)             AS distinct_profiles_5m,
            coalesce(v.distinct_asns_5m, 0)                 AS distinct_asns_5m
          FROM flow_novelty n
    INNER JOIN flows f ON n.flow_id = f.flow_id
     LEFT JOIN (
            SELECT registrable,
                   toStartOfFiveMinute(window_start)    AS w,
                   countMerge(query_count_state)        AS query_count_5m,
                   uniqMerge(distinct_profiles_state)   AS distinct_profiles_5m,
                   uniqMerge(distinct_asns_state)       AS distinct_asns_5m
              FROM domain_velocity_5m
          GROUP BY registrable, w
          ) v ON v.registrable = n.registrable
             AND v.w = toStartOfFiveMinute(n.started_at)
         WHERE f.list_action = 'PASS'
           AND n.started_at >= now() - INTERVAL {days} DAY
      ORDER BY n.started_at DESC
        {limit_clause}
    """
    print(f"[CH] fetching flows (days={days}, limit={limit}) ...", flush=True)
    result = ch_client.query(query)
    df = pd.DataFrame(result.result_rows, columns=result.column_names)
    print(f"[CH] {len(df):,} rows", flush=True)
    return df


# ---------------------------------------------------------------------------
# Derived features (Python-side post-processing)
# ---------------------------------------------------------------------------


def derive_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute features that don't come straight from CH columns."""
    df = df.copy()

    # auth_ttl log-scale (long-tail distribution)
    df["auth_ttl_log1p"] = np.log1p(df["auth_ttl"].astype(np.float64))

    # rrsig expiry margin in hours (negative = expired)
    started_ts = pd.to_datetime(df["started_at"], utc=True).astype("int64") // 10**9
    # dnssec_rrsig_expiry is unix seconds (i64 in CH schema)
    expiry = df["dnssec_rrsig_expiry"].fillna(0).astype(np.int64)
    df["rrsig_expiry_margin_hours"] = (
        (expiry - started_ts).where(expiry > 0, 0) / 3600.0
    )

    # Record-type presence from all_records_json
    def parse_records(blob: str) -> dict:
        if not blob:
            return {}
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            return {}

    records = df["all_records_json"].map(parse_records)
    df["has_mx"] = records.map(lambda r: bool(r.get("mx"))).astype(np.int8)
    df["has_txt"] = records.map(lambda r: bool(r.get("txt"))).astype(np.int8)
    df["has_soa"] = records.map(lambda r: bool(r.get("soa"))).astype(np.int8)
    df["has_a"] = records.map(lambda r: bool(r.get("a"))).astype(np.int8)
    df["has_aaaa"] = records.map(lambda r: bool(r.get("aaaa"))).astype(np.int8)
    df["aaaa_without_a"] = ((df["has_aaaa"] == 1) & (df["has_a"] == 0)).astype(
        np.int8
    )

    # qtype × rcode cross
    df["qtype_x_rcode"] = df["qtype"].astype(str) + "_" + df["rcode"].astype(str)

    # IPv4 ratio + unique-IP count approximation (distinct by parse)
    def ipv4_ratio(ips) -> float:
        if not ips:
            return 0.0
        n = len(ips)
        v4 = sum(1 for ip in ips if ":" not in ip)
        return v4 / n

    df["response_ipv4_ratio"] = df["response_ips"].map(ipv4_ratio)

    # Known-CDN flag
    df["registrable_is_known_cdn"] = df["registrable"].isin(CDN_REGISTRABLES).astype(
        np.int8
    )

    return df


# ---------------------------------------------------------------------------
# PG enrichment — reputation, popularity, labels
# ---------------------------------------------------------------------------


def enrich_reputation(pg_url: str, df: pd.DataFrame) -> pd.DataFrame:
    """Left-join domain_reputation by registrable. Missing rows → NaN."""
    regs = df["registrable"].dropna().unique().tolist()
    if not regs:
        return df

    print(f"[PG] fetching reputation for {len(regs):,} registrables ...",
          flush=True)
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    registrable_domain,
                    ns_observation_count,
                    total_flow_count,
                    EXTRACT(EPOCH FROM (now() - first_seen))/86400.0 AS days_since_first_seen,
                    EXTRACT(EPOCH FROM (now() - last_ns_change_at))/86400.0 AS days_since_ns_change,
                    ns_trust
                  FROM domain_reputation
                 WHERE registrable_domain = ANY(%s)
                """,
                (regs,),
            )
            rows = cur.fetchall()

    rep_df = pd.DataFrame(
        rows,
        columns=[
            "registrable",
            "rep_ns_observation_count",
            "rep_total_flow_count",
            "rep_days_since_first_seen",
            "rep_days_since_ns_change",
            "rep_ns_trust",
        ],
    )
    print(f"[PG] reputation rows returned: {len(rep_df):,}", flush=True)
    merged = df.merge(rep_df, on="registrable", how="left")
    # rep_has_infra_data: presence of reputation row (NaN-guard for downstream)
    merged["rep_has_infra_data"] = (
        merged["rep_ns_observation_count"].notna().astype(np.int8)
    )
    return merged


def enrich_nrd(pg_url: str, df: pd.DataFrame) -> pd.DataFrame:
    """Flag whether the registrable is in any Hagezi NRD list (7/14/21/28/35d).
    NRD slugs follow `hagezi-nrd-Nd` pattern; bucketed age is the minimum Nd."""
    regs = df["registrable"].dropna().unique().tolist()
    if not regs:
        df["rep_is_nrd"] = 0
        df["rep_nrd_age_days"] = np.nan
        return df

    nrd_slugs = [
        ("hagezi-nrd-7d", 7),
        ("hagezi-nrd-14d", 14),
        ("hagezi-nrd-21d", 21),
        ("hagezi-nrd-28d", 28),
        ("hagezi-nrd-35d", 35),
    ]

    print(f"[PG] fetching NRD flags ...", flush=True)
    domain_to_age: dict[str, int] = {}
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            for slug, age in nrd_slugs:
                cur.execute("SELECT id FROM sources WHERE slug = %s", (slug,))
                row = cur.fetchone()
                if row is None:
                    continue
                src_id = row[0]
                cur.execute(
                    """
                    SELECT domain FROM indicator_domains
                     WHERE source = %s
                       AND domain = ANY(%s)
                    """,
                    (src_id, regs),
                )
                for (d,) in cur.fetchall():
                    if d not in domain_to_age or age < domain_to_age[d]:
                        domain_to_age[d] = age

    df = df.copy()
    df["rep_is_nrd"] = df["registrable"].isin(domain_to_age).astype(np.int8)
    df["rep_nrd_age_days"] = df["registrable"].map(domain_to_age).astype("Float32")
    print(f"[PG] NRD registrables in batch: {len(domain_to_age):,}", flush=True)
    return df


def enrich_popularity(pg_url: str, df: pd.DataFrame) -> pd.DataFrame:
    """Add tranco + majestic ranks + is_well_known by registrable."""
    regs = df["registrable"].dropna().unique().tolist()
    if not regs:
        df["registrable_tranco_rank"] = np.nan
        df["registrable_majestic_rank"] = np.nan
        df["rep_is_well_known"] = 0
        return df

    print(f"[PG] fetching popularity ranks ...", flush=True)
    tranco_ranks: dict[str, int] = {}
    majestic_ranks: dict[str, int] = {}

    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            for slug, target_dict in [
                ("tranco-100k", tranco_ranks),
                ("majestic-1m", majestic_ranks),
            ]:
                cur.execute("SELECT id FROM sources WHERE slug = %s", (slug,))
                row = cur.fetchone()
                if row is None:
                    continue
                src_id = row[0]
                cur.execute(
                    """
                    SELECT domain, rank FROM indicator_domains
                     WHERE source = %s
                       AND domain = ANY(%s)
                       AND rank IS NOT NULL
                    """,
                    (src_id, regs),
                )
                for d, r in cur.fetchall():
                    target_dict[d] = r

    df = df.copy()
    df["registrable_tranco_rank"] = df["registrable"].map(tranco_ranks).astype(
        "Float32"
    )
    df["registrable_majestic_rank"] = df["registrable"].map(majestic_ranks).astype(
        "Float32"
    )
    df["rep_is_well_known"] = (
        df["registrable"].isin(tranco_ranks)
        | df["registrable"].isin(majestic_ranks)
    ).astype(np.int8)
    return df


# ---------------------------------------------------------------------------
# Label assignment — join incident_labels
# ---------------------------------------------------------------------------


def assign_labels(pg_url: str, df: pd.DataFrame) -> pd.DataFrame:
    """Label each flow: 1 = malicious (FQDN or registrable in TIF),
    0 = benign (FQDN realtraffic_benign OR registrable in Tranco/Majestic),
    NaN = unlabeled (exclude from training).
    """
    print(f"[PG] loading DNS-layer labels ...", flush=True)
    with psycopg2.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT domain, verdict, source FROM incident_labels
                 WHERE layer = 'dns'
                """
            )
            rows = cur.fetchall()

    malicious_domains: set[str] = set()
    benign_fqdn: set[str] = set()
    benign_registrable: set[str] = set()
    for domain, verdict, source in rows:
        if verdict == "malicious":
            malicious_domains.add(domain)
        elif verdict == "benign":
            if source == "realtraffic":
                benign_fqdn.add(domain)
            else:
                # tranco / majestic — registrable-level
                benign_registrable.add(domain)
    print(
        f"[PG] labels: malicious={len(malicious_domains):,} "
        f"benign_fqdn={len(benign_fqdn):,} "
        f"benign_reg={len(benign_registrable):,}",
        flush=True,
    )

    df = df.copy()
    clean_domain = df["domain"].str.rstrip(".")
    df["_clean_domain"] = clean_domain

    # Priority: malicious FQDN > malicious registrable > benign FQDN > benign registrable > unlabeled
    label = pd.Series(np.nan, index=df.index, dtype="float32")
    label[clean_domain.isin(malicious_domains)] = 1.0
    label[df["registrable"].isin(malicious_domains)] = 1.0
    label[clean_domain.isin(benign_fqdn)] = 0.0
    benign_reg_mask = df["registrable"].isin(benign_registrable) & label.isna()
    label[benign_reg_mask] = 0.0
    df["label"] = label

    n_pos = int((label == 1.0).sum())
    n_neg = int((label == 0.0).sum())
    n_unlabeled = int(label.isna().sum())
    print(
        f"[labels] pos={n_pos:,} neg={n_neg:,} unlabeled={n_unlabeled:,} "
        f"(pos_rate={n_pos / max(1, n_pos + n_neg):.2%})",
        flush=True,
    )
    return df


def subsample_negatives(df: pd.DataFrame, ratio: float) -> pd.DataFrame:
    """Q1: stratified sample negatives down to `ratio` × positives.
    Unlabeled rows are kept as-is (for inference at train time)."""
    pos = df[df["label"] == 1.0]
    neg = df[df["label"] == 0.0]
    unl = df[df["label"].isna()]

    if len(pos) == 0:
        print(
            "[sample] pos=0 — no subsample applied (keep all negatives)",
            flush=True,
        )
        return df

    target_neg = int(len(pos) * ratio)
    if len(neg) <= target_neg:
        print(
            f"[sample] neg {len(neg):,} ≤ target {target_neg:,}; no subsample",
            flush=True,
        )
        return df

    # Stratify by registrable so we keep diversity across the negative space.
    neg_sampled = (
        neg.groupby("registrable", group_keys=False, observed=True)
        .apply(
            lambda g: g.sample(
                n=max(1, int(round(target_neg * len(g) / len(neg)))),
                random_state=42,
            ),
            include_groups=False,
        )
    )
    # groupby drops the grouping column with include_groups=False; add back
    neg_sampled = neg.loc[neg_sampled.index]

    combined = pd.concat([pos, neg_sampled, unl], axis=0).sort_values("started_at")
    print(
        f"[sample] pos={len(pos):,} neg={len(neg_sampled):,} "
        f"(from {len(neg):,}, ratio={len(neg_sampled)/max(1,len(pos)):.2f})",
        flush=True,
    )
    return combined.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def write_metadata(
    out_parquet: Path,
    df: pd.DataFrame,
    ch_host: str,
    days: int,
    cli_args: argparse.Namespace,
) -> None:
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ch_host": ch_host,
        "days": days,
        "rows": len(df),
        "pos_count": int((df["label"] == 1.0).sum()),
        "neg_count": int((df["label"] == 0.0).sum()),
        "unlabeled_count": int(df["label"].isna().sum()),
        "unique_registrables": int(df["registrable"].nunique()),
        "columns": list(df.columns),
        "cli_args": vars(cli_args),
        "fingerprint": hashlib.sha256(
            (",".join(sorted(df.columns))).encode()
        ).hexdigest(),
    }
    meta_path = out_parquet.with_suffix(".meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"[meta] wrote {meta_path}", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=90, help="Training window (Q5: 90d default)")
    parser.add_argument("--limit", type=int, default=None,
                        help="CH row cap for smoke tests")
    parser.add_argument("--out", type=str,
                        default=str(DATA_DIR / "detector_features.parquet"))
    parser.add_argument("--neg-ratio", type=float, default=3.0,
                        help="Q1: stratified sample of negatives to N× positives")
    parser.add_argument("--no-subsample", action="store_true",
                        help="Skip negative subsampling (keep full set)")
    args = parser.parse_args()

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    ch_host = os.environ.get("CH_HOST", DEFAULT_CH_HOST)
    ch_port = int(os.environ.get("CH_PORT", str(DEFAULT_CH_PORT)))
    ch_db = os.environ.get("CH_DB", DEFAULT_CH_DB)

    ch = clickhouse_connect.get_client(host=ch_host, port=ch_port, database=ch_db)

    df = fetch_ch_flows(ch, args.days, args.limit)
    if df.empty:
        print("[!] no flows in window; exiting", flush=True)
        return 0

    # UUID -> str so parquet can store it
    df["flow_id"] = df["flow_id"].astype(str)

    df = derive_features(df)
    df = enrich_reputation(pg_url, df)
    df = enrich_nrd(pg_url, df)
    df = enrich_popularity(pg_url, df)
    df = assign_labels(pg_url, df)

    # Compute confidence_active per row. This is the "does this flow's
    # resolution look like an active malicious response, or a cleaned-up
    # / parked / sinkholed one?" score. Training positives can be
    # filtered by this column to drop flows that reflect post-cleanup
    # state (see project_bulk_resolution_contamination.md). The column
    # is stored on EVERY row, including benign — the training script
    # decides how to use it.
    print("[score] computing confidence_active ...", flush=True)
    from confidence_active import score_row
    df["confidence_active"] = df.apply(score_row, axis=1).astype("float32")
    q = df["confidence_active"].quantile([0.05, 0.25, 0.5, 0.75, 0.95]).to_dict()
    print(f"[score] confidence_active quantiles: {q}", flush=True)

    if not args.no_subsample:
        df = subsample_negatives(df, args.neg_ratio)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    print(f"[out] wrote {len(df):,} rows × {len(df.columns)} cols to {out_path}",
          flush=True)

    write_metadata(out_path, df, ch_host, args.days, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
