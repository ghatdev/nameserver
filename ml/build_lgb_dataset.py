"""Build curated LightGBM training dataset.

Reads resolved.parquet (single source for Group B/C/D/E),
computes Group A features from domain names,
merges CNN embeddings, outputs lgb_features.parquet.

Pipeline:
    dataset.parquet (2.87M) → CNN → embeddings.parquet
    dataset.parquet → resolve_data.py → resolved.parquet (200K, full features)
    resolved.parquet + embeddings → THIS SCRIPT → lgb_features.parquet → train.py

Usage:
    uv run python build_lgb_dataset.py
    uv run python build_lgb_dataset.py --resolved data/resolved.parquet
    uv run python build_lgb_dataset.py --max-per-category 50000
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

import pandas as pd
import tldextract

from features import (
    DATA_DIR,
    extract_group_a,
    features_to_dict,
    load_tranco_ranks,
    shannon_entropy,
)

MODELS_DIR = Path(__file__).parent / "models"

# Known sinkhole IPs — resolved malicious domains pointing here have
# law enforcement / security researcher infrastructure, not attacker infra.
# Sources: Shadowserver, CERT.PL, abuse.ch, FBI, Kaspersky, Microsoft, etc.
SINKHOLE_IPS: set[str] = {
    "0.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.9",
    # Shadowserver
    "87.106.24.200", "87.106.26.9", "87.106.253.18", "213.165.83.176", "50.21.181.152",
    # Kaspersky
    "93.159.228.22", "95.211.172.143",
    # Microsoft
    "131.253.18.11", "131.253.18.12", "204.95.99.59",
    # CERT.PL
    "148.81.111.111", "148.81.111.91", "148.81.111.114",
    # Arbor
    "23.253.126.58", "168.181.184.35",
    # abuse.ch
    "208.43.245.213", "173.192.192.10", "199.231.211.108", "198.98.120.157",
    "192.42.116.41", "192.42.119.41", "104.155.47.38", "87.255.51.229",
    # FBI
    "142.0.36.234", "74.81.170.108", "74.81.170.109", "74.81.170.110",
    "66.212.148.115", "74.208.15.160",
    # Palo Alto
    "72.5.65.111", "198.135.184.22",
    # Registrar parking
    "34.102.136.180", "34.98.99.30", "198.54.117.210", "198.54.117.211",
    # Others
    "166.78.144.80", "67.215.255.139", "192.169.69.25", "193.166.255.171",
    "74.200.48.169", "91.186.66.36", "139.146.167.25",
    "176.31.62.76", "178.32.140.251", "94.23.175.2",
    "95.211.174.92", "106.187.96.49",
}

SINKHOLE_RANGES: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("74.82.47.0/24"),      # Shadowserver
    ipaddress.ip_network("184.105.139.0/24"),    # Shadowserver
    ipaddress.ip_network("184.105.143.0/24"),    # Shadowserver
    ipaddress.ip_network("184.105.192.0/24"),    # Shadowserver
    ipaddress.ip_network("184.105.247.192/26"),  # Shadowserver
    ipaddress.ip_network("195.22.26.192/26"),    # AnubisNetworks/BitSight
    ipaddress.ip_network("199.2.137.0/24"),      # Microsoft
    ipaddress.ip_network("207.46.90.0/24"),      # Microsoft
    ipaddress.ip_network("143.215.130.0/24"),    # Georgia Tech
    ipaddress.ip_network("104.244.12.0/22"),     # Farsight
    ipaddress.ip_network("198.54.117.0/24"),     # Namecheap parking
]


def is_sinkholed(ips_json: str) -> bool:
    """Check if resolved IPs indicate a sinkholed domain."""
    try:
        ips = json.loads(ips_json) if isinstance(ips_json, str) else ips_json
    except (json.JSONDecodeError, TypeError):
        return False
    if not ips:
        return False
    first_ip = ips[0]
    if first_ip in SINKHOLE_IPS:
        return True
    try:
        addr = ipaddress.ip_address(first_ip)
        for net in SINKHOLE_RANGES:
            if addr in net:
                return True
    except ValueError:
        return False
    return False


# Hagezi NRD source slug → upper-bound age in days.
# Must match scoring_chain.rs::nrd_max_age_days().
NRD_AGE_MAP: dict[str, int] = {
    "hagezi-nrd-7d": 7,
    "hagezi-nrd-14d": 14,
    "hagezi-nrd-21d": 21,
    "hagezi-nrd-28d": 28,
    "hagezi-nrd-35d": 35,
}


FREE_HOSTING_PATTERNS: list[str] = [
    "vercel.app", "netlify.app", "pages.dev", "herokuapp.com",
    "firebaseapp.com", "github.io", "weebly.com", "wixsite.com",
    "squarespace.com", "wordpress.com", "blogspot.com", "web.app",
    "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
    "appspot.com", "pythonanywhere.com", "glitch.me",
]


def find_latest_cnn_embeddings() -> Path | None:
    """Auto-detect the latest CNN embeddings."""
    cnn_dirs = sorted(MODELS_DIR.glob("cnn_*"), reverse=True)
    for d in cnn_dirs:
        for ext in ("parquet", "csv"):
            emb_path = d / f"embeddings.{ext}"
            if emb_path.exists():
                return emb_path
    return None


def extract_groupb_features(row: pd.Series) -> dict:
    """Extract Group B (infrastructure) features from a resolved.parquet row.

    v2: only 5 features, matching feature-design.md.
    """
    features: dict = {}

    # Group B: Infrastructure
    features["avg_auth_ttl"] = row.get("ttl")  # authoritative TTL
    features["a_record_count"] = row.get("a_record_count", 0)
    features["has_cname"] = bool(row.get("cname_depth", 0) > 0)

    # NS infrastructure (from ns_servers JSON)
    ns_servers: list[str] = []
    try:
        ns_raw = row.get("ns_servers", "[]")
        ns_servers = json.loads(ns_raw) if isinstance(ns_raw, str) else []
    except (ValueError, TypeError):
        ns_servers = []

    if ns_servers:
        primary_ns = ns_servers[0].lower().rstrip(".")
        features["ns_name_entropy"] = shannon_entropy(primary_ns.split(".")[0])
        features["ns_name_length"] = len(primary_ns)
    else:
        features["ns_name_entropy"] = None
        features["ns_name_length"] = None

    # Group F: cname_target_entropy (the only Group F feature from resolution data;
    # ns_observation_count, well_known_rank_norm, domain_seen_days come from
    # domain_reputation in the enrichment step below)
    try:
        cname_raw = row.get("cname_chain", "[]")
        cname_chain = json.loads(cname_raw) if isinstance(cname_raw, str) else []
        if cname_chain:
            features["cname_target_entropy"] = shannon_entropy(cname_chain[0])
        else:
            features["cname_target_entropy"] = None
    except (ValueError, TypeError):
        features["cname_target_entropy"] = None

    return features


def main() -> None:
    parser = argparse.ArgumentParser(description="Build curated LightGBM training dataset")
    parser.add_argument(
        "--dataset", type=str, default=str(DATA_DIR / "dataset.parquet"),
        help="Full dataset (for labels + categories)",
    )
    parser.add_argument(
        "--resolved", type=str, default=str(DATA_DIR / "resolved.parquet"),
        help="Resolved domains with Group B/C/D/E features",
    )
    parser.add_argument(
        "--max-per-category", type=int, default=None,
        help="Max domains per category (default: no limit)",
    )
    parser.add_argument(
        "--cnn-embeddings", type=str, default=None,
        help="Path to CNN embeddings (default: auto-detect latest)",
    )
    parser.add_argument(
        "--reputation-csv", type=str, default=str(DATA_DIR / "reputation_export.csv"),
        help="Group F: domain_reputation export "
             "(registrable_domain, ns_observation_count, last_ns_change_at). "
             "Export with: \\copy (SELECT registrable_domain, ns_observation_count, "
             "last_ns_change_at FROM domain_reputation) TO 'reputation_export.csv' CSV HEADER",
    )
    parser.add_argument(
        "--nrd-csv", type=str, default=str(DATA_DIR / "nrd_domains.csv"),
        help="NRD domain export from indicator_domains (domain, slug). "
             "Authoritative source — every training domain is checked against this.",
    )
    parser.add_argument(
        "--output", type=str, default=str(DATA_DIR / "lgb_features_v2.parquet"),
        help="Output path",
    )
    args = parser.parse_args()

    # Load resolved.parquet — single source for Group B/C/D/E
    resolved_path = Path(args.resolved)
    if not resolved_path.exists():
        print(f"Resolved data not found: {resolved_path}")
        print("Run: uv run python resolve_data.py --sample 100000")
        raise SystemExit(1)

    print(f"Loading resolved data from {resolved_path.name} ...")
    resolved_df = pd.read_parquet(resolved_path)
    resolved_ok = resolved_df[resolved_df["error"] == ""]
    print(f"  {len(resolved_df):,} total, {len(resolved_ok):,} resolved successfully")

    # Filter sinkholed domains — their infrastructure belongs to law enforcement,
    # not the original attacker. Keeps domain for Group A but nulls Group B.
    sinkholed_mask = resolved_ok["ips"].apply(is_sinkholed)
    n_sinkholed = sinkholed_mask.sum()
    if n_sinkholed > 0:
        resolved_ok = resolved_ok[~sinkholed_mask]
        print(f"  Removed {n_sinkholed:,} sinkholed domains")

    # Load full dataset for labels + categories
    dataset_path = Path(args.dataset)
    ds = pd.read_parquet(dataset_path)
    print(f"  Dataset: {len(ds):,} domains")

    # Join resolved with dataset to get labels + categories
    candidates = resolved_ok.merge(ds[["domain", "label", "category"]], on="domain", how="inner")
    print(f"  Candidates (resolved ∩ dataset): {len(candidates):,}")

    # Per-category stats
    print(f"\nPer-category:")
    for cat in candidates["category"].value_counts().index:
        count = (candidates["category"] == cat).sum()
        print(f"  {cat:<20s} {count:>8,}")

    # Sample per category if max_per_category is set
    if args.max_per_category is not None:
        sampled_parts = []
        for cat in candidates["category"].unique():
            cat_df = candidates[candidates["category"] == cat]
            if len(cat_df) > args.max_per_category:
                cat_df = cat_df.sample(n=args.max_per_category, random_state=42)
            sampled_parts.append(cat_df)
        candidates = pd.concat(sampled_parts, ignore_index=True)
        print(f"\nAfter sampling (max {args.max_per_category:,} per category): {len(candidates):,}")

    # Load CNN embeddings (split-label format: reg_emb_*, sub_emb_* or sub0_emb_*)
    cnn_path: Path | None = None
    if args.cnn_embeddings:
        cnn_path = Path(args.cnn_embeddings)
    else:
        cnn_path = find_latest_cnn_embeddings()

    embeddings: dict[str, dict[str, float]] = {}
    emb_cols: list[str] = []
    if cnn_path and cnn_path.exists():
        print(f"\nLoading CNN embeddings from {cnn_path.name} ...")
        if str(cnn_path).endswith(".parquet"):
            emb_df = pd.read_parquet(cnn_path)
        else:
            emb_df = pd.read_csv(cnn_path)
        # Auto-detect embedding columns (reg_emb_*, sub_emb_*, sub0_emb_*, etc.)
        emb_cols = [c for c in emb_df.columns if "_emb_" in c]
        for _, row in emb_df.iterrows():
            embeddings[row["domain"]] = {c: float(row[c]) for c in emb_cols}
        print(f"  {len(embeddings):,} embeddings ({len(emb_cols)} features)")

    # Load tranco ranks (metadata only, excluded from training)
    tranco_ranks = load_tranco_ranks()

    # Build features
    print(f"\nExtracting features for {len(candidates):,} domains ...")
    records: list[dict] = []
    emb_hits = 0

    for i, (_, row) in enumerate(candidates.iterrows()):
        if (i + 1) % 10000 == 0:
            print(f"  Processing {i + 1}/{len(candidates)} ...")

        domain = row["domain"]

        # Group A: lexical features from domain string
        feat = extract_group_a(domain)
        if domain in tranco_ranks:
            feat.tranco_rank = tranco_ranks[domain]
        record = features_to_dict(feat)

        # Group B/C/D/E: from resolved.parquet row
        groupb = extract_groupb_features(row)
        record.update(groupb)

        # Labels + metadata
        record["label"] = int(row["label"])
        record["category"] = row["category"]

        # CNN embeddings (split-label: reg_emb_*, sub_emb_* or sub0_emb_*)
        if domain in embeddings:
            record.update(embeddings[domain])
            emb_hits += 1
        else:
            for col in emb_cols:
                record[col] = 0.0

        records.append(record)

    df = pd.DataFrame(records)
    print(f"\n  CNN embedding hits: {emb_hits:,} / {len(candidates):,}")

    # ── Group F enrichment ──
    # Two levels: FQDN-level (domains table) and registrable-level (domain_reputation).
    # FQDN-level for temporal trust, registrable-level for zone properties.

    def get_registrable(domain: str) -> str:
        ext = tldextract.extract(domain)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain

    df["_registrable"] = df["domain"].apply(get_registrable)

    # 1. Registrable-level: ns_observation_count + days_since_ns_change
    #    (both from domain_reputation).
    rep_path = Path(args.reputation_csv)
    if rep_path.exists():
        rep_df = pd.read_csv(
            rep_path,
            usecols=["registrable_domain", "ns_observation_count", "last_ns_change_at"],
            parse_dates=["last_ns_change_at"],
        )
        # Project last_ns_change_at into days_since_ns_change. NaT (NULL) stays
        # as NaN so LightGBM gets a missing-value signal, not a zero.
        now = pd.Timestamp.utcnow()
        if rep_df["last_ns_change_at"].dt.tz is None:
            rep_df["last_ns_change_at"] = rep_df["last_ns_change_at"].dt.tz_localize("UTC")
        rep_df["days_since_ns_change"] = (
            (now - rep_df["last_ns_change_at"]).dt.total_seconds() / 86400.0
        )
        rep_df = rep_df.drop(columns=["last_ns_change_at"]).rename(
            columns={"registrable_domain": "_registrable"}
        )

        for col in ["ns_observation_count", "days_since_ns_change"]:
            if col in df.columns:
                df = df.drop(columns=[col])
        before = len(df)
        df = df.merge(rep_df, on="_registrable", how="left")
        rep_hits = df["ns_observation_count"].notna().sum()
        change_hits = df["days_since_ns_change"].notna().sum()
        print(
            f"  Reputation enrichment: {rep_hits:,} / {before:,} matched "
            f"(days_since_ns_change populated for {change_hits:,})"
        )
    else:
        print(f"  WARNING: reputation CSV not found: {rep_path}")

    # 2. NRD enrichment (authoritative: directly from indicator_domains export).
    #    Every training domain is checked — is_nrd is always 0 or 1, never NaN.
    #    This avoids conflating "confirmed not NRD" with "unknown / no reputation row".
    #    Export: \copy (SELECT d.domain, s.slug FROM indicator_domains d
    #            JOIN sources s ON d.source = s.id JOIN enrichment_bindings eb
    #            ON eb.source_id = s.id WHERE eb.enrichment_type = 'nrd') TO 'nrd_domains.csv' CSV HEADER
    nrd_path = Path(args.nrd_csv)
    for col in ["is_nrd", "nrd_age_days"]:
        if col in df.columns:
            df = df.drop(columns=[col])
    if nrd_path.exists():
        nrd_df = pd.read_csv(nrd_path)
        # Build registrable → youngest slug mapping (smallest age = most dangerous)
        nrd_map: dict[str, str] = {}
        for _, nrd_row in nrd_df.iterrows():
            domain = str(nrd_row["domain"]).rstrip(".")
            slug = str(nrd_row["slug"])
            age = NRD_AGE_MAP.get(slug, 999)
            existing_age = NRD_AGE_MAP.get(nrd_map.get(domain, ""), 999)
            if age < existing_age:
                nrd_map[domain] = slug

        # Check every training domain against the NRD set
        def lookup_nrd(registrable: str) -> tuple[float, float | None]:
            slug = nrd_map.get(registrable)
            if slug is not None:
                return 1.0, float(NRD_AGE_MAP[slug])
            return 0.0, None

        nrd_results = df["_registrable"].apply(lookup_nrd)
        df["is_nrd"] = nrd_results.apply(lambda t: t[0])
        df["nrd_age_days"] = nrd_results.apply(lambda t: t[1])

        nrd_hits = int((df["is_nrd"] == 1.0).sum())
        print(f"  NRD enrichment: {nrd_hits:,} / {len(df):,} domains flagged as NRD")
    else:
        print(f"  WARNING: NRD CSV not found: {nrd_path} — is_nrd will be 0 for all domains")
        df["is_nrd"] = 0.0
        df["nrd_age_days"] = None

    # 3. Registrable-level: well_known_rank_norm (from local Tranco CSV)
    tranco_rank_map: dict[str, float] = {}
    for csv_name in ("benign_domains.csv", "cdn_benign_domains.csv"):
        csv_path = DATA_DIR / csv_name
        if csv_path.exists():
            import csv
            with open(csv_path) as f_csv:
                for row_csv in csv.DictReader(f_csv):
                    rank = int(row_csv["rank"])
                    registrable = get_registrable(row_csv["domain"])
                    tranco_rank_map[registrable] = rank / 1_000_000.0

    if "well_known_rank_norm" in df.columns:
        df = df.drop(columns=["well_known_rank_norm"])
    df["well_known_rank_norm"] = df["_registrable"].map(tranco_rank_map)
    rank_hits = df["well_known_rank_norm"].notna().sum()
    print(f"  Well-known rank enrichment: {rank_hits:,} / {len(df):,} domains matched")

    df = df.drop(columns=["_registrable"])

    # NaN handling: Group B/F features left as NaN when missing.
    # LightGBM handles NaN natively — model learns "missing = unknown."
    # Only fill a_record_count (0 = no records, different from "unknown").
    if "a_record_count" in df.columns:
        df["a_record_count"] = df["a_record_count"].fillna(0)

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False)

    n_mal = (df["label"] == 1).sum()
    n_ben = (df["label"] == 0).sum()
    print(f"\nSaved → {output_path}")
    print(f"  Shape: {df.shape}")
    print(f"  Malicious: {n_mal:,}")
    print(f"  Benign:    {n_ben:,}")
    print(f"  Ratio (benign:mal): {n_ben/n_mal:.1f}:1" if n_mal > 0 else "")

    print(f"\nCategory breakdown:")
    for cat in df["category"].value_counts().index:
        count = (df["category"] == cat).sum()
        print(f"  {cat:<20s} {count:>8,}")


if __name__ == "__main__":
    main()
