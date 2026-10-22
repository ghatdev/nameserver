"""Test model on real flow domains with full Group B features from PostgreSQL.

Queries the control plane PostgreSQL (via SSH tunnel on port 5433) for
recent flow domains that have resolution_history data, then runs the
split-label CNN + LightGBM model with complete features.

Usage:
    uv run python predict_live.py
    uv run python predict_live.py --n 200 --pg-port 5433
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import psycopg2
import tldextract

from features import extract_group_a, features_to_dict, shannon_entropy, REGISTRAR_NS_PATTERNS
from predict_test import get_split_embeddings, load_cnn_onnx

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


def fetch_flow_domains_with_infra(conninfo: str, n: int) -> list[dict]:
    """Fetch recent flow domains that have resolution_history data."""
    query = """
    WITH recent_domains AS (
        SELECT d.domain, d.query_count, d.first_seen
        FROM domains d
        WHERE d.query_count > 1
        ORDER BY d.last_seen DESC
        LIMIT %s
    )
    SELECT
        rd.domain,
        rd.query_count,
        EXTRACT(EPOCH FROM (NOW() - rd.first_seen)) / 86400.0 AS first_seen_days,
        -- Latest resolution
        rh.ttl AS avg_ttl,
        rh.ips,
        rh.cname_chain,
        rh.ns_servers,
        rh.mx_records,
        rh.dnssec_status,
        rh.a_record_count,
        rh.has_txt,
        -- IP info (first resolved IP)
        ip.geo_country,
        ip.asn_number AS ip_asn,
        ip.is_cdn,
        ip.is_bulletproof,
        ip.domain_count AS ip_domain_count,
        ip.malicious_count AS ip_malicious_count
    FROM recent_domains rd
    LEFT JOIN LATERAL (
        SELECT * FROM resolution_history
        WHERE domain = rd.domain
        ORDER BY resolved_at DESC LIMIT 1
    ) rh ON true
    LEFT JOIN LATERAL (
        SELECT i.* FROM domain_ips di
        JOIN ips i ON di.ip = i.ip
        WHERE di.domain = rd.domain
        ORDER BY di.last_seen DESC LIMIT 1
    ) ip ON true
    WHERE rh.domain IS NOT NULL
    ORDER BY rd.query_count DESC
    """

    rows = []
    with psycopg2.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute(query, (n * 2,))  # fetch extra to account for domains without resolution
            cols = [desc.name for desc in cur.description]
            for row in cur.fetchall():
                rows.append(dict(zip(cols, row)))
                if len(rows) >= n:
                    break

    return rows


def build_features(domain_row: dict, cnn_session, char_to_idx, cnn_meta, feature_names, ordinal_maps) -> list[float]:
    """Build full feature vector from PostgreSQL row + Group A + CNN."""
    domain = domain_row["domain"]

    # Group A: lexical features
    feat = extract_group_a(domain)
    record = features_to_dict(feat)

    # Group B: from PostgreSQL
    if domain_row.get("avg_ttl") is not None:
        record["avg_ttl"] = float(domain_row["avg_ttl"])

    ips = domain_row.get("ips") or []
    if isinstance(ips, str):
        ips = json.loads(ips)
    record["unique_ip_count"] = len(set(ips)) if ips else 0

    cname = domain_row.get("cname_chain") or []
    if isinstance(cname, str):
        cname = json.loads(cname)
    record["cname_depth"] = len(cname) if cname else 0

    record["dnssec_status"] = domain_row.get("dnssec_status") or "unknown"
    record["a_record_count"] = domain_row.get("a_record_count") or 0
    record["has_txt"] = bool(domain_row.get("has_txt"))

    # NS infrastructure
    ns = domain_row.get("ns_servers") or []
    if isinstance(ns, str):
        ns = json.loads(ns)
    if ns:
        record["ns_count"] = len(ns)
        primary_ns = ns[0].lower().rstrip(".")
        record["ns_name_entropy"] = shannon_entropy(primary_ns.split(".")[0])
        record["ns_name_length"] = len(primary_ns)
        record["ns_is_registrar_default"] = any(
            pat in primary_ns for pat in REGISTRAR_NS_PATTERNS
        )

    # MX
    mx = domain_row.get("mx_records") or []
    if isinstance(mx, str):
        mx = json.loads(mx)
    record["has_mx"] = len(mx) > 0 if mx else False

    # IP info
    if domain_row.get("geo_country"):
        record["ip_country"] = domain_row["geo_country"]
    if domain_row.get("ip_asn"):
        record["ip_asn"] = domain_row["ip_asn"]
    if domain_row.get("is_cdn") is not None:
        record["is_cdn"] = domain_row["is_cdn"]
    if domain_row.get("is_bulletproof") is not None:
        record["is_bulletproof"] = domain_row["is_bulletproof"]

    # First seen / query count
    if domain_row.get("first_seen_days") is not None:
        record["first_seen_days"] = float(domain_row["first_seen_days"])
    if domain_row.get("query_count") is not None:
        record["query_count"] = domain_row["query_count"]

    # CNN embeddings
    if cnn_session and char_to_idx and cnn_meta:
        emb = get_split_embeddings(cnn_session, domain, char_to_idx, cnn_meta)
        record.update(emb)

    # Build feature vector in model order
    row = []
    for fname in feature_names:
        val = record.get(fname)
        if val is None:
            row.append(np.nan)
        elif isinstance(val, bool):
            row.append(1.0 if val else 0.0)
        elif isinstance(val, str):
            if fname in ordinal_maps:
                row.append(float(ordinal_maps[fname].get(val, -1)))
            else:
                row.append(np.nan)
        else:
            row.append(float(val))

    return row


def main():
    parser = argparse.ArgumentParser(description="Test model on real flow domains from PostgreSQL")
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--pg-port", type=int, default=5433)
    parser.add_argument("--pg-user", type=str, default="nameserver_admin")
    parser.add_argument("--pg-password", type=str, default=None)
    parser.add_argument("--pg-db", type=str, default="nameserver")
    parser.add_argument("--model", type=str, default=str(MODELS_DIR / "lgb_maxpool"))
    parser.add_argument("--cnn", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    parser.add_argument("--threshold", type=float, default=0.9)
    args = parser.parse_args()

    password_part = f" password={args.pg_password}" if args.pg_password else ""
    conninfo = f"host=localhost port={args.pg_port} user={args.pg_user} dbname={args.pg_db}{password_part}"

    # Load models
    model_dir = Path(args.model)
    lgb_model = lgb.Booster(model_file=str(model_dir / "model.lgb"))
    with open(model_dir / "metadata.json") as f:
        lgb_meta = json.load(f)
    feature_names = lgb_meta["feature_names"]
    ordinal_maps = lgb_meta.get("ordinal_maps", {})

    cnn_dir = Path(args.cnn)
    cnn_session, char_to_idx, cnn_meta = load_cnn_onnx(cnn_dir)

    print(f"LightGBM: {len(feature_names)} features")
    print(f"CNN: {cnn_meta['embedding_dim']}-dim, variant={cnn_meta.get('variant')}" if cnn_meta else "CNN: not loaded")

    # Fetch domains from PostgreSQL
    print(f"\nFetching {args.n} flow domains from PostgreSQL (port {args.pg_port}) ...")
    rows = fetch_flow_domains_with_infra(conninfo, args.n)
    print(f"  Got {len(rows)} domains with resolution data")

    if not rows:
        print("No domains found. Is the SSH tunnel up?")
        return

    # Build features and predict
    X = []
    domains = []
    infra_counts = {"has_ttl": 0, "has_ip": 0, "has_ns": 0}
    for r in rows:
        fv = build_features(r, cnn_session, char_to_idx, cnn_meta, feature_names, ordinal_maps)
        X.append(fv)
        domains.append(r["domain"])
        if r.get("avg_ttl") is not None:
            infra_counts["has_ttl"] += 1
        if r.get("ip_asn"):
            infra_counts["has_ip"] += 1
        if r.get("ns_servers"):
            infra_counts["has_ns"] += 1

    print(f"  Infrastructure coverage: TTL={infra_counts['has_ttl']}, IP={infra_counts['has_ip']}, NS={infra_counts['has_ns']}")

    X_arr = np.array(X)
    probs = lgb_model.predict(X_arr)

    # Results
    print(f"\n{'Domain':<55s} {'Score':>7s}  {'Verdict':>10s}  {'TTL':>5s} {'IPs':>4s} {'ASN':>7s} {'Country':>3s}")
    print("-" * 100)

    flagged = []
    for i, r in enumerate(rows):
        prob = probs[i]
        verdict = "MALICIOUS" if prob >= args.threshold else ("suspicious" if prob >= 0.5 else "safe")
        if prob >= 0.3:
            ttl = str(int(r["avg_ttl"])) if r.get("avg_ttl") is not None else "-"
            ips = r.get("ips") or []
            if isinstance(ips, str):
                ips = json.loads(ips)
            n_ips = str(len(set(ips))) if ips else "-"
            asn = str(r.get("ip_asn") or "-")
            country = r.get("geo_country") or "-"
            print(f"  {r['domain']:<53s} {prob:>7.4f}  {verdict:>10s}  {ttl:>5s} {n_ips:>4s} {asn:>7s} {country:>3s}")
        if prob >= 0.5:
            flagged.append((r["domain"], prob, verdict))

    # Summary
    n_safe = sum(1 for p in probs if p < 0.5)
    n_susp = sum(1 for p in probs if 0.5 <= p < args.threshold)
    n_mal = sum(1 for p in probs if p >= args.threshold)

    print(f"\n{'='*100}")
    print(f"Summary ({len(rows)} flow domains with full Group B features):")
    print(f"  Safe (<0.5):        {n_safe:>4d}  ({100*n_safe/len(rows):.1f}%)")
    print(f"  Suspicious (0.5-{args.threshold}): {n_susp:>4d}  ({100*n_susp/len(rows):.1f}%)")
    print(f"  Malicious (>={args.threshold}):   {n_mal:>4d}  ({100*n_mal/len(rows):.1f}%)")
    print(f"  FP rate (>=0.5):    {100*(n_susp+n_mal)/len(rows):.1f}%")

    print(f"\nScore distribution:")
    for bucket, lo, hi in [("<0.1", 0, 0.1), ("0.1-0.3", 0.1, 0.3), ("0.3-0.5", 0.3, 0.5),
                            ("0.5-0.7", 0.5, 0.7), ("0.7-0.9", 0.7, 0.9), (">=0.9", 0.9, 1.01)]:
        count = sum(1 for p in probs if lo <= p < hi)
        bar = "#" * count
        print(f"  {bucket:>8s}: {count:>4d}  {bar}")


if __name__ == "__main__":
    main()
