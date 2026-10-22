"""Test model on real flow domains with full features from ClickHouse.

Queries ClickHouse for flow domains and extracts ALL Group B features from
all_records_json (NS, MX, AAAA, A records), response_auth_ttl, and aggregated
flow data. No PostgreSQL needed.

Usage:
    uv run python predict_ch.py
    uv run python predict_ch.py --n 200 --ch-port 8124
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
from urllib.request import urlopen, Request

import lightgbm as lgb
import numpy as np
import tldextract

from features import extract_group_a, features_to_dict, shannon_entropy, REGISTRAR_NS_PATTERNS
from predict_test import get_split_embeddings, load_cnn_onnx

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


def ch_query(port: int, query: str) -> list[dict]:
    """Execute a ClickHouse query via HTTP, return list of dicts."""
    url = f"http://localhost:{port}/"
    req = Request(url, data=query.encode("utf-8"))
    with urlopen(req) as resp:
        text = resp.read().decode("utf-8")
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    return list(reader)


def fetch_flow_domains(port: int, n: int) -> list[dict]:
    """Fetch top flow domains with full infrastructure from ClickHouse.

    Combines regular traffic data (TTL, IPs, GeoIP) with ML Research profile
    data (NS, MX, TXT, SOA from explicit multi-type resolution).
    """
    query = f"""
    WITH traffic AS (
        SELECT
            domain,
            count() as query_count,
            avg(response_ttl) as avg_ttl,
            avg(response_auth_ttl) as avg_auth_ttl,
            max(length(response_ips)) as a_record_count,
            max(length(cname_chain)) as cname_depth,
            anyLastIf(geo_country, geo_country <> '') as ip_country,
            anyLastIf(geo_asn, geo_asn > 0) as ip_asn,
            anyLastIf(dnssec_status, dnssec_status <> '') as dnssec_status,
            countIf(qtype = 'AAAA' AND length(response_ips) > 0) as aaaa_hits,
            anyLastIf(
                resolution_path.server_name[length(resolution_path.server_name)],
                length(resolution_path.server_name) > 0
                AND resolution_path.server_name[length(resolution_path.server_name)] <> ''
            ) as auth_ns
        FROM nameserver.flows
        WHERE domain <> '' AND domain NOT LIKE '%arpa.' AND rcode = 'NOERROR'
        GROUP BY domain
        HAVING query_count >= 2
    ),
    ml_records AS (
        SELECT
            domain,
            anyIf(all_records_json, all_records_json LIKE '%"ns"%') as ns_json,
            anyIf(all_records_json, all_records_json LIKE '%"mx"%') as mx_json,
            anyIf(all_records_json, all_records_json LIKE '%"txt"%') as txt_json,
            anyIf(all_records_json, all_records_json LIKE '%"soa"%') as soa_json,
            anyIf(all_records_json, all_records_json LIKE '%"aaaa"%') as aaaa_json
        FROM nameserver.flows
        WHERE domain <> '' AND rcode = 'NOERROR'
        GROUP BY domain
    )
    SELECT
        t.domain,
        t.query_count,
        t.avg_ttl,
        t.avg_auth_ttl,
        t.a_record_count,
        t.cname_depth,
        t.ip_country,
        t.ip_asn,
        t.dnssec_status,
        t.aaaa_hits,
        t.auth_ns,
        m.ns_json,
        m.mx_json,
        m.txt_json,
        m.soa_json,
        m.aaaa_json
    FROM traffic t
    LEFT JOIN ml_records m ON t.domain = m.domain
    ORDER BY t.query_count DESC
    LIMIT {n}
    FORMAT TabSeparatedWithNames
    """
    return ch_query(port, query)


def parse_all_records(records_json: str) -> dict:
    """Extract Group B features from all_records_json."""
    result: dict = {}
    try:
        records = json.loads(records_json) if records_json else {}
    except (json.JSONDecodeError, TypeError):
        return result

    # NS records
    ns_list = records.get("ns", [])
    if ns_list:
        result["ns_count"] = len(ns_list)
        primary_ns = ns_list[0].lower().rstrip(".")
        ns_label = primary_ns.split(".")[0] if "." in primary_ns else primary_ns
        result["ns_name_entropy"] = shannon_entropy(ns_label)
        result["ns_name_length"] = len(primary_ns)
        result["ns_is_registrar_default"] = any(
            pat in primary_ns for pat in REGISTRAR_NS_PATTERNS
        )

    # MX records
    mx_list = records.get("mx", [])
    result["has_mx"] = len(mx_list) > 0

    # AAAA records
    aaaa_list = records.get("aaaa", [])
    result["has_aaaa"] = len(aaaa_list) > 0

    # SOA records
    soa = records.get("soa")
    if isinstance(soa, dict):
        result["soa_refresh"] = soa.get("refresh", 0)
        result["soa_minimum"] = soa.get("minimum", 0)

    # TXT records
    txt_list = records.get("txt", [])
    result["has_txt"] = len(txt_list) > 0

    return result


def build_features(row: dict, cnn_session, char_to_idx, cnn_meta,
                   feature_names: list[str], ordinal_maps: dict) -> list[float]:
    """Build full feature vector from ClickHouse row + Group A + CNN."""
    domain = row["domain"].rstrip(".")

    # Group A: lexical
    feat = extract_group_a(domain)
    record = features_to_dict(feat)

    # Group B: from ClickHouse aggregation
    def safe_float(key: str, default: float = 0.0) -> float | None:
        try:
            val = row.get(key)
            return float(val) if val else default
        except (ValueError, TypeError):
            return default

    def safe_int(key: str, default: int = 0) -> int | None:
        try:
            val = row.get(key)
            return int(val) if val else default
        except (ValueError, TypeError):
            return default

    record["avg_ttl"] = safe_float("avg_ttl")
    record["avg_auth_ttl"] = safe_float("avg_auth_ttl")
    record["a_record_count"] = safe_int("a_record_count")
    record["cname_depth"] = safe_int("cname_depth")
    record["dnssec_status"] = row.get("dnssec_status") or "unknown"

    # Unique IP count from aggregated array
    all_ips_str = row.get("all_ips", "[]")
    try:
        all_ips = json.loads(all_ips_str.replace("'", '"')) if isinstance(all_ips_str, str) else []
    except (json.JSONDecodeError, TypeError):
        all_ips = []
    record["unique_ip_count"] = len(set(all_ips))

    # has_aaaa from AAAA query hits
    aaaa_hits = safe_int("aaaa_hits")
    record["has_aaaa"] = (aaaa_hits or 0) > 0

    ip_country = row.get("ip_country", "")
    if ip_country:
        record["ip_country"] = ip_country

    # NS from delegation chain (always available from recursive resolution)
    auth_ns = (row.get("auth_ns") or "").strip().lower().rstrip(".")
    if auth_ns:
        record["ns_count"] = 1  # at least 1 NS known from delegation
        ns_label = auth_ns.split(".")[0] if "." in auth_ns else auth_ns
        record["ns_name_entropy"] = shannon_entropy(ns_label)
        record["ns_name_length"] = len(auth_ns)
        record["ns_is_registrar_default"] = any(
            pat in auth_ns for pat in REGISTRAR_NS_PATTERNS
        )

    # Supplement with ML Research profile data if available (NS list, MX, TXT, SOA, AAAA)
    for json_key in ("ns_json", "mx_json", "txt_json", "soa_json", "aaaa_json"):
        parsed = parse_all_records(row.get(json_key, ""))
        record.update(parsed)  # overwrites ns_count etc. if richer data available

    # CNN embeddings
    if cnn_session and char_to_idx and cnn_meta:
        emb = get_split_embeddings(cnn_session, domain, char_to_idx, cnn_meta)
        record.update(emb)

    # Build feature vector in model order
    fv: list[float] = []
    for fname in feature_names:
        val = record.get(fname)
        if val is None:
            fv.append(np.nan)
        elif isinstance(val, bool):
            fv.append(1.0 if val else 0.0)
        elif isinstance(val, str):
            if fname in ordinal_maps:
                fv.append(float(ordinal_maps[fname].get(val, -1)))
            else:
                fv.append(np.nan)
        else:
            fv.append(float(val))

    return fv


def main() -> None:
    parser = argparse.ArgumentParser(description="Test model on flow domains from ClickHouse")
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--ch-port", type=int, default=8124)
    parser.add_argument("--model", type=str, default=str(MODELS_DIR / "lgb_fresh"))
    parser.add_argument("--cnn", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    parser.add_argument("--threshold", type=float, default=0.9)
    args = parser.parse_args()

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
    if cnn_meta:
        print(f"CNN: {cnn_meta['embedding_dim']}-dim, variant={cnn_meta.get('variant')}")

    # Fetch from ClickHouse
    print(f"\nFetching {args.n} flow domains from ClickHouse (port {args.ch_port}) ...")
    rows = fetch_flow_domains(args.ch_port, args.n)
    print(f"  Got {len(rows)} domains")

    if not rows:
        print("No domains found. Is the SSH tunnel up?")
        return

    # Check feature coverage
    has_ns = sum(1 for r in rows if r.get("ns_json"))
    has_mx = sum(1 for r in rows if r.get("mx_json"))
    has_txt = sum(1 for r in rows if r.get("txt_json"))
    print(f"  Feature coverage: NS={has_ns}/{len(rows)}, MX={has_mx}/{len(rows)}, TXT={has_txt}/{len(rows)}")

    # Build features and predict
    X = [build_features(r, cnn_session, char_to_idx, cnn_meta, feature_names, ordinal_maps) for r in rows]
    probs = lgb_model.predict(np.array(X))

    # Results
    print(f"\n{'Domain':<55s} {'Score':>7s}  {'Verdict':>10s}  {'TTL':>5s} {'IPs':>4s} {'ASN':>7s} {'CC':>3s} {'Qry':>5s}")
    print("-" * 105)

    for i, r in enumerate(rows):
        prob = probs[i]
        domain = r["domain"].rstrip(".")
        verdict = "MALICIOUS" if prob >= args.threshold else ("suspicious" if prob >= 0.5 else "safe")

        ttl = str(int(float(r.get("avg_ttl", 0)))) if r.get("avg_ttl") else "-"
        all_ips_str = r.get("all_ips", "[]")
        try:
            n_ips = str(len(set(json.loads(all_ips_str.replace("'", '"')))))
        except (json.JSONDecodeError, TypeError, ValueError):
            n_ips = "-"
        asn = r.get("ip_asn", "-")
        cc = r.get("ip_country", "-")
        qry = r.get("query_count", "-")

        if prob >= 0.3:
            print(f"  {domain:<53s} {prob:>7.4f}  {verdict:>10s}  {ttl:>5s} {n_ips:>4s} {asn:>7s} {cc:>3s} {qry:>5s}")

    # Summary
    n_safe = sum(1 for p in probs if p < 0.5)
    n_susp = sum(1 for p in probs if 0.5 <= p < args.threshold)
    n_mal = sum(1 for p in probs if p >= args.threshold)

    print(f"\n{'='*105}")
    print(f"Summary ({len(rows)} flow domains with full ClickHouse features):")
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
