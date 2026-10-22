"""A/B comparison of two LightGBM models on real traffic from ClickHouse.

Enriches NRD features from nrd_domains.csv so the v3 model gets proper
is_nrd / nrd_age_days values (not NaN).

Usage:
    uv run python compare_models.py
    uv run python compare_models.py --n 500 --ch-port 8124
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import tldextract

from features import extract_group_a, features_to_dict, shannon_entropy, REGISTRAR_NS_PATTERNS
from predict_ch import fetch_flow_domains
from predict_test import get_split_embeddings, load_cnn_onnx

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"

# Must match scoring_chain.rs::nrd_max_age_days()
NRD_AGE_MAP: dict[str, int] = {
    "hagezi-nrd-7d": 7,
    "hagezi-nrd-14d": 14,
    "hagezi-nrd-21d": 21,
    "hagezi-nrd-28d": 28,
    "hagezi-nrd-35d": 35,
}


def load_nrd_set(nrd_csv: Path) -> dict[str, str]:
    """Load NRD domain → youngest slug mapping from CSV."""
    import csv

    nrd_map: dict[str, str] = {}
    if not nrd_csv.exists():
        return nrd_map
    with open(nrd_csv) as f:
        for row in csv.DictReader(f):
            domain = row["domain"].rstrip(".")
            slug = row["slug"]
            age = NRD_AGE_MAP.get(slug, 999)
            existing_age = NRD_AGE_MAP.get(nrd_map.get(domain, ""), 999)
            if age < existing_age:
                nrd_map[domain] = slug
    return nrd_map


def get_registrable(domain: str) -> str:
    ext = tldextract.extract(domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain


def build_features_for_model(
    row: dict,
    cnn_session: object | None,
    char_to_idx: dict[str, int] | None,
    cnn_meta: dict | None,
    feature_names: list[str],
    ordinal_maps: dict[str, dict[str, int]],
    nrd_map: dict[str, str],
) -> list[float]:
    """Build feature vector from a ClickHouse row, enriched with NRD."""
    domain = row["domain"].rstrip(".")

    # Group A: lexical
    feat = extract_group_a(domain)
    record = features_to_dict(feat)

    # Group B: from ClickHouse
    def safe_float(key: str, default: float | None = None) -> float | None:
        try:
            val = row.get(key)
            return float(val) if val else default
        except (ValueError, TypeError):
            return default

    def safe_int(key: str, default: int | None = None) -> int | None:
        try:
            val = row.get(key)
            return int(val) if val else default
        except (ValueError, TypeError):
            return default

    record["avg_auth_ttl"] = safe_float("avg_auth_ttl")
    record["a_record_count"] = safe_int("a_record_count", 0)
    record["has_cname"] = (safe_int("cname_depth", 0) or 0) > 0

    # NS from delegation chain (last = authoritative)
    auth_ns = (row.get("auth_ns") or "").strip().lower().rstrip(".")
    if auth_ns:
        ns_label = auth_ns.split(".")[0] if "." in auth_ns else auth_ns
        record["ns_name_entropy"] = shannon_entropy(ns_label)
        record["ns_name_length"] = len(auth_ns)

    # Supplement with ML Research profile NS data
    ns_json_raw = row.get("ns_json", "")
    if ns_json_raw:
        try:
            ns_records = json.loads(ns_json_raw) if isinstance(ns_json_raw, str) else {}
            ns_list = ns_records.get("ns", [])
            if ns_list:
                # NS can be str or dict — normalize
                first_ns = ns_list[0]
                if isinstance(first_ns, dict):
                    first_ns = first_ns.get("name", first_ns.get("target", ""))
                primary_ns = str(first_ns).lower().rstrip(".")
                if primary_ns:
                    ns_label = primary_ns.split(".")[0] if "." in primary_ns else primary_ns
                    record["ns_name_entropy"] = shannon_entropy(ns_label)
                    record["ns_name_length"] = len(primary_ns)
        except (json.JSONDecodeError, TypeError, IndexError):
            record["ns_name_entropy"] = None
            record["ns_name_length"] = None

    # CNAME target entropy
    cname_chain_str = row.get("cname_chain", "")
    if cname_chain_str:
        try:
            chain = json.loads(cname_chain_str) if isinstance(cname_chain_str, str) else []
            if chain:
                record["cname_target_entropy"] = shannon_entropy(chain[0])
        except (json.JSONDecodeError, TypeError):
            record["cname_target_entropy"] = None

    # NRD enrichment (authoritative — from nrd_domains.csv)
    registrable = get_registrable(domain)
    slug = nrd_map.get(registrable)
    if slug is not None:
        record["is_nrd"] = True
        record["nrd_age_days"] = NRD_AGE_MAP[slug]
    else:
        record["is_nrd"] = False
        # nrd_age_days stays None → NaN

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


# Hosting platforms (must match scoring_chain.rs)
HOSTING_PLATFORMS: list[str] = [
    "vercel.app", "netlify.app", "pages.dev", "herokuapp.com",
    "github.io", "firebaseapp.com", "web.app", "weebly.com",
    "wixsite.com", "squarespace.com", "wordpress.com", "blogspot.com",
    "azurewebsites.net", "appspot.com", "pythonanywhere.com",
    "glitch.me", "repl.co", "surge.sh", "fly.dev",
]


def load_well_known_set() -> set[str]:
    """Load Tranco/Majestic registrable domains as well-known set."""
    wk: set[str] = set()
    for csv_name in ("benign_domains.csv", "cdn_benign_domains.csv"):
        csv_path = DATA_DIR / csv_name
        if csv_path.exists():
            import csv as csv_mod
            with open(csv_path) as f:
                for row in csv_mod.DictReader(f):
                    wk.add(get_registrable(row["domain"]))
    return wk


def simulate_chain(
    ml_score: float,
    domain: str,
    well_known: set[str],
    nrd_map: dict[str, str],
) -> tuple[float, str, str]:
    """Simplified scoring chain simulation.

    Returns (final_score, verdict, explanation).
    Simulates Steps 1, 2, 5, 7 (no PG-dependent steps: NS trust, similarity).
    Assumes ns_trust=stable for well-known domains (production behavior).
    """
    registrable = get_registrable(domain)
    explanations: list[str] = []

    # Step 1: Well-known fast path
    if registrable in well_known:
        final = min(ml_score, 0.05)
        return final, "safe", "well-known"

    # Step 2: ML threshold gate
    if ml_score < 0.15:
        return ml_score, "safe", "low-ml"

    adjustment = 0.0

    # Step 5: NRD graduated adjustment
    slug = nrd_map.get(registrable)
    if slug is not None:
        age = NRD_AGE_MAP.get(slug, 35)
        nrd_adj = {7: 0.15, 14: 0.10, 21: 0.07, 28: 0.05, 35: 0.03}.get(age, 0.03)
        adjustment += nrd_adj
        explanations.append(f"nrd+{nrd_adj:.2f}")

    # Step 7: Hosting platform (simplified — no brand/keyword check)
    domain_lower = domain.lower()
    is_hosting = any(domain_lower.endswith(f".{h}") for h in HOSTING_PLATFORMS)
    if is_hosting:
        adjustment -= 0.1  # clean hosting (no impersonation detection without seeds)
        explanations.append("hosting-0.10")

    final = max(0.0, min(1.0, ml_score + adjustment))
    v = "malicious" if final >= 0.9 else "suspicious" if final >= 0.5 else "unknown" if final >= 0.1 else "safe"
    return final, v, "+".join(explanations) if explanations else "chain"


def verdict(prob: float) -> str:
    if prob >= 0.9:
        return "MALICIOUS"
    if prob >= 0.5:
        return "suspicious"
    if prob >= 0.1:
        return "unknown"
    return "safe"


def main() -> None:
    parser = argparse.ArgumentParser(description="A/B model comparison on real traffic")
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--ch-port", type=int, default=8124)
    parser.add_argument("--model-a", type=str, default=str(MODELS_DIR / "lgb_v2"),
                        help="Model A (baseline)")
    parser.add_argument("--model-b", type=str, default=str(MODELS_DIR / "20260409_070141"),
                        help="Model B (new with NRD)")
    parser.add_argument("--cnn", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    parser.add_argument("--nrd-csv", type=str, default=str(DATA_DIR / "nrd_domains.csv"))
    args = parser.parse_args()

    # Load models
    dir_a, dir_b = Path(args.model_a), Path(args.model_b)
    model_a = lgb.Booster(model_file=str(dir_a / "model.lgb"))
    model_b = lgb.Booster(model_file=str(dir_b / "model.lgb"))
    meta_a = json.load(open(dir_a / "metadata.json"))
    meta_b = json.load(open(dir_b / "metadata.json"))

    cnn_session, char_to_idx, cnn_meta = load_cnn_onnx(Path(args.cnn))

    # Load NRD set and well-known set
    nrd_map = load_nrd_set(Path(args.nrd_csv))
    well_known = load_well_known_set()
    print(f"NRD set: {len(nrd_map):,} domains loaded")
    print(f"Well-known set: {len(well_known):,} domains loaded")

    print(f"Model A: {dir_a.name} ({meta_a['n_features']} features)")
    print(f"Model B: {dir_b.name} ({meta_b['n_features']} features)")

    # Fetch from ClickHouse
    print(f"\nFetching {args.n} flow domains from ClickHouse ...")
    rows = fetch_flow_domains(args.ch_port, args.n)
    print(f"  Got {len(rows)} domains")
    if not rows:
        print("No domains. Is the CH tunnel up? (ssh -f -N -L 8124:localhost:8123 root@127.0.0.1)")
        return

    # Build features and predict for both models
    X_a = [build_features_for_model(r, cnn_session, char_to_idx, cnn_meta,
                                     meta_a["feature_names"], meta_a.get("ordinal_maps", {}),
                                     nrd_map) for r in rows]
    X_b = [build_features_for_model(r, cnn_session, char_to_idx, cnn_meta,
                                     meta_b["feature_names"], meta_b.get("ordinal_maps", {}),
                                     nrd_map) for r in rows]

    probs_a = model_a.predict(np.array(X_a))
    probs_b = model_b.predict(np.array(X_b))

    # Show domains where scores differ significantly
    diffs: list[tuple[str, float, float, float, bool]] = []
    nrd_domains: list[tuple[str, float, float, int]] = []
    for i, r in enumerate(rows):
        domain = r["domain"].rstrip(".")
        pa, pb = probs_a[i], probs_b[i]
        diff = pb - pa
        registrable = get_registrable(domain)
        is_nrd = registrable in nrd_map
        if is_nrd:
            age = NRD_AGE_MAP.get(nrd_map[registrable], 0)
            nrd_domains.append((domain, pa, pb, age))
        if abs(diff) > 0.01:
            diffs.append((domain, pa, pb, diff, is_nrd))

    # NRD domains in traffic
    if nrd_domains:
        print(f"\n{'='*90}")
        print(f"NRD domains in real traffic ({len(nrd_domains)}):")
        print(f"{'Domain':<50s} {'v2':>7s} {'v3':>7s} {'Δ':>7s} {'Age':>4s}")
        print("-" * 90)
        for domain, pa, pb, age in sorted(nrd_domains, key=lambda x: x[2], reverse=True):
            d = pb - pa
            print(f"  {domain:<48s} {pa:>7.4f} {pb:>7.4f} {d:>+7.4f} {age:>3d}d")

    # Significant score changes
    if diffs:
        print(f"\n{'='*90}")
        print(f"Significant score changes (|Δ| > 0.01): {len(diffs)}")
        print(f"{'Domain':<50s} {'v2':>7s} {'v3':>7s} {'Δ':>7s} {'NRD':>4s}")
        print("-" * 90)
        for domain, pa, pb, d, is_nrd in sorted(diffs, key=lambda x: abs(x[3]), reverse=True)[:30]:
            nrd_flag = " NRD" if is_nrd else ""
            print(f"  {domain:<48s} {pa:>7.4f} {pb:>7.4f} {d:>+7.4f}{nrd_flag}")

    # Verdict flips
    flips = [(rows[i]["domain"].rstrip("."), probs_a[i], probs_b[i])
             for i in range(len(rows))
             if verdict(probs_a[i]) != verdict(probs_b[i])]
    if flips:
        print(f"\n{'='*90}")
        print(f"Verdict flips: {len(flips)}")
        for domain, pa, pb in flips:
            print(f"  {domain:<48s} {verdict(pa):>10s} ({pa:.4f}) → {verdict(pb):>10s} ({pb:.4f})")
    else:
        print(f"\nNo verdict flips.")

    # ── Scoring chain simulation ──
    chain_a: list[tuple[float, str, str]] = []
    chain_b: list[tuple[float, str, str]] = []
    for i, r in enumerate(rows):
        domain = r["domain"].rstrip(".")
        chain_a.append(simulate_chain(probs_a[i], domain, well_known, nrd_map))
        chain_b.append(simulate_chain(probs_b[i], domain, well_known, nrd_map))

    chain_flips = [(rows[i]["domain"].rstrip("."), chain_a[i], chain_b[i])
                   for i in range(len(rows))
                   if chain_a[i][1] != chain_b[i][1]]

    print(f"\n{'='*90}")
    print(f"AFTER SCORING CHAIN (simulated Steps 1,2,5,7):")

    if chain_flips:
        print(f"\n  Verdict flips: {len(chain_flips)} (was {len(flips)} raw ML)")
        print(f"  {'Domain':<50s} {'v2':>17s}  {'v3':>17s}")
        print(f"  {'-'*86}")
        for domain, (sa, va, ea), (sb, vb, eb) in sorted(chain_flips, key=lambda x: abs(x[2][0] - x[1][0]), reverse=True):
            note_a = f" ({ea})" if ea else ""
            note_b = f" ({eb})" if eb else ""
            print(f"  {domain:<50s} {va:>10s} {sa:.3f}{note_a:<6s}  {vb:>10s} {sb:.3f}{note_b}")
    else:
        print(f"\n  Verdict flips: 0 (was {len(flips)} raw ML)")

    # Summary stats
    print(f"\n{'='*90}")
    print("Summary (raw ML):")
    for label, probs in [("v2 (A)", probs_a), ("v3 (B)", probs_b)]:
        n_safe = sum(1 for p in probs if p < 0.1)
        n_unk = sum(1 for p in probs if 0.1 <= p < 0.5)
        n_susp = sum(1 for p in probs if 0.5 <= p < 0.9)
        n_mal = sum(1 for p in probs if p >= 0.9)
        print(f"  {label}: safe={n_safe} unknown={n_unk} suspicious={n_susp} malicious={n_mal}")

    print(f"\nSummary (after chain):")
    for label, chain in [("v2 (A)", chain_a), ("v3 (B)", chain_b)]:
        counts: dict[str, int] = {"safe": 0, "unknown": 0, "suspicious": 0, "malicious": 0}
        for _, v, _ in chain:
            counts[v] = counts.get(v, 0) + 1
        print(f"  {label}: safe={counts['safe']} unknown={counts['unknown']} suspicious={counts['suspicious']} malicious={counts['malicious']}")

    mean_diff = np.mean(probs_b - probs_a)
    abs_diff = np.mean(np.abs(probs_b - probs_a))
    print(f"\n  Raw ML — Mean Δ (B-A): {mean_diff:+.6f}  Mean |Δ|: {abs_diff:.6f}")
    chain_scores_a = np.array([s for s, _, _ in chain_a])
    chain_scores_b = np.array([s for s, _, _ in chain_b])
    chain_mean_diff = np.mean(chain_scores_b - chain_scores_a)
    chain_abs_diff = np.mean(np.abs(chain_scores_b - chain_scores_a))
    print(f"  Chain   — Mean Δ (B-A): {chain_mean_diff:+.6f}  Mean |Δ|: {chain_abs_diff:.6f}")
    corr = np.corrcoef(probs_a, probs_b)[0, 1]
    print(f"  Correlation (raw):      {corr:.6f}")


if __name__ == "__main__":
    main()
