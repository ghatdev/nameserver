"""Test scoring chain behavior with similarity index on real + simulated domains.

Tests three scenarios:
1. Benign traffic domains (should be safe/low score)
2. litellm.cloud-style attacks (exact label match, different NS)
3. Similar-domain attacks (rnicrosoft, naver-login, etc.)

Usage:
    uv run python test_scoring_chain.py
"""

from __future__ import annotations

import json
from pathlib import Path

import msgpack
import numpy as np
import onnxruntime as ort
import tldextract

MODELS_DIR = Path(__file__).parent / "models"
COMPILED_DIR = Path(__file__).parent.parent / "compiled"


def load_index(path: Path) -> dict:
    """Load compiled similarity index."""
    with open(path, "rb") as f:
        return msgpack.unpackb(f.read(), raw=False)


def load_cnn(model_dir: Path):
    """Load CNN ONNX model."""
    meta_path = model_dir / "cnn_metadata.json"
    onnx_path = model_dir / "cnn_embedding.onnx"
    with open(meta_path) as f:
        meta = json.load(f)
    session = ort.InferenceSession(str(onnx_path))
    return session, meta


def embed_label(session, meta: dict, label: str) -> list[float]:
    """Embed a single label."""
    char_to_idx = meta["char_to_idx"]
    max_len = meta["max_len"]
    input_name = meta.get("input_name", "label_chars")
    chars = [char_to_idx.get(c, 0) for c in label.lower()[:max_len]]
    chars += [0] * (max_len - len(chars))
    result = session.run(None, {input_name: np.array([chars], dtype=np.int64)})
    return result[0][0].tolist()


def cosine_similarity(a: list[float], b: list[float]) -> float:
    a_arr = np.array(a)
    b_arr = np.array(b)
    dot = np.dot(a_arr, b_arr)
    norm = np.linalg.norm(a_arr) * np.linalg.norm(b_arr)
    return float(dot / norm) if norm > 1e-8 else 0.0


# NS provider matching (mirrors Rust similarity::ns_same_provider)
NS_PROVIDER_PATTERNS = [
    "cloudflare", "awsdns", "google", "azure-dns", "msft.net",
    "akamai", "akam.net", "ultradns", "nsone.net", "dynect",
    "vercel-dns", "dnsimple", "digitalocean", "linode", "vultr",
    "name-services", "domaincontrol", "registrar-servers",
    "hetzner", "ovh.net", "oracle.com",
]


def ns_same_provider(a: str, b: str) -> bool:
    a_l, b_l = a.lower(), b.lower()
    for pat in NS_PROVIDER_PATTERNS:
        if pat in a_l and pat in b_l:
            return True
    # Fallback 1: same registrable domain (ns1.proton.me and ns3.proton.me)
    a_ext = tldextract.extract(a)
    b_ext = tldextract.extract(b)
    if a_ext.registered_domain and a_ext.registered_domain == b_ext.registered_domain:
        return True
    # Fallback 2: same operator name across TLDs (ns1.naver.com and ns2.naver.jp)
    a_parts = a_l.rstrip(".").split(".")
    b_parts = b_l.rstrip(".").split(".")
    if len(a_parts) >= 2 and len(b_parts) >= 2:
        a_label = a_parts[-2]
        b_label = b_parts[-2]
        if a_label and len(a_label) >= 3 and a_label == b_label:
            return True
    return False


def compare_ns(auth_ns: str, known_ns_list: list[str]) -> str:
    if not known_ns_list:
        return "unknown"
    for known in known_ns_list:
        if ns_same_provider(auth_ns, known):
            return "same_infra"
    return "different_infra"


def simulate_chain(
    domain: str,
    auth_ns: str,
    ml_score: float,
    index: dict,
    cnn_session,
    cnn_meta: dict,
    is_nrd: bool = False,
) -> dict:
    """Simulate scoring chain logic in Python."""
    ext = tldextract.extract(domain)
    label = ext.domain
    embedding = embed_label(cnn_session, cnn_meta, label)

    signals = {
        "ml_score": ml_score,
        "ns_adj": 0.0,
        "similarity_adj": 0.0,
        "nrd_adj": 0.0,
    }
    adjustment = 0.0

    # Step 3.5: Similarity detection
    tier = None
    matched_domain = None
    ns_result = None

    # Tier 1: exact label match
    label_index = index.get("label_index", {})
    if label in label_index:
        known_domains = label_index[label]
        registrable = ext.registered_domain
        for known in known_domains:
            if known["domain"].rstrip(".") == registrable:
                continue  # self-match
            result = compare_ns(auth_ns, known["ns_domains"])
            if result == "same_infra":
                signals["similarity_adj"] = -0.2
                adjustment -= 0.2
                tier = "tier1_exact"
                matched_domain = known["domain"]
                ns_result = "same"
                break
            elif result == "different_infra":
                signals["similarity_adj"] = 0.3
                adjustment += 0.3
                tier = "tier1_exact"
                matched_domain = known["domain"]
                ns_result = "different"
                break

    # Tier 2: edit distance (confusable detection)
    if tier is None and len(label) >= 4:
        from features import levenshtein
        best_dist = 999
        best_match_label = None
        best_match_domains = None

        for known_label, known_domains_list in index.get("label_index", {}).items():
            if known_label == label:
                continue
            if abs(len(label) - len(known_label)) > 2:
                continue
            dist = levenshtein(label.lower(), known_label.lower())
            if 0 < dist <= 2 and dist < best_dist:
                max_len = max(len(label), len(known_label))
                if dist * 3 <= max_len:
                    best_dist = dist
                    best_match_label = known_label
                    best_match_domains = known_domains_list

        if best_match_label and best_match_domains:
            for known in best_match_domains:
                result = compare_ns(auth_ns, known["ns_domains"])
                if result == "same_infra":
                    signals["similarity_adj"] = -0.2
                    adjustment -= 0.2
                    tier = f"tier2_edit(d={best_dist})"
                    matched_domain = known["domain"]
                    ns_result = "same"
                    break
                elif result == "different_infra":
                    signals["similarity_adj"] = 0.3
                    adjustment += 0.3
                    tier = f"tier2_edit(d={best_dist})"
                    matched_domain = known["domain"]
                    ns_result = "different"
                    break
            if tier is None:
                tier = f"tier2_edit(d={best_dist},no_ns)"
                matched_domain = best_match_label

    # NRD
    if is_nrd:
        signals["nrd_adj"] = 0.15
        adjustment += 0.15

    final_score = max(0.0, min(1.0, ml_score + adjustment))

    if final_score >= 0.9:
        verdict = "malicious"
    elif final_score >= 0.5:
        verdict = "suspicious"
    elif final_score >= 0.1:
        verdict = "unknown"
    else:
        verdict = "safe"

    return {
        "domain": domain,
        "label": label,
        "auth_ns": auth_ns,
        "ml_score": ml_score,
        "final_score": final_score,
        "verdict": verdict,
        "tier": tier,
        "matched_domain": matched_domain,
        "ns_result": ns_result,
        "signals": signals,
    }


def main():
    # Load index and CNN
    index_path = COMPILED_DIR / "similarity_index.bin"
    if not index_path.exists():
        print(f"Index not found: {index_path}")
        print("Run: uv run python compile_similarity_index.py")
        return

    print("Loading similarity index ...")
    index = load_index(index_path)
    print(f"  Labels: {len(index['label_index']):,}")
    print(f"  Embeddings: {len(index['entries']):,}")

    cnn_session, cnn_meta = load_cnn(MODELS_DIR / "label_cnn_maxpool")
    print(f"  CNN: {cnn_meta['embedding_dim']}-dim\n")

    # Test scenarios
    test_cases = [
        # === Scenario 1: Benign traffic (should be safe) ===
        ("google.com", "ns4.google.com", 0.3, False,
         "Benign: google.com with real NS"),
        ("naver.com", "ns1.naver.com", 0.25, False,
         "Benign: naver.com with real NS"),
        ("api.anthropic.com", "gemma.ns.cloudflare.com", 0.4, False,
         "Benign: anthropic.com with Cloudflare NS"),
        ("calendar-api.proton.me", "ns1.proton.me", 0.5, False,
         "Benign: proton.me subdomain with real NS"),

        # === Scenario 2: litellm.cloud-style (exact label, different NS) ===
        ("litellm.cloud", "ns1.cheaphosting.xyz", 0.4, True,
         "ATTACK: litellm.cloud (exact label match, different NS, NRD)"),
        ("naver.xyz", "ns1.freedns.afraid.org", 0.5, True,
         "ATTACK: naver.xyz (exact label match, free DNS, NRD)"),
        ("kakao.cloud", "ns1.hostinger.com", 0.35, True,
         "ATTACK: kakao.cloud (exact label, cheap hosting NS, NRD)"),
        ("toss.top", "ns1.dnspod.net", 0.4, True,
         "ATTACK: toss.top (exact label, different NS, NRD)"),

        # === Scenario 3: Similar-domain attacks ===
        ("rnicrosoft.com", "ns1.cheaphosting.xyz", 0.6, True,
         "ATTACK: rnicrosoft (confusable rn→m, different NS)"),
        ("naver-login.com", "ns1.hostinger.com", 0.7, True,
         "ATTACK: naver-login (brand+keyword, different NS)"),
        ("g00gle.com", "ns1.freedns.afraid.org", 0.5, True,
         "ATTACK: g00gle (confusable 0→o, different NS)"),

        # === Edge cases ===
        ("google.co.kr", "ns4.google.com", 0.3, False,
         "Edge: google.co.kr with real Google NS (same operator)"),
        ("newstartup.com", "ns1.registrar-servers.com", 0.4, True,
         "Edge: new legitimate startup with registrar NS (no match expected)"),
    ]

    print(f"{'Description':<55s} {'ML':>5s} {'Final':>6s} {'Verdict':>10s}  {'Tier':>20s}  {'Match':>20s} {'NS':>10s}")
    print("-" * 140)

    for domain, auth_ns, ml_score, is_nrd, desc in test_cases:
        result = simulate_chain(domain, auth_ns, ml_score, index, cnn_session, cnn_meta, is_nrd)
        tier = result["tier"] or "-"
        matched = result["matched_domain"] or "-"
        ns_res = result["ns_result"] or "-"
        print(f"  {desc:<53s} {result['ml_score']:>5.2f} {result['final_score']:>6.3f} {result['verdict']:>10s}  {tier:>20s}  {matched:>20s} {ns_res:>10s}")

    # Summary
    print(f"\n{'='*140}")
    print("Expected behavior:")
    print("  - Benign: final_score < 0.5 (safe/unknown)")
    print("  - litellm-style: final_score raised by +0.3 (similarity) + 0.15 (NRD)")
    print("  - Similar-domain: if embedding matches above 0.85, same +0.3 adjustment")
    print("  - Edge cases: same operator → -0.2, no match → no adjustment")


if __name__ == "__main__":
    main()
