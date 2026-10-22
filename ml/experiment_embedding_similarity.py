"""Quick experiment: Do general embedding models put confusing domains close together?

Tests whether models like all-MiniLM-L6 encode brand similarity for domain names.
No training — just inference with pretrained models.

Usage:
    uv run --with sentence-transformers python experiment_embedding_similarity.py
"""

from __future__ import annotations

import numpy as np
from sentence_transformers import SentenceTransformer

# Test pairs: (real brand domain, impersonation/typosquat)
# We want HIGH similarity for these
IMPERSONATION_PAIRS = [
    # Typosquatting (char substitution)
    ("amazon", "amaz0n"),
    ("google", "g00gle"),
    ("naver", "naverr"),
    ("kakao", "kaka0"),
    ("shinhan", "sh1nhan"),
    # Brand abbreviation (world knowledge needed)
    ("amazon", "a2z"),
    ("amazon", "amzn"),
    # Combosquatting
    ("amazon", "amazon-login"),
    ("naver", "naver-verify"),
    ("kakao", "kakao-pay-secure"),
    # Homoglyph-like
    ("microsoft", "rnicrosoft"),
    ("discord", "dlscord"),
    # With TLD
    ("amazon.com", "amaz0n.com"),
    ("naver.com", "naver-login.com"),
    ("kakao.com", "kaka0-verify.com"),
]

# These should have LOW similarity (unrelated domains)
UNRELATED_PAIRS = [
    ("amazon", "wikipedia"),
    ("google", "shinhan"),
    ("naver", "youtube"),
    ("kakao", "cloudflare"),
    ("amazon", "xpsiowkeoryxl"),  # DGA
    ("naver", "a8f3d2e1b9c7"),   # random hash
]


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def run_experiment(model_name: str) -> None:
    print(f"\n{'='*60}")
    print(f"Model: {model_name}")
    print(f"{'='*60}")

    model = SentenceTransformer(model_name)

    # Encode all domains
    all_domains = set()
    for a, b in IMPERSONATION_PAIRS + UNRELATED_PAIRS:
        all_domains.add(a)
        all_domains.add(b)

    domain_list = sorted(all_domains)
    embeddings = model.encode(domain_list)
    embed_map = {d: e for d, e in zip(domain_list, embeddings)}

    print("\nImpersonation pairs (want HIGH similarity):")
    print(f"  {'Brand':<20} {'Typosquat':<25} {'Cosine':>8}")
    print(f"  {'-'*55}")
    for brand, typo in IMPERSONATION_PAIRS:
        sim = cosine_similarity(embed_map[brand], embed_map[typo])
        marker = "✓" if sim > 0.7 else "✗"
        print(f"  {brand:<20} {typo:<25} {sim:>7.3f}  {marker}")

    print("\nUnrelated pairs (want LOW similarity):")
    print(f"  {'Domain A':<20} {'Domain B':<25} {'Cosine':>8}")
    print(f"  {'-'*55}")
    for a, b in UNRELATED_PAIRS:
        sim = cosine_similarity(embed_map[a], embed_map[b])
        marker = "✓" if sim < 0.5 else "✗"
        print(f"  {a:<20} {b:<25} {sim:>7.3f}  {marker}")


MODELS = [
    "all-MiniLM-L6-v2",           # 80MB, fast, general purpose
    "all-mpnet-base-v2",          # 420MB, best quality sentence-transformers
    "google/embeddinggemma-300m", # 300M params, Gemma 3 based, 100+ languages
]

if __name__ == "__main__":
    for model_name in MODELS:
        try:
            run_experiment(model_name)
        except Exception as e:
            print(f"\n{model_name}: failed — {e}")
