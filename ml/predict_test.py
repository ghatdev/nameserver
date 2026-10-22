"""Quick prediction test: run new split-label CNN + LightGBM on real traffic domains.

Usage:
    uv run python predict_test.py
    uv run python predict_test.py --model models/lgb_maxpool --n 100
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import tldextract

from features import extract_group_a, features_to_dict

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


def load_cnn_onnx(model_dir: Path):
    """Load CNN ONNX model and metadata."""
    import onnxruntime as ort

    onnx_path = model_dir / "cnn_embedding.onnx"
    meta_path = model_dir / "cnn_metadata.json"
    if not onnx_path.exists():
        return None, None, None

    session = ort.InferenceSession(str(onnx_path))
    with open(meta_path) as f:
        meta = json.load(f)

    return session, meta["char_to_idx"], meta


def encode_label(label: str, char_to_idx: dict[str, int], max_len: int) -> np.ndarray:
    """Encode a single DNS label to character indices."""
    encoded = [char_to_idx.get(c, 0) for c in label.lower()[:max_len]]
    padded = encoded + [0] * (max_len - len(encoded))
    return np.array([padded], dtype=np.int64)


def get_label_embedding(session, label: str, char_to_idx: dict, meta: dict) -> np.ndarray:
    """Run CNN on a single label, return embedding vector."""
    input_name = meta.get("input_name", "label_chars")
    max_len = meta.get("max_len", 63)
    x = encode_label(label, char_to_idx, max_len)
    result = session.run(None, {input_name: x})
    return result[0][0]  # (embedding_dim,)


def get_split_embeddings(
    session, domain: str, char_to_idx: dict, meta: dict,
) -> dict[str, float]:
    """Get registrable + subdomain embeddings for a domain."""
    embedding_dim = meta.get("embedding_dim", 32)
    variant = meta.get("variant", "maxpool")
    max_slots = meta.get("max_subdomain_slots", 3)

    ext = tldextract.extract(domain)
    result: dict[str, float] = {}

    # Registrable label
    reg_label = ext.domain or ""
    if reg_label and session:
        reg_emb = get_label_embedding(session, reg_label, char_to_idx, meta)
        for i, val in enumerate(reg_emb):
            result[f"reg_emb_{i}"] = float(val)
    else:
        for i in range(embedding_dim):
            result[f"reg_emb_{i}"] = 0.0

    # Subdomain labels
    sub_labels = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []

    if variant == "maxpool":
        if sub_labels and session:
            sub_embs = np.array([
                get_label_embedding(session, s, char_to_idx, meta)
                for s in sub_labels
            ])
            pooled = sub_embs.max(axis=0)
        else:
            pooled = np.zeros(embedding_dim)
        for i in range(embedding_dim):
            result[f"sub_emb_{i}"] = float(pooled[i])
    else:
        for slot in range(max_slots):
            if slot < len(sub_labels) and session:
                emb = get_label_embedding(session, sub_labels[slot], char_to_idx, meta)
            else:
                emb = np.zeros(embedding_dim)
            for i in range(embedding_dim):
                result[f"sub{slot}_emb_{i}"] = float(emb[i])

    return result


def main():
    parser = argparse.ArgumentParser(description="Test predictions on real traffic domains")
    parser.add_argument("--model", type=str, default=str(MODELS_DIR / "lgb_maxpool"))
    parser.add_argument("--cnn", type=str, default=None, help="CNN model dir (auto-detect if not set)")
    parser.add_argument("--n", type=int, default=100, help="Number of domains to test")
    parser.add_argument("--threshold", type=float, default=0.9)
    args = parser.parse_args()

    model_dir = Path(args.model)

    # Load LightGBM model
    lgb_model = lgb.Booster(model_file=str(model_dir / "model.lgb"))
    with open(model_dir / "metadata.json") as f:
        lgb_meta = json.load(f)
    feature_names = lgb_meta["feature_names"]
    ordinal_maps = lgb_meta.get("ordinal_maps", {})
    print(f"LightGBM model: {len(feature_names)} features")

    # Load CNN model
    cnn_dir = Path(args.cnn) if args.cnn else MODELS_DIR / "label_cnn_maxpool"
    cnn_session, char_to_idx, cnn_meta = load_cnn_onnx(cnn_dir)
    if cnn_session:
        print(f"CNN model: {cnn_meta['embedding_dim']}-dim, variant={cnn_meta.get('variant', 'maxpool')}")
    else:
        print("CNN model: not loaded")

    # Load traffic domains
    traffic_path = DATA_DIR / "traffic_benign.csv"
    traffic_df = pd.read_csv(traffic_path)
    sample = traffic_df.sample(n=min(args.n, len(traffic_df)), random_state=42)
    domains = sample["domain"].tolist()
    print(f"\nTesting {len(domains)} real traffic domains (from {traffic_path.name})")

    # Run predictions
    results = []
    for domain in domains:
        # Group A features
        feat = extract_group_a(domain)
        record = features_to_dict(feat)

        # CNN embeddings
        emb = get_split_embeddings(cnn_session, domain, char_to_idx, cnn_meta)
        record.update(emb)

        # Build feature vector in model's expected order
        row = []
        for fname in feature_names:
            val = record.get(fname)
            if val is None:
                row.append(np.nan)
            elif isinstance(val, bool):
                row.append(1.0 if val else 0.0)
            elif isinstance(val, str):
                # Ordinal encoding
                if fname in ordinal_maps:
                    row.append(float(ordinal_maps[fname].get(val, -1)))
                else:
                    row.append(np.nan)
            else:
                row.append(float(val))

        results.append({"domain": domain, "features": row})

    # Batch predict
    X = np.array([r["features"] for r in results])
    probs = lgb_model.predict(X)

    # Display results
    flagged = []
    print(f"\n{'Domain':<55s} {'Score':>7s}  {'Verdict':>10s}")
    print("-" * 78)
    for i, r in enumerate(results):
        prob = probs[i]
        verdict = "MALICIOUS" if prob >= args.threshold else ("suspicious" if prob >= 0.5 else "safe")
        if prob >= 0.5:
            flagged.append((r["domain"], prob, verdict))
        if prob >= 0.3:  # only show domains with some signal
            print(f"  {r['domain']:<53s} {prob:>7.4f}  {verdict:>10s}")

    # Summary
    n_safe = sum(1 for p in probs if p < 0.5)
    n_suspicious = sum(1 for p in probs if 0.5 <= p < args.threshold)
    n_malicious = sum(1 for p in probs if p >= args.threshold)
    print(f"\n{'='*78}")
    print(f"Summary ({len(domains)} traffic domains, all expected benign):")
    print(f"  Safe (<0.5):        {n_safe:>4d}  ({100*n_safe/len(domains):.1f}%)")
    print(f"  Suspicious (0.5-{args.threshold}): {n_suspicious:>4d}  ({100*n_suspicious/len(domains):.1f}%)")
    print(f"  Malicious (>={args.threshold}):   {n_malicious:>4d}  ({100*n_malicious/len(domains):.1f}%)")
    print(f"  FP rate (>=0.5):    {100*(n_suspicious+n_malicious)/len(domains):.1f}%")

    if flagged:
        print(f"\nFalse positives (score >= 0.5):")
        for domain, prob, verdict in sorted(flagged, key=lambda x: -x[1]):
            print(f"  {domain:<53s} {prob:.4f}  {verdict}")


if __name__ == "__main__":
    main()
