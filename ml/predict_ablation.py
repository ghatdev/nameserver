"""Ablation test: compare predictions with CNN vs without CNN embeddings.

Runs the same 100 traffic domains through LightGBM three ways:
  1. Group A + CNN embeddings (no Group B) — current predict_test.py
  2. Group A only (CNN zeroed, no Group B) — isolate CNN contribution
  3. CNN only (Group A zeroed) — isolate Group A contribution

Usage:
    uv run python predict_ablation.py
"""

from __future__ import annotations

import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import tldextract

from features import extract_group_a, features_to_dict
from predict_test import get_split_embeddings, load_cnn_onnx

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


def build_feature_row(
    domain: str,
    feature_names: list[str],
    ordinal_maps: dict,
    cnn_session,
    char_to_idx: dict | None,
    cnn_meta: dict | None,
    zero_cnn: bool = False,
    zero_group_a: bool = False,
) -> list[float]:
    """Build a single feature row for LightGBM prediction."""
    feat = extract_group_a(domain)
    record = features_to_dict(feat)

    # CNN embeddings
    if cnn_session and char_to_idx and cnn_meta:
        emb = get_split_embeddings(cnn_session, domain, char_to_idx, cnn_meta)
        record.update(emb)

    row = []
    for fname in feature_names:
        val = record.get(fname)

        # Zero out CNN features if requested
        if zero_cnn and "_emb_" in fname:
            row.append(0.0)
            continue

        # Zero out Group A features if requested
        if zero_group_a and "_emb_" not in fname:
            row.append(np.nan)
            continue

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
    model_dir = MODELS_DIR / "lgb_maxpool"
    cnn_dir = MODELS_DIR / "label_cnn_maxpool"

    lgb_model = lgb.Booster(model_file=str(model_dir / "model.lgb"))
    with open(model_dir / "metadata.json") as f:
        lgb_meta = json.load(f)
    feature_names = lgb_meta["feature_names"]
    ordinal_maps = lgb_meta.get("ordinal_maps", {})

    cnn_session, char_to_idx, cnn_meta = load_cnn_onnx(cnn_dir)

    # Load 100 traffic domains
    traffic_df = pd.read_csv(DATA_DIR / "traffic_benign.csv")
    sample = traffic_df.sample(n=100, random_state=42)
    domains = sample["domain"].tolist()

    # Run three variants
    modes = {
        "A + CNN": {"zero_cnn": False, "zero_group_a": False},
        "A only":  {"zero_cnn": True,  "zero_group_a": False},
        "CNN only": {"zero_cnn": False, "zero_group_a": True},
    }

    all_probs: dict[str, np.ndarray] = {}
    for mode_name, kwargs in modes.items():
        rows = [
            build_feature_row(d, feature_names, ordinal_maps, cnn_session, char_to_idx, cnn_meta, **kwargs)
            for d in domains
        ]
        X = np.array(rows)
        probs = lgb_model.predict(X)
        all_probs[mode_name] = probs

    # Summary table
    print(f"\n{'Mode':<12s}  {'Safe':>6s}  {'Susp':>6s}  {'Mal':>6s}  {'FP>=0.5':>8s}  {'FP>=0.9':>8s}  {'Mean':>7s}  {'Median':>7s}")
    print("-" * 80)
    for mode_name, probs in all_probs.items():
        n_safe = sum(1 for p in probs if p < 0.5)
        n_susp = sum(1 for p in probs if 0.5 <= p < 0.9)
        n_mal = sum(1 for p in probs if p >= 0.9)
        fp_50 = 100 * (len(probs) - n_safe) / len(probs)
        fp_90 = 100 * n_mal / len(probs)
        print(f"{mode_name:<12s}  {n_safe:>6d}  {n_susp:>6d}  {n_mal:>6d}  {fp_50:>7.1f}%  {fp_90:>7.1f}%  {probs.mean():>7.4f}  {np.median(probs):>7.4f}")

    # Per-domain comparison for worst FPs
    print(f"\nTop 20 FPs (by 'A + CNN' score) — comparison across modes:")
    print(f"{'Domain':<50s}  {'A+CNN':>7s}  {'A only':>7s}  {'CNN only':>9s}  {'Delta':>7s}")
    print("-" * 90)

    indices = np.argsort(-all_probs["A + CNN"])[:20]
    for idx in indices:
        domain = domains[idx]
        p_both = all_probs["A + CNN"][idx]
        p_a = all_probs["A only"][idx]
        p_cnn = all_probs["CNN only"][idx]
        delta = p_both - p_a  # CNN contribution
        print(f"{domain:<50s}  {p_both:>7.4f}  {p_a:>7.4f}  {p_cnn:>9.4f}  {delta:>+7.4f}")


if __name__ == "__main__":
    main()
