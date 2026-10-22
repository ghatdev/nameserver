"""CNN-only prediction: raw CNN classifier (sigmoid) on real traffic domains.

Runs the CNN classification head directly (not LightGBM), showing what the
CNN alone thinks about each domain's registrable label and subdomain labels.

Usage:
    uv run python predict_cnn_only.py
    uv run python predict_cnn_only.py --n 200
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import tldextract

from train_cnn import LabelCNN, LabelDataset, MAX_LEN, CHAR_TO_IDX

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


def predict_labels(model, labels: list[str], device) -> np.ndarray:
    """Run CNN classifier on individual labels. Returns probabilities."""
    from torch.utils.data import DataLoader

    model.eval()
    dataset = LabelDataset(labels, [0] * len(labels))
    loader = DataLoader(dataset, batch_size=512, shuffle=False)

    probs = []
    with torch.no_grad():
        for batch_x, _ in loader:
            batch_x = batch_x.to(device)
            output = model(batch_x)  # sigmoid output
            probs.extend(output.cpu().numpy())

    return np.array(probs)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--model", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    args = parser.parse_args()

    model_dir = Path(args.model)

    # Load model with classification head
    with open(model_dir / "cnn_metadata.json") as f:
        meta = json.load(f)

    model = LabelCNN(embedding_dim=meta["embedding_dim"])
    model.load_state_dict(torch.load(model_dir / "best_model.pt", weights_only=True))
    model.eval()
    device = torch.device("cpu")

    # Load traffic domains
    traffic_df = pd.read_csv(DATA_DIR / "traffic_benign.csv")
    sample = traffic_df.sample(n=min(args.n, len(traffic_df)), random_state=42)
    domains = sample["domain"].tolist()

    print(f"CNN-only prediction on {len(domains)} real traffic domains\n")

    # Parse all domains and collect unique labels
    parsed = []
    all_labels: set[str] = set()
    for domain in domains:
        ext = tldextract.extract(domain)
        reg = ext.domain or ""
        subs = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []
        parsed.append((domain, reg, subs))
        if reg:
            all_labels.add(reg)
        all_labels.update(subs)

    # Batch predict all unique labels
    label_list = sorted(all_labels)
    label_probs = predict_labels(model, label_list, device)
    label_to_prob = {lbl: float(label_probs[i]) for i, lbl in enumerate(label_list)}

    # Build per-domain results
    print(f"{'Domain':<55s} {'Reg':>6s} {'RegP':>6s}  {'Subs':>30s}  {'MaxSub':>6s}")
    print("-" * 115)

    flagged_domains = []
    for domain, reg, subs in parsed:
        reg_prob = label_to_prob.get(reg, 0.0)
        sub_probs = [(s, label_to_prob.get(s, 0.0)) for s in subs]
        max_sub = max((p for _, p in sub_probs), default=0.0)

        # Flag if any label scores > 0.5
        any_flagged = reg_prob > 0.5 or max_sub > 0.5

        if any_flagged:
            flagged_domains.append((domain, reg, reg_prob, subs, sub_probs, max_sub))

        # Show domains where something is interesting (prob > 0.3)
        if reg_prob > 0.3 or max_sub > 0.3:
            sub_str = ", ".join(f"{s}={p:.3f}" for s, p in sub_probs) if sub_probs else "-"
            if len(sub_str) > 30:
                sub_str = sub_str[:27] + "..."
            print(f"  {domain:<53s} {reg:>6s} {reg_prob:>6.3f}  {sub_str:>30s}  {max_sub:>6.3f}")

    # Summary
    reg_probs_all = [label_to_prob.get(reg, 0.0) for _, reg, _ in parsed]
    max_sub_all = [
        max((label_to_prob.get(s, 0.0) for s in subs), default=0.0)
        for _, _, subs in parsed
    ]

    print(f"\n{'='*115}")
    print(f"Registrable label stats (CNN classifier):")
    print(f"  Mean:   {np.mean(reg_probs_all):.4f}")
    print(f"  Median: {np.median(reg_probs_all):.4f}")
    print(f"  >0.5:   {sum(1 for p in reg_probs_all if p > 0.5)} / {len(reg_probs_all)}")
    print(f"  >0.7:   {sum(1 for p in reg_probs_all if p > 0.7)} / {len(reg_probs_all)}")

    print(f"\nSubdomain label stats (max per domain):")
    has_sub = [p for p in max_sub_all if p > 0]
    print(f"  Domains with subdomains: {len(has_sub)} / {len(max_sub_all)}")
    if has_sub:
        print(f"  Mean:   {np.mean(has_sub):.4f}")
        print(f"  Median: {np.median(has_sub):.4f}")
        print(f"  >0.5:   {sum(1 for p in has_sub if p > 0.5)} / {len(has_sub)}")
        print(f"  >0.7:   {sum(1 for p in has_sub if p > 0.7)} / {len(has_sub)}")

    print(f"\nFP summary (any label > 0.5):")
    print(f"  Flagged domains: {len(flagged_domains)} / {len(domains)} ({100*len(flagged_domains)/len(domains):.1f}%)")

    if flagged_domains:
        print(f"\nFlagged domains detail:")
        for domain, reg, reg_prob, subs, sub_probs, max_sub in sorted(flagged_domains, key=lambda x: -max(x[2], x[5])):
            reason = []
            if reg_prob > 0.5:
                reason.append(f"reg:{reg}={reg_prob:.3f}")
            for s, p in sub_probs:
                if p > 0.5:
                    reason.append(f"sub:{s}={p:.3f}")
            print(f"  {domain:<55s} {' | '.join(reason)}")


if __name__ == "__main__":
    main()
