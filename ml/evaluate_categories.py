"""Per-category evaluation of the trained LightGBM model.

Breaks down AUC, precision, recall, FP, FN by malicious category
(dga, phishing, c2, malware) and benign source (tranco, majestic, traffic).

Uses the same train/val split as train.py (random_state=42, test_size=0.2).

Usage:
    uv run python evaluate_categories.py
    uv run python evaluate_categories.py --model models/20260318_201527
    uv run python evaluate_categories.py --threshold 0.8
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import matplotlib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"

# Must match train.py exactly
EXCLUDE_FEATURES = [
    "domain",
    "label",
    "category",
    "tranco_rank",
    "feed_hit_count",
    "query_count",
    "first_seen_days",
    "ns_is_known_legitimate",
    "is_cdn",
    "is_bulletproof",
    "high_risk_tld",
    "is_ptr_domain",
    "min_ttl",
    "ip_asn",
    "tld",
]

ORDINAL_ENCODE_FEATURES = ["tld", "ip_country"]

GROUP_B_COLS = [
    "avg_ttl", "unique_ip_count", "cname_depth",
    "ip_country", "ip_asn", "domain_age_days",
]


def find_latest_model() -> Path:
    """Find the latest LightGBM model directory (non-CNN)."""
    dirs = sorted(
        [d for d in MODELS_DIR.iterdir() if d.is_dir() and not d.name.startswith("cnn_")],
        reverse=True,
    )
    if not dirs:
        raise FileNotFoundError("No model directories found in models/")
    return dirs[0]


def load_and_prepare(
    features_path: Path,
    dataset_path: Path,
    ordinal_maps: dict[str, dict[str, int]],
) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Load features, merge categories, apply ordinal encoding + NaN injection.

    Returns (X_prepared, y, category_series) — all aligned by index.
    """
    if str(features_path).endswith(".parquet"):
        feat_df = pd.read_parquet(features_path)
    else:
        feat_df = pd.read_csv(features_path, low_memory=False)
    if str(dataset_path).endswith(".parquet"):
        ds_df = pd.read_parquet(dataset_path, columns=["domain", "category"])
    else:
        ds_df = pd.read_csv(dataset_path, usecols=["domain", "category"], low_memory=False)

    # Merge category into features by domain (skip if already present)
    if "category" not in feat_df.columns:
        feat_df = feat_df.merge(ds_df, on="domain", how="left")
    categories = feat_df["category"].fillna("unknown")

    # Prepare X (same logic as train.py)
    feature_cols = [c for c in feat_df.columns if c not in EXCLUDE_FEATURES and c != "category"]
    X = feat_df[feature_cols].copy()
    y = feat_df["label"]

    # Bool → Int64
    for col in X.select_dtypes(include=["bool"]).columns:
        X[col] = X[col].astype("Int64")

    # Mixed object → numeric
    for col in X.select_dtypes(include=["object", "string"]).columns:
        if col not in ORDINAL_ENCODE_FEATURES:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    # Ordinal encode using the SAME maps from the trained model
    for col in ORDINAL_ENCODE_FEATURES:
        if col not in X.columns:
            continue
        val_to_code = ordinal_maps.get(col, {})
        X[col] = X[col].astype(str).map(val_to_code).astype("Float64")
        non_null = feat_df[col].notna() if col in feat_df.columns else pd.Series(True, index=X.index)
        X.loc[~non_null, col] = pd.NA

    # Inject 20% NaN into Group B (same seed as train.py)
    rng = np.random.RandomState(42)
    null_mask = rng.random(len(X)) < 0.2
    for col in GROUP_B_COLS:
        if col in X.columns:
            X.loc[null_mask, col] = np.nan

    return X, y, categories


def per_category_metrics(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    categories: np.ndarray,
    threshold: float,
) -> pd.DataFrame:
    """Compute per-category metrics."""
    y_pred = (y_prob >= threshold).astype(int)
    rows: list[dict] = []

    for cat in sorted(set(categories)):
        mask = categories == cat
        n = mask.sum()
        if n == 0:
            continue

        yt = y_true[mask]
        yp = y_prob[mask]
        ypred = y_pred[mask]

        # AUC (only if both classes present)
        try:
            auc = roc_auc_score(yt, yp)
        except ValueError:
            auc = float("nan")

        tp = int(((ypred == 1) & (yt == 1)).sum())
        fp = int(((ypred == 1) & (yt == 0)).sum())
        fn = int(((ypred == 0) & (yt == 1)).sum())
        tn = int(((ypred == 0) & (yt == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else float("nan")

        is_malicious = int(yt.sum()) > 0
        rows.append({
            "category": cat,
            "type": "malicious" if is_malicious else "benign",
            "n": n,
            "auc": auc,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        })

    return pd.DataFrame(rows)


def print_category_report(df: pd.DataFrame, threshold: float) -> None:
    """Pretty-print per-category metrics."""
    print(f"\n{'=' * 80}")
    print(f"Per-Category Evaluation (threshold={threshold})")
    print(f"{'=' * 80}")

    # Malicious categories
    mal = df[df["type"] == "malicious"].sort_values("n", ascending=False)
    if not mal.empty:
        print(f"\n{'MALICIOUS CATEGORIES':^80}")
        print(f"{'Category':<15} {'N':>8} {'AUC':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>8} {'FN':>8}")
        print("-" * 80)
        for _, r in mal.iterrows():
            print(
                f"{r['category']:<15} {r['n']:>8,} {r['auc']:>8.4f} "
                f"{r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f} "
                f"{r['tp']:>8,} {r['fn']:>8,}"
            )

        total_tp = mal["tp"].sum()
        total_fn = mal["fn"].sum()
        total_mal = mal["n"].sum()
        print("-" * 80)
        print(
            f"{'TOTAL':<15} {total_mal:>8,} {'':>8} "
            f"{'':>8} {total_tp / (total_tp + total_fn):>8.4f} {'':>8} "
            f"{total_tp:>8,} {total_fn:>8,}"
        )

    # Benign categories
    ben = df[df["type"] == "benign"].sort_values("n", ascending=False)
    if not ben.empty:
        print(f"\n{'BENIGN CATEGORIES (FP analysis)':^80}")
        print(f"{'Category':<15} {'N':>8} {'FP':>8} {'FP rate':>10} {'TN':>8}")
        print("-" * 80)
        for _, r in ben.iterrows():
            fp_rate = r["fp"] / r["n"] if r["n"] > 0 else 0
            print(f"{r['category']:<15} {r['n']:>8,} {r['fp']:>8,} {fp_rate:>10.4%} {r['tn']:>8,}")

        total_fp = ben["fp"].sum()
        total_ben = ben["n"].sum()
        print("-" * 80)
        print(
            f"{'TOTAL':<15} {total_ben:>8,} {total_fp:>8,} "
            f"{total_fp / total_ben:>10.4%} {(total_ben - total_fp):>8,}"
        )


def plot_per_category_pr(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    categories: np.ndarray,
    output_path: Path,
) -> None:
    """Plot precision-recall curves per malicious category."""
    mal_cats = sorted(set(categories[y_true == 1]))
    if not mal_cats:
        return

    fig, ax = plt.subplots(figsize=(10, 7))
    colors = plt.cm.tab10(np.linspace(0, 1, len(mal_cats)))

    for cat, color in zip(mal_cats, colors):
        mask = categories == cat
        yt = y_true[mask]
        yp = y_prob[mask]

        if len(set(yt)) < 2:
            continue

        precision, recall, _ = precision_recall_curve(yt, yp)
        auc = roc_auc_score(yt, yp)
        n = mask.sum()
        ax.plot(recall, precision, color=color, label=f"{cat} (n={n:,}, AUC={auc:.3f})", linewidth=2)

    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall by Malicious Category", fontsize=14)
    ax.legend(loc="lower left", fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_xlim([0, 1.02])
    ax.set_ylim([0, 1.02])

    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\n  PR curve per category → {output_path}")


def plot_fp_breakdown(
    df: pd.DataFrame,
    threshold: float,
    output_path: Path,
) -> None:
    """Bar chart of FP counts by benign category."""
    ben = df[df["type"] == "benign"].sort_values("fp", ascending=True)
    if ben.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(ben["category"], ben["fp"], color="#e74c3c", alpha=0.8)
    for i, (_, r) in enumerate(ben.iterrows()):
        fp_rate = r["fp"] / r["n"] if r["n"] > 0 else 0
        ax.text(r["fp"] + 1, i, f'{fp_rate:.2%}', va="center", fontsize=10)

    ax.set_xlabel("False Positives", fontsize=12)
    ax.set_title(f"FP by Benign Source (threshold={threshold})", fontsize=14)
    ax.grid(True, alpha=0.3, axis="x")

    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  FP breakdown → {output_path}")


def show_worst_fn_examples(
    domains: np.ndarray,
    y_true: np.ndarray,
    y_prob: np.ndarray,
    categories: np.ndarray,
    threshold: float,
    n_per_category: int = 10,
) -> None:
    """Show example FN domains (highest prob among misses) per category."""
    fn_mask = (y_true == 1) & (y_prob < threshold)
    if fn_mask.sum() == 0:
        print("\n  No false negatives!")
        return

    print(f"\n{'=' * 80}")
    print(f"Highest-confidence False Negatives (malicious missed, threshold={threshold})")
    print(f"{'=' * 80}")

    for cat in sorted(set(categories[fn_mask])):
        cat_fn = fn_mask & (categories == cat)
        if cat_fn.sum() == 0:
            continue

        # Sort by probability descending (closest to threshold = most interesting)
        idxs = np.where(cat_fn)[0]
        sorted_idxs = idxs[np.argsort(y_prob[idxs])[::-1]][:n_per_category]

        print(f"\n  {cat} ({cat_fn.sum()} FN total, showing top {len(sorted_idxs)}):")
        for idx in sorted_idxs:
            print(f"    {y_prob[idx]:.4f}  {domains[idx]}")


def show_worst_fp_examples(
    domains: np.ndarray,
    y_true: np.ndarray,
    y_prob: np.ndarray,
    categories: np.ndarray,
    threshold: float,
    n_per_category: int = 10,
) -> None:
    """Show example FP domains (highest prob among false positives) per category."""
    fp_mask = (y_true == 0) & (y_prob >= threshold)
    if fp_mask.sum() == 0:
        print("\n  No false positives!")
        return

    print(f"\n{'=' * 80}")
    print(f"False Positives (benign flagged as malicious, threshold={threshold})")
    print(f"{'=' * 80}")

    for cat in sorted(set(categories[fp_mask])):
        cat_fp = fp_mask & (categories == cat)
        if cat_fp.sum() == 0:
            continue

        idxs = np.where(cat_fp)[0]
        sorted_idxs = idxs[np.argsort(y_prob[idxs])[::-1]][:n_per_category]

        print(f"\n  {cat} ({cat_fp.sum()} FP total, showing top {len(sorted_idxs)}):")
        for idx in sorted_idxs:
            print(f"    {y_prob[idx]:.4f}  {domains[idx]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Per-category model evaluation")
    parser.add_argument("--model", type=str, help="Model directory (default: latest)")
    parser.add_argument("--features", type=str, default=str(DATA_DIR / "lgb_features.parquet"))
    parser.add_argument("--dataset", type=str, default=str(DATA_DIR / "dataset.parquet"))
    parser.add_argument("--threshold", type=float, default=0.9)
    parser.add_argument("--examples", type=int, default=10, help="FP/FN examples per category")
    args = parser.parse_args()

    # Find model
    if args.model:
        model_dir = Path(args.model)
    else:
        model_dir = find_latest_model()
    print(f"Model: {model_dir.name}")

    lgb_path = model_dir / "model.lgb"
    meta_path = model_dir / "metadata.json"

    if not lgb_path.exists():
        raise FileNotFoundError(f"No model.lgb in {model_dir}")

    model = lgb.Booster(model_file=str(lgb_path))

    # Load ordinal maps from metadata
    ordinal_maps: dict[str, dict[str, int]] = {}
    if meta_path.exists():
        with open(meta_path) as f:
            metadata = json.load(f)
        ordinal_maps = metadata.get("ordinal_maps", {})

    # Load and prepare data (same transforms as train.py)
    features_path = Path(args.features)
    dataset_path = Path(args.dataset)

    X, y, categories = load_and_prepare(features_path, dataset_path, ordinal_maps)

    # Same split as train.py
    X_train, X_val, y_train, y_val, cat_train, cat_val = train_test_split(
        X, y, categories, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"\nValidation set: {len(X_val):,} samples")

    # Get domain names for the validation set (for example display)
    if str(features_path).endswith(".parquet"):
        feat_df = pd.read_parquet(features_path, columns=["domain"])
    else:
        feat_df = pd.read_csv(features_path, usecols=["domain"], low_memory=False)
    domains_all = feat_df["domain"].to_numpy(dtype=str)
    _, domains_val = train_test_split(
        domains_all, test_size=0.2, random_state=42, stratify=y,
    )

    # Predict
    y_prob = model.predict(X_val, num_iteration=model.best_iteration)
    y_true = y_val.values
    cats = cat_val.values

    # Overall metrics
    auc = roc_auc_score(y_true, y_prob)
    y_pred = (y_prob >= args.threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred)
    print(f"\nOverall AUC: {auc:.4f}")
    print(f"Confusion (threshold={args.threshold}): TN={cm[0][0]:,}  FP={cm[0][1]:,}  FN={cm[1][0]:,}  TP={cm[1][1]:,}")

    # Per-category
    cat_df = per_category_metrics(y_true, y_prob, cats, args.threshold)
    print_category_report(cat_df, args.threshold)

    # Plots
    output_dir = model_dir / "category_eval"
    output_dir.mkdir(exist_ok=True)

    plot_per_category_pr(y_true, y_prob, cats, output_dir / "pr_per_category.png")
    plot_fp_breakdown(cat_df, args.threshold, output_dir / "fp_breakdown.png")

    # Examples
    show_worst_fn_examples(domains_val, y_true, y_prob, cats, args.threshold, args.examples)
    show_worst_fp_examples(domains_val, y_true, y_prob, cats, args.threshold, args.examples)

    # Save results
    cat_df.to_csv(output_dir / "category_metrics.csv", index=False)
    print(f"\n  Results saved → {output_dir}")

    # Multi-threshold comparison
    print(f"\n{'=' * 80}")
    print("Multi-threshold comparison (malicious categories)")
    print(f"{'=' * 80}")
    print(f"\n{'Cat':<12} {'Metric':<10} {'0.50':>8} {'0.70':>8} {'0.80':>8} {'0.90':>8} {'0.95':>8}")
    print("-" * 70)
    for cat in sorted(set(cats[y_true == 1])):
        mask = cats == cat
        yt = y_true[mask]
        yp = y_prob[mask]
        recalls = []
        fps_list = []
        for t in [0.5, 0.7, 0.8, 0.9, 0.95]:
            pred = (yp >= t).astype(int)
            tp = ((pred == 1) & (yt == 1)).sum()
            fn = ((pred == 0) & (yt == 1)).sum()
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            recalls.append(rec)
        print(f"{cat:<12} {'recall':<10} " + " ".join(f"{r:>8.4f}" for r in recalls))

    # Benign FP rates at multiple thresholds
    print(f"\n{'Cat':<12} {'Metric':<10} {'0.50':>8} {'0.70':>8} {'0.80':>8} {'0.90':>8} {'0.95':>8}")
    print("-" * 70)
    for cat in sorted(set(cats[y_true == 0])):
        mask = cats == cat
        yt = y_true[mask]
        yp = y_prob[mask]
        fp_rates = []
        for t in [0.5, 0.7, 0.8, 0.9, 0.95]:
            pred = (yp >= t).astype(int)
            fp = ((pred == 1) & (yt == 0)).sum()
            rate = fp / len(yt) if len(yt) > 0 else 0
            fp_rates.append(rate)
        print(f"{cat:<12} {'fp_rate':<10} " + " ".join(f"{r:>8.4%}" for r in fp_rates))


if __name__ == "__main__":
    main()
