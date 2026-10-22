"""Train LightGBM model for domain classification.

Reads features from lgb_features.parquet (which already contains all
feature columns including CNN embeddings), trains a binary classifier,
evaluates performance, generates SHAP analysis, and exports ONNX model.

Usage:
    uv run python train.py
    uv run python train.py --features data/lgb_features.parquet
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
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

matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"

# No native categoricals — all string features are ordinal-encoded for ONNX compatibility.
CATEGORICAL_FEATURES: list[str] = []

# String features to ordinal-encode. Mapping is saved in metadata.json
# so the Rust inference can use the same encoding.
ORDINAL_ENCODE_FEATURES = [
    "tld_category",
]

# Features to exclude from training (identifiers, label leaks, legacy)
EXCLUDE_FEATURES = [
    # --- Identifiers / metadata ---
    "domain",
    "label",
    "category",

    # --- Label leaks ---
    "tranco_rank",          # benign=ranked, malicious=0
    "feed_hit_count",       # malicious=hit, benign=0
    "query_count",          # popularity, not domain property

    # --- Legacy fields (kept in features_to_dict for other scripts) ---
    "tld",                  # replaced by tld_category
    "high_risk_tld",        # static rule in scoring chain
    "is_ptr_domain",        # pre-ML skip in scoring chain
]

# Classification thresholds (tuned after evaluation)
THRESHOLD_MALICIOUS = 0.9
THRESHOLD_SUSPICIOUS = 0.5
THRESHOLD_SAFE = 0.1


def load_data(features_path: Path) -> tuple[pd.DataFrame, pd.Series, dict[str, dict[str, int]]]:
    """Load features and split into X, y.

    Returns (X, y, ordinal_maps) where ordinal_maps maps feature name → {value → code}.
    """
    if str(features_path).endswith(".parquet"):
        df = pd.read_parquet(features_path)
    else:
        df = pd.read_csv(features_path, low_memory=False)
    print(f"Loaded {len(df)} samples ({df.shape[1]} columns)")
    print(f"  Malicious: {(df['label'] == 1).sum()}")
    print(f"  Benign:    {(df['label'] == 0).sum()}")

    feature_cols = [c for c in df.columns if c not in EXCLUDE_FEATURES]
    X = df[feature_cols].copy()
    y = df["label"]

    # Convert bool and object-bool columns to numeric for LightGBM
    bool_cols = X.select_dtypes(include=["bool"]).columns
    for col in bool_cols:
        X[col] = X[col].astype("Int64")

    # Handle mixed-type columns (bool + NaN becomes object)
    for col in X.select_dtypes(include=["object", "string"]).columns:
        if col not in ORDINAL_ENCODE_FEATURES:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    # Ordinal-encode string features → integers.
    # Unknown/missing values become NaN (LightGBM handles natively).
    # Mapping is saved so Rust inference can use the same encoding.
    ordinal_maps: dict[str, dict[str, int]] = {}
    for col in ORDINAL_ENCODE_FEATURES:
        if col not in X.columns:
            continue
        # Get unique non-null values sorted alphabetically for deterministic codes
        unique_vals = sorted(X[col].dropna().unique().astype(str))
        val_to_code = {v: i for i, v in enumerate(unique_vals)}
        ordinal_maps[col] = val_to_code
        # Encode: known values → code, unknown/NaN → NaN
        X[col] = X[col].astype(str).map(val_to_code).astype("Float64")
        # Restore NaN for original NaN entries (pandas maps NaN→"nan"→missing)
        non_null = df[col].notna() if col in df.columns else pd.Series(True, index=X.index)
        X.loc[~non_null, col] = pd.NA
        print(f"  Ordinal-encoded {col}: {len(val_to_code)} categories")

    # Mark remaining categorical features (if any)
    for col in CATEGORICAL_FEATURES:
        if col in X.columns:
            X[col] = X[col].astype("category")

    return X, y, ordinal_maps


def train_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
) -> lgb.Booster:
    """Train LightGBM binary classifier."""
    # Calculate scale_pos_weight for class imbalance
    n_neg = (y_train == 0).sum()
    n_pos = (y_train == 1).sum()
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1.0

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "boosting_type": "gbdt",
        "num_leaves": 63,
        "learning_rate": 0.05,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "scale_pos_weight": scale_pos_weight,
        "min_child_samples": 20,
        "verbose": -1,
    }

    train_set = lgb.Dataset(
        X_train,
        label=y_train,
        categorical_feature=CATEGORICAL_FEATURES,
        free_raw_data=False,
    )
    val_set = lgb.Dataset(
        X_val,
        label=y_val,
        categorical_feature=CATEGORICAL_FEATURES,
        reference=train_set,
        free_raw_data=False,
    )

    print("\nTraining LightGBM ...")
    model = lgb.train(
        params,
        train_set,
        num_boost_round=1000,
        valid_sets=[train_set, val_set],
        valid_names=["train", "val"],
        callbacks=[
            lgb.early_stopping(stopping_rounds=50),
            lgb.log_evaluation(period=100),
        ],
    )

    print(f"  Best iteration: {model.best_iteration}")
    print(f"  Best val AUC:   {model.best_score['val']['auc']:.4f}")
    return model


def evaluate_model(
    model: lgb.Booster,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    output_dir: Path,
) -> dict:
    """Evaluate model and save reports."""
    y_prob = model.predict(X_val, num_iteration=model.best_iteration)
    y_pred = (y_prob >= THRESHOLD_MALICIOUS).astype(int)

    # AUC
    auc = roc_auc_score(y_val, y_prob)
    print(f"\n{'='*50}")
    print(f"Validation Results:")
    print(f"  ROC-AUC: {auc:.4f}")

    # Classification report at malicious threshold
    print(f"\n  Classification report (threshold={THRESHOLD_MALICIOUS}):")
    report = classification_report(y_val, y_pred, target_names=["benign", "malicious"])
    print(report)

    # Confusion matrix
    cm = confusion_matrix(y_val, y_pred)
    print(f"  Confusion matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # Precision-recall curve
    precision, recall, thresholds = precision_recall_curve(y_val, y_prob)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")
    ax.grid(True, alpha=0.3)
    pr_path = output_dir / "precision_recall.png"
    fig.savefig(pr_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\n  Precision-recall curve → {pr_path}")

    # Threshold analysis
    print(f"\n  Threshold analysis:")
    for thresh in [0.5, 0.7, 0.8, 0.9, 0.95]:
        preds = (y_prob >= thresh).astype(int)
        tp = ((preds == 1) & (y_val == 1)).sum()
        fp = ((preds == 1) & (y_val == 0)).sum()
        fn = ((preds == 0) & (y_val == 1)).sum()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"    threshold={thresh:.2f}  precision={prec:.4f}  recall={rec:.4f}  FP={fp}  FN={fn}")

    return {
        "auc": float(auc),
        "threshold_malicious": THRESHOLD_MALICIOUS,
        "confusion_matrix": {"tn": int(cm[0][0]), "fp": int(cm[0][1]), "fn": int(cm[1][0]), "tp": int(cm[1][1])},
        "val_samples": len(y_val),
        "val_malicious": int(y_val.sum()),
        "val_benign": int((y_val == 0).sum()),
    }


def shap_analysis(
    model: lgb.Booster,
    X_val: pd.DataFrame,
    output_dir: Path,
) -> dict:
    """SHAP feature importance analysis."""
    import shap

    print("\nComputing SHAP values ...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_val)

    # For binary classification, shap_values may be a list [class0, class1]
    if isinstance(shap_values, list):
        sv = shap_values[1]  # class 1 = malicious
    else:
        sv = shap_values

    # Summary plot
    fig, ax = plt.subplots(figsize=(10, 8))
    shap.summary_plot(sv, X_val, show=False, max_display=20)
    summary_path = output_dir / "shap_summary.png"
    plt.savefig(summary_path, dpi=150, bbox_inches="tight")
    plt.close("all")
    print(f"  SHAP summary plot → {summary_path}")

    # Feature importance (mean absolute SHAP)
    importance = pd.DataFrame(
        {"feature": X_val.columns, "mean_abs_shap": np.abs(sv).mean(axis=0)}
    ).sort_values("mean_abs_shap", ascending=False)

    print(f"\n  Top 15 features by SHAP importance:")
    for _, row in importance.head(15).iterrows():
        print(f"    {row['feature']:30s} {row['mean_abs_shap']:.4f}")

    importance.to_csv(output_dir / "feature_importance.csv", index=False)
    return {"top_features": importance.head(20).to_dict("records")}


def export_onnx(model: lgb.Booster, feature_names: list[str], output_dir: Path) -> Path:
    """Export model to ONNX format."""
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    print("\nExporting ONNX model ...")
    n_features = len(feature_names)
    initial_types = [("features", FloatTensorType([None, n_features]))]

    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=initial_types,
        target_opset=15,
        zipmap=False,
    )

    onnx_path = output_dir / "model.onnx"
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))
    print(f"  ONNX model → {onnx_path} ({onnx_path.stat().st_size / 1024:.1f} KB)")

    # Validate with onnxruntime
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path))
    test_input = np.zeros((1, n_features), dtype=np.float32)
    result = session.run(None, {"features": test_input})
    print(f"  ONNX validation: OK (output shape: {result[0].shape})")

    return onnx_path


def save_metadata(
    output_dir: Path,
    feature_names: list[str],
    eval_results: dict,
    shap_results: dict,
    training_time_s: float,
    ordinal_maps: dict[str, dict[str, int]] | None = None,
) -> None:
    """Save model metadata for Rust inference."""
    metadata = {
        "version": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": feature_names,
        "categorical_features": CATEGORICAL_FEATURES,
        "ordinal_encode_features": ORDINAL_ENCODE_FEATURES,
        "ordinal_maps": ordinal_maps or {},
        "n_features": len(feature_names),
        "thresholds": {
            "malicious": THRESHOLD_MALICIOUS,
            "suspicious": THRESHOLD_SUSPICIOUS,
            "safe": THRESHOLD_SAFE,
        },
        "evaluation": eval_results,
        "shap": shap_results,
        "training_time_seconds": training_time_s,
    }

    meta_path = output_dir / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2, default=str)
    print(f"\n  Metadata → {meta_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ML scoring model")
    parser.add_argument("--features", type=str, default=str(DATA_DIR / "lgb_features.parquet"))
    parser.add_argument("--output", type=str, help="Output directory for model artifacts")
    parser.add_argument("--test-size", type=float, default=0.2, help="Validation split ratio")
    args = parser.parse_args()

    features_path = Path(args.features)
    if not features_path.exists():
        print(f"Features file not found: {features_path}")
        print("Run build_lgb_dataset.py first.")
        raise SystemExit(1)

    # Output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = MODELS_DIR / ts
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load data
    X, y, ordinal_maps = load_data(features_path)
    feature_names = list(X.columns)

    # Inject 20% NaN into Group B + F columns to teach the model to handle missing
    # infrastructure/reputation data at inference (new domains without history).
    nullable_cols = [
        # Group B
        "avg_auth_ttl", "has_cname", "a_record_count",
        "ns_name_entropy", "ns_name_length",
        # Group F
        "ns_observation_count", "well_known_rank_norm",
        "cname_target_entropy",
    ]
    rng = np.random.RandomState(42)
    null_mask = rng.random(len(X)) < 0.2
    for col in nullable_cols:
        if col in X.columns:
            X.loc[null_mask, col] = np.nan
    nulled_cols = [c for c in nullable_cols if c in X.columns]
    print(f"  Injected 20% NaN into Group B+F: {', '.join(nulled_cols)}")
    print(f"  Model: {len(feature_names)} features")

    # Split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)} samples  |  Val: {len(X_val)} samples")

    # Train
    start = time.monotonic()
    model = train_model(X_train, y_train, X_val, y_val)
    training_time = time.monotonic() - start

    # Evaluate
    eval_results = evaluate_model(model, X_val, y_val, output_dir)

    # SHAP
    shap_results = shap_analysis(model, X_val, output_dir)

    # Export ONNX
    export_onnx(model, feature_names, output_dir)

    # Save LightGBM native format too (for debugging / re-evaluation)
    lgb_path = output_dir / "model.lgb"
    model.save_model(str(lgb_path))
    print(f"  LightGBM native → {lgb_path}")

    # Save metadata (includes ordinal maps for Rust inference)
    save_metadata(
        output_dir, feature_names, eval_results, shap_results, training_time,
        ordinal_maps,
    )

    print(f"\n{'='*50}")
    print(f"Training complete!")
    print(f"  Output:   {output_dir}")
    print(f"  AUC:      {eval_results['auc']:.4f}")
    print(f"  Time:     {training_time:.1f}s")
    print(f"\nFiles:")
    for p in sorted(output_dir.iterdir()):
        size = p.stat().st_size
        if size > 1024 * 1024:
            print(f"  {p.name:30s} {size / 1024 / 1024:.1f} MB")
        elif size > 1024:
            print(f"  {p.name:30s} {size / 1024:.1f} KB")
        else:
            print(f"  {p.name:30s} {size} B")


if __name__ == "__main__":
    main()
