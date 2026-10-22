"""Train the zero-second detector LightGBM.

Fork of `ml/train.py` — a DISTINCT model from the phishing LightGBM:
different feature set, different labels (Hagezi TIF vs Tranco/Majestic +
realtraffic_benign), different output path. The phishing pipeline is
untouched.

Implements `docs/detector-lightgbm-design.md` §5:
- Registrable-stratified split (GroupShuffleSplit on `registrable`).
- LightGBM binary with §5.2 hyperparameters.
- Isotonic calibration on a dedicated holdout (not the early-stopping
  val set — §5.3).
- ONNX export; calibrator stored as (x, y) knots for Rust application.
- SHAP analysis + CNN-embedding gate per §5.5 (graceful when CNN cols
  absent).

Input: `data/detector_features.parquet` produced by
`build_detector_dataset.py`. CNN embedding columns may be added in a
later step; this script auto-includes them if present.

Usage:
    uv run ml/train_detector_lgb.py
    uv run ml/train_detector_lgb.py --limit 50000  # smoke test
    uv run ml/train_detector_lgb.py --out models/detector_lgb_v1_manual
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import lightgbm as lgb
import matplotlib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"
MODELS_DIR = ML_DIR / "models"

MODEL_NAME = "detector_lgb"
MODEL_VERSION = "v1"
CALIBRATOR_VERSION = "v1"

LABEL_COL = "label"

# --- Feature exclusions -----------------------------------------------------

# Identifiers / metadata / raw fields reserved for future CNN embedding.
IDENTIFIER_COLS: list[str] = [
    "flow_id",
    "started_at",
    "domain",
    "registrable",
    "_clean_domain",
    "cname_chain",
    "response_ips",
    "all_records_json",
    "path_server_names",
]

# design §3.12: active-feed lookups excluded from feature vector. Lists
# stay as LABEL sources + data filters, not features.
#
# `rep_is_well_known` and `registrable_is_known_cdn` are intentionally
# KEPT as §3.9 context gates. The high SHAP they earn reflects reality
# (well-known/CDN registrables really are almost always benign), and
# baking the signal into the model keeps downstream consumers simple.
# An earlier removal experiment (now reverted) confirmed the dataset
# was the actual problem — once realtraffic_longtail negatives broke
# the perfect rep_is_well_known ↔ negative-label correlation, the
# feature behaves like a gate, not a shortcut.
ACTIVE_FEED_COLS: list[str] = [
    "rep_is_nrd",
    "rep_nrd_age_days",
    "registrable_tranco_rank",
    "registrable_majestic_rank",
]

# Privacy-sensitive columns excluded from training. profile_id is being
# removed from flows entirely in the near future — train without it now
# so the model doesn't develop a dependency.
PRIVACY_SENSITIVE_COLS: list[str] = [
    "profile_id",
]

# Bookkeeping columns used by the training pipeline but not fed as
# features. confidence_active is used to FILTER positives below a
# threshold; keeping it as a feature would let the tree short-circuit
# on it (it'd learn "we filtered out low-confidence → remaining high
# confidence correlates with label=1 trivially").
BOOKKEEPING_COLS: list[str] = [
    "confidence_active",
]

# --- Categorical handling ---------------------------------------------------

# String columns → ordinal-encoded integers. Mapping stored in metadata so
# the Rust inference path can apply the same encoding deterministically.
ORDINAL_ENCODE_FEATURES: list[str] = [
    "dnssec_status",
    "dnssec_algorithm",
    "rcode",
    "qtype",
    "qtype_x_rcode",
    "rep_ns_trust",
]

# For these columns the empty string is a real category (e.g. profile_id
# "" = query without profile; dnssec_algorithm "" = insecure/none). Other
# ordinal columns treat "" as missing → NaN.
TREAT_EMPTY_AS_CATEGORY: frozenset[str] = frozenset({"dnssec_algorithm", "profile_id"})

REPORT_THRESHOLDS: list[float] = [0.3, 0.5, 0.7, 0.9]

CNN_EMB_PREFIXES: tuple[str, ...] = (
    "query_reg_emb_",
    "query_sub_emb_",
    "cname_target_emb_",
    "ns_host_emb_",
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_dataset(
    path: Path,
    limit: int | None,
    confidence_threshold: float = 0.0,
) -> pd.DataFrame:
    """Load parquet, drop unlabeled rows, coerce Decimal columns to float.

    When `confidence_threshold > 0` AND the dataset has a
    `confidence_active` column, POSITIVE rows with a score below
    threshold are dropped before training. This is the primary lever
    for suppressing training on post-cleanup/parked malicious flows
    (see project_bulk_resolution_contamination.md).
    """
    df = pd.read_parquet(path)
    n_total = len(df)

    # Coerce PG EXTRACT EPOCH columns (Decimal -> object) to float.
    for col in ("rep_days_since_first_seen", "rep_days_since_ns_change"):
        if col in df.columns and df[col].dtype == object:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")

    df = df[df[LABEL_COL].notna()].reset_index(drop=True)
    df[LABEL_COL] = df[LABEL_COL].astype(np.int8)

    # Apply confidence_active filter to positives only. Benigns keep
    # their low-confidence rows (NODATA / parking-IP on a benign domain
    # is itself a normal pattern we want the model to recognize).
    if confidence_threshold > 0 and "confidence_active" in df.columns:
        before = len(df)
        pos_mask = df[LABEL_COL] == 1
        low_conf_pos = pos_mask & (df["confidence_active"] < confidence_threshold)
        dropped = int(low_conf_pos.sum())
        df = df[~low_conf_pos].reset_index(drop=True)
        print(
            f"[filter] dropped {dropped:,} positive rows with "
            f"confidence_active < {confidence_threshold} "
            f"({dropped/max(1, int(pos_mask.sum())):.1%} of positives)",
            flush=True,
        )
        _ = before  # keep for future debugging
    elif confidence_threshold > 0:
        print(
            "[filter] --confidence-threshold set but column not present; skipping",
            flush=True,
        )

    if limit is not None and len(df) > limit:
        rng = np.random.RandomState(42)
        keep = rng.permutation(len(df))[:limit]
        df = df.iloc[sorted(keep)].reset_index(drop=True)

    pos = int((df[LABEL_COL] == 1).sum())
    neg = int((df[LABEL_COL] == 0).sum())
    print(
        f"[load] {n_total:,} rows → {len(df):,} labeled "
        f"(pos={pos:,}, neg={neg:,}, ratio={neg/max(1,pos):.2f}:1)",
        flush=True,
    )
    return df


def build_feature_matrix(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, list[str], dict[str, dict[str, int]]]:
    """Drop non-features, ordinal-encode strings, coerce dtypes for LightGBM.

    Returns (X, feature_names, ordinal_maps).
    """
    exclude = (
        set(IDENTIFIER_COLS)
        | set(ACTIVE_FEED_COLS)
        | set(PRIVACY_SENSITIVE_COLS)
        | set(BOOKKEEPING_COLS)
        | {LABEL_COL}
    )
    feature_cols = [c for c in df.columns if c not in exclude]
    X = df[feature_cols].copy()

    ordinal_maps: dict[str, dict[str, int]] = {}
    for col in ORDINAL_ENCODE_FEATURES:
        if col not in X.columns:
            continue
        raw = X[col].astype("object")
        if col in TREAT_EMPTY_AS_CATEGORY:
            values = raw.fillna("").astype(str)
            uniques = sorted(values.unique())
        else:
            # Drop "" and NaN both → NaN at output.
            coalesced = raw.where(raw.astype(str) != "", other=np.nan)
            uniques = sorted(str(v) for v in coalesced.dropna().unique())
        mapping = {v: i for i, v in enumerate(uniques)}
        ordinal_maps[col] = mapping

        if col in TREAT_EMPTY_AS_CATEGORY:
            encoded = values.map(mapping).astype("float64")
        else:
            encoded = raw.astype("object").map(
                lambda v: mapping.get(str(v)) if pd.notna(v) and str(v) != "" else np.nan,
            ).astype("float64")
        X[col] = encoded
        print(
            f"[encode] {col}: {len(mapping)} categories "
            f"(empty={'kept' if col in TREAT_EMPTY_AS_CATEGORY else 'NaN'})",
            flush=True,
        )

    # Coerce remaining non-numeric columns to numeric (LightGBM wants floats).
    for col in X.columns:
        if X[col].dtype == object:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    # Nullable numeric dtypes (Int8 / Float32 / ...) → plain float64 so
    # LightGBM handles NaN natively without pandas extension-array tricks.
    for col in X.columns:
        dt = X[col].dtype
        if pd.api.types.is_bool_dtype(dt):
            X[col] = X[col].astype("float64")
        elif pd.api.types.is_extension_array_dtype(dt) or str(dt).startswith(("Int", "Float", "UInt")):
            X[col] = X[col].astype("float64")

    # Deterministic column order (matters for ONNX + feature fingerprint).
    X = X[sorted(X.columns)]
    feature_names = list(X.columns)

    # Report CNN embedding presence.
    cnn_cols = [c for c in feature_names if c.startswith(CNN_EMB_PREFIXES)]
    if cnn_cols:
        print(f"[encode] CNN embedding columns: {len(cnn_cols)}", flush=True)
    else:
        print("[encode] no CNN embedding columns found — tabular-only run", flush=True)

    print(f"[encode] feature vector: {len(feature_names)} cols", flush=True)
    return X, feature_names, ordinal_maps


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split_by_registrable(
    df: pd.DataFrame,
    test_size: float,
    val_size: float,
    cal_size: float,
    seed: int,
) -> dict[str, np.ndarray]:
    """4-way GroupShuffleSplit on `registrable`.

    Returns dict with keys train / val / cal / test, each an ndarray of
    row indices into `df`. No registrable appears in more than one split.
    """
    groups = df["registrable"].fillna("<unknown>").to_numpy()
    all_idx = np.arange(len(df))

    # Outer: (train+val+cal) vs test
    outer = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    tvc_sub, test_sub = next(outer.split(all_idx, groups=groups))
    tvc_idx = all_idx[tvc_sub]
    test_idx = all_idx[test_sub]

    # Middle: from tvc, split off calibration holdout
    cal_splitter = GroupShuffleSplit(n_splits=1, test_size=cal_size, random_state=seed + 1)
    tv_sub, cal_sub = next(cal_splitter.split(tvc_idx, groups=groups[tvc_idx]))
    tv_idx = tvc_idx[tv_sub]
    cal_idx = tvc_idx[cal_sub]

    # Inner: from tv, split off val (early-stopping holdout)
    val_splitter = GroupShuffleSplit(n_splits=1, test_size=val_size, random_state=seed + 2)
    train_sub, val_sub = next(val_splitter.split(tv_idx, groups=groups[tv_idx]))
    train_idx = tv_idx[train_sub]
    val_idx = tv_idx[val_sub]

    # Leakage sanity check — no shared registrables between splits.
    splits = {"train": train_idx, "val": val_idx, "cal": cal_idx, "test": test_idx}
    reg_sets = {k: set(groups[idx]) for k, idx in splits.items()}
    for a, b in [("train", "val"), ("train", "cal"), ("train", "test"),
                 ("val", "cal"), ("val", "test"), ("cal", "test")]:
        inter = reg_sets[a] & reg_sets[b]
        assert not inter, f"registrable leak between {a}/{b}: {len(inter)} shared"

    for name, idx in splits.items():
        n_pos = int(df.iloc[idx][LABEL_COL].sum())
        print(
            f"[split] {name:5s}: rows={len(idx):>8,}  regs={len(reg_sets[name]):>7,}  "
            f"pos={n_pos:>6,} ({n_pos/max(1,len(idx)):.1%})",
            flush=True,
        )
    return splits


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train_lgb(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    num_boost_round: int,
) -> lgb.Booster:
    """Fit LightGBM binary classifier with §5.2 hyperparameters."""
    params: dict[str, Any] = {
        "objective": "binary",
        "metric": ["auc", "binary_logloss"],
        "boosting_type": "gbdt",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "max_depth": -1,
        "min_data_in_leaf": 100,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "lambda_l1": 0.1,
        "lambda_l2": 0.1,
        "is_unbalance": True,
        "verbose": -1,
    }
    train_set = lgb.Dataset(X_train, label=y_train, free_raw_data=False)
    val_set = lgb.Dataset(X_val, label=y_val, reference=train_set, free_raw_data=False)

    print(
        f"[train] starting: rows={len(X_train):,}  features={X_train.shape[1]}  "
        f"max_rounds={num_boost_round}",
        flush=True,
    )
    model = lgb.train(
        params,
        train_set,
        num_boost_round=num_boost_round,
        valid_sets=[train_set, val_set],
        valid_names=["train", "val"],
        callbacks=[
            lgb.early_stopping(stopping_rounds=50),
            lgb.log_evaluation(period=100),
        ],
    )
    print(
        f"[train] done: best_iteration={model.best_iteration}  "
        f"best_val_auc={model.best_score['val']['auc']:.4f}",
        flush=True,
    )
    return model


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def fit_calibrator(
    model: lgb.Booster,
    X_cal: pd.DataFrame,
    y_cal: np.ndarray,
) -> tuple[IsotonicRegression, dict[str, list[float]]]:
    """Isotonic regression from raw LightGBM score → calibrated probability.

    Fit on the dedicated calibration holdout (§5.3). Returns the fitted
    estimator plus a JSON-serializable dict of the piecewise knots for
    Rust application.
    """
    raw = model.predict(X_cal, num_iteration=model.best_iteration)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(raw, y_cal)
    knots = {
        "x": [float(v) for v in iso.X_thresholds_],
        "y": [float(v) for v in iso.y_thresholds_],
    }
    print(
        f"[calib] isotonic fit: {len(knots['x'])} knots, "
        f"x=[{knots['x'][0]:.4f}..{knots['x'][-1]:.4f}], "
        f"y=[{knots['y'][0]:.4f}..{knots['y'][-1]:.4f}]",
        flush=True,
    )
    return iso, knots


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _threshold_metrics(scores: np.ndarray, y: np.ndarray) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []
    for t in REPORT_THRESHOLDS:
        pred = (scores >= t).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        rows.append(
            {
                "threshold": float(t),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": float(prec),
                "recall_on_resolved": float(rec),
            }
        )
    return rows


def _slice_recall_fp(
    scores: np.ndarray, y: np.ndarray, mask: np.ndarray, threshold: float,
) -> dict[str, float | int]:
    """Compute recall (on positives in slice) and FP rate (on negatives in slice)."""
    sl_y = y[mask]
    sl_s = scores[mask]
    pred = (sl_s >= threshold).astype(int)
    tp = int(((pred == 1) & (sl_y == 1)).sum())
    fp = int(((pred == 1) & (sl_y == 0)).sum())
    fn = int(((pred == 0) & (sl_y == 1)).sum())
    n_pos = int((sl_y == 1).sum())
    n_neg = int((sl_y == 0).sum())
    return {
        "n_pos": n_pos,
        "n_neg": n_neg,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "recall": float(tp / n_pos) if n_pos else float("nan"),
        "fp_rate": float(fp / n_neg) if n_neg else float("nan"),
    }


def evaluate(
    model: lgb.Booster,
    iso: IsotonicRegression,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    output_dir: Path,
    slice_masks: dict[str, np.ndarray] | None = None,
) -> dict[str, Any]:
    """Score test set, report metrics + PR curve for raw and calibrated scores.

    Dataset rows are already filtered to `list_action = PASS`; therefore
    the recall numbers here are `recall_on_resolved` only. The full
    `recall_on_all_tif` metric (combining detector + blocklist) needs a
    CH-querying eval script outside training (see design §6).
    """
    raw = model.predict(X_test, num_iteration=model.best_iteration)
    cal = iso.predict(raw)

    auc_raw = float(roc_auc_score(y_test, raw))
    auc_cal = float(roc_auc_score(y_test, cal))
    ap_raw = float(average_precision_score(y_test, raw))
    ap_cal = float(average_precision_score(y_test, cal))

    per_t_raw = _threshold_metrics(raw, y_test)
    per_t_cal = _threshold_metrics(cal, y_test)

    print(f"\n[eval] ROC AUC:    raw={auc_raw:.4f}  calibrated={auc_cal:.4f}", flush=True)
    print(f"[eval] Avg Prec:   raw={ap_raw:.4f}  calibrated={ap_cal:.4f}", flush=True)
    print("[eval] Calibrated threshold table (recall_on_resolved):", flush=True)
    for row in per_t_cal:
        print(
            f"        t={row['threshold']:.2f}  P={row['precision']:.4f}  "
            f"R={row['recall_on_resolved']:.4f}  "
            f"TP={row['tp']}  FP={row['fp']}  FN={row['fn']}",
            flush=True,
        )

    prec, rec, _ = precision_recall_curve(y_test, cal)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(rec, prec, label=f"AP={ap_cal:.3f}")
    ax.set_xlabel("Recall (resolved flows)")
    ax.set_ylabel("Precision")
    ax.set_title("Detector LightGBM v1 — Precision-Recall (calibrated)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    pr_path = output_dir / "precision_recall.png"
    fig.savefig(pr_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[eval] PR curve → {pr_path.name}", flush=True)

    slice_results: dict[str, dict[str, dict[str, float | int]]] = {}
    if slice_masks:
        print("\n[eval] slice metrics (calibrated):", flush=True)
        for name, mask in slice_masks.items():
            slice_results[name] = {}
            for t in (0.5, 0.7, 0.9):
                res = _slice_recall_fp(cal, y_test, mask, threshold=t)
                slice_results[name][f"t={t:.1f}"] = res
            r05 = slice_results[name]["t=0.5"]
            r09 = slice_results[name]["t=0.9"]
            print(
                f"        {name:32s}  pos={r05['n_pos']:>5}  neg={r05['n_neg']:>6}  "
                f"R@0.5={r05['recall']:.3f}  FP@0.5={r05['fp_rate']:.3%}  "
                f"R@0.9={r09['recall']:.3f}  FP@0.9={r09['fp_rate']:.3%}",
                flush=True,
            )

    return {
        "auc_raw": auc_raw,
        "auc_calibrated": auc_cal,
        "ap_raw": ap_raw,
        "ap_calibrated": ap_cal,
        "per_threshold_raw": per_t_raw,
        "per_threshold_calibrated": per_t_cal,
        "test_samples": int(len(y_test)),
        "test_pos": int(y_test.sum()),
        "test_neg": int((y_test == 0).sum()),
        "slice_metrics": slice_results,
        "recall_scope": (
            "resolved_only (list_action=PASS). "
            "recall_on_all_tif requires eval_detector_lgb.py — see design §6."
        ),
    }


# ---------------------------------------------------------------------------
# SHAP
# ---------------------------------------------------------------------------


def shap_analysis(
    model: lgb.Booster,
    X_test: pd.DataFrame,
    output_dir: Path,
    cap: int = 50_000,
) -> dict[str, Any]:
    """SHAP summary + CNN-embedding gate per design §5.5.

    Caps the SHAP compute set for speed; importance rankings are stable
    at 50k rows.
    """
    import shap

    if len(X_test) > cap:
        X_sample = X_test.sample(n=cap, random_state=42)
    else:
        X_sample = X_test

    print(f"\n[shap] computing on {len(X_sample):,} rows ...", flush=True)
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(X_sample)
    # TreeExplainer on binary LightGBM may return list[2] or single array.
    if isinstance(values, list) and len(values) == 2:
        sv = values[1]
    else:
        sv = values

    fig, _ = plt.subplots(figsize=(10, 8))
    shap.summary_plot(sv, X_sample, show=False, max_display=25)
    summary_path = output_dir / "shap_summary.png"
    plt.savefig(summary_path, dpi=150, bbox_inches="tight")
    plt.close("all")

    importance = (
        pd.DataFrame(
            {"feature": X_sample.columns, "mean_abs_shap": np.abs(sv).mean(axis=0)}
        )
        .sort_values("mean_abs_shap", ascending=False)
        .reset_index(drop=True)
    )
    importance.to_csv(output_dir / "feature_importance.csv", index=False)

    print("[shap] top 20 features:", flush=True)
    for _, r in importance.head(20).iterrows():
        print(f"        {r['feature']:35s}  {r['mean_abs_shap']:.4f}", flush=True)

    cnn_present = any(c.startswith(CNN_EMB_PREFIXES) for c in X_sample.columns)
    top50 = importance["feature"].head(50).tolist()
    cnn_in_top50 = sum(1 for f in top50 if f.startswith(CNN_EMB_PREFIXES))
    if not cnn_present:
        decision = "cnn_not_yet_added"
    elif cnn_in_top50 >= 10:
        decision = "keep_frozen"
    elif cnn_in_top50 < 5:
        decision = "retrain_cnn"
    else:
        decision = "ambiguous"
    gate = {
        "cnn_features_present": cnn_present,
        "cnn_features_in_top50": int(cnn_in_top50),
        "decision": decision,
    }
    print(f"[shap] CNN gate: {gate}", flush=True)

    return {
        "top_features": importance.head(30).to_dict("records"),
        "cnn_gate": gate,
    }


# ---------------------------------------------------------------------------
# ONNX export + fingerprint
# ---------------------------------------------------------------------------


def export_onnx(
    model: lgb.Booster,
    feature_names: list[str],
    output_dir: Path,
) -> Path:
    """Export LightGBM to ONNX. Calibrator is applied downstream (in Rust)."""
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    initial_types = [("features", FloatTensorType([None, len(feature_names)]))]
    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=initial_types,
        target_opset=15,
        zipmap=False,
    )
    onnx_path = output_dir / f"{MODEL_NAME}_{MODEL_VERSION}.onnx"
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))

    import onnxruntime as ort

    sess = ort.InferenceSession(str(onnx_path))
    probe = np.zeros((1, len(feature_names)), dtype=np.float32)
    out = sess.run(None, {"features": probe})
    print(
        f"[onnx] {onnx_path.name} ({onnx_path.stat().st_size/1024:.1f} KB)  "
        f"output_shape={out[0].shape}",
        flush=True,
    )
    return onnx_path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_features_fingerprint(
    feature_names: list[str],
    onnx_sha: str,
    cnn_sha: str | None,
    calibrator_version: str,
) -> str:
    """§8.2 features_fingerprint — binds feature set + artifacts together."""
    payload = (
        ",".join(sorted(feature_names))
        + f"|lgb={onnx_sha}"
        + f"|cnn={cnn_sha or 'none'}"
        + f"|cal={calibrator_version}"
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def save_metadata(
    output_dir: Path,
    *,
    feature_names: list[str],
    ordinal_maps: dict[str, dict[str, int]],
    calibrator_knots: dict[str, list[float]],
    onnx_path: Path,
    eval_results: dict[str, Any],
    shap_results: dict[str, Any],
    dataset_meta: dict[str, Any],
    split_sizes: dict[str, int],
    training_time_s: float,
    best_iteration: int,
    cli_args: argparse.Namespace,
) -> Path:
    onnx_sha = sha256_file(onnx_path)
    cnn_sha = (
        dataset_meta.get("cnn_onnx_sha256")
        if isinstance(dataset_meta, dict)
        else None
    )
    fingerprint = compute_features_fingerprint(
        feature_names, onnx_sha, cnn_sha, CALIBRATOR_VERSION,
    )

    meta = {
        "model": MODEL_NAME,
        "version": MODEL_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "ordinal_encode_features": ORDINAL_ENCODE_FEATURES,
        "treat_empty_as_category": sorted(TREAT_EMPTY_AS_CATEGORY),
        "ordinal_maps": ordinal_maps,
        "calibrator": {
            "type": "isotonic",
            "version": CALIBRATOR_VERSION,
            "x_thresholds": calibrator_knots["x"],
            "y_thresholds": calibrator_knots["y"],
            "out_of_bounds": "clip",
        },
        "onnx_filename": onnx_path.name,
        "onnx_sha256": onnx_sha,
        "features_fingerprint": fingerprint,
        "best_iteration": int(best_iteration),
        "training_time_seconds": training_time_s,
        "split_sizes": split_sizes,
        "evaluation": eval_results,
        "shap": shap_results,
        "dataset": dataset_meta,
        "cli_args": vars(cli_args),
    }
    out = output_dir / f"{MODEL_NAME}_{MODEL_VERSION}_meta.json"
    with open(out, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"[meta] {out.name}  (features_fingerprint={fingerprint[:12]}…)", flush=True)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--features",
        default=str(DATA_DIR / "detector_features.parquet"),
        help="Input parquet from build_detector_dataset.py",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output directory (default: models/detector_lgb_v1_<timestamp>)",
    )
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument(
        "--val-size", type=float, default=0.125,
        help="Within (train+val+cal) fraction held out for early stopping",
    )
    parser.add_argument(
        "--cal-size", type=float, default=0.125,
        help="Within (train+val+cal) fraction held out for isotonic calibration",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--num-boost-round", type=int, default=2000,
        help="Max trees; actual count capped by early stopping",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Optional cap on rows (smoke test)",
    )
    parser.add_argument(
        "--shap-cap", type=int, default=50_000,
        help="Row cap for SHAP compute on the test set",
    )
    parser.add_argument(
        "--rep-well-known-noise", type=float, default=0.0,
        help=(
            "Fraction of TRAIN rows with rep_is_well_known=1 to flip to 0 "
            "(symmetric across labels). Breaks the perfect "
            "well_known ↔ negative-label correlation that produces both "
            "the well_known=0→malicious and well_known=1→benign shortcuts. "
            "Val/cal/test stay clean so eval metrics reflect real inference. "
            "Try 0.10–0.30."
        ),
    )
    parser.add_argument(
        "--confidence-threshold", type=float, default=0.0,
        help=(
            "Drop POSITIVE rows whose confidence_active score is below "
            "this threshold before splitting/training. Default 0 = no "
            "filter. Typical values 0.3-0.5 to exclude flows whose "
            "resolution looks cleaned up / parked / sinkholed (the "
            "training-data contamination mode documented in "
            "project_bulk_resolution_contamination.md). Benign rows "
            "are never filtered — low-confidence on benigns is normal."
        ),
    )
    return parser.parse_args()


def apply_rep_well_known_noise(
    X: pd.DataFrame, pct: float, seed: int,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Flip rep_is_well_known=1 → 0 on a random `pct` of rows.

    Returns the noised X (copy) and a stats dict for logging.
    No-op when pct≤0 or the column is absent.
    """
    stats = {"eligible": 0, "flipped": 0}
    if pct <= 0 or "rep_is_well_known" not in X.columns:
        return X, stats
    X = X.copy()
    well_known_mask = (X["rep_is_well_known"] == 1.0).to_numpy()
    eligible = np.where(well_known_mask)[0]
    stats["eligible"] = int(len(eligible))
    if len(eligible) == 0:
        return X, stats
    rng = np.random.RandomState(seed)
    n_flip = int(round(len(eligible) * pct))
    if n_flip == 0:
        return X, stats
    flip_idx = rng.choice(eligible, size=n_flip, replace=False)
    col_loc = X.columns.get_loc("rep_is_well_known")
    X.iloc[flip_idx, col_loc] = 0.0
    stats["flipped"] = int(n_flip)
    return X, stats


def main() -> int:
    args = parse_args()
    features_path = Path(args.features)
    if not features_path.exists():
        print(f"[!] dataset not found: {features_path}", file=sys.stderr)
        print("    run build_detector_dataset.py first.", file=sys.stderr)
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = (
        Path(args.out)
        if args.out
        else MODELS_DIR / f"{MODEL_NAME}_{MODEL_VERSION}_{ts}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[out] {output_dir}", flush=True)

    # Optional dataset sidecar for audit + CNN SHA (when CNN cols land).
    dataset_meta: dict[str, Any] = {}
    sidecar = features_path.with_suffix(".meta.json")
    if sidecar.exists():
        with open(sidecar) as f:
            dataset_meta = json.load(f)

    # Load + encode.
    df = load_dataset(features_path, args.limit, args.confidence_threshold)
    X, feature_names, ordinal_maps = build_feature_matrix(df)
    y = df[LABEL_COL].to_numpy().astype(np.int8)

    # Split.
    splits = split_by_registrable(
        df, args.test_size, args.val_size, args.cal_size, args.seed
    )
    X_train, y_train = X.iloc[splits["train"]], y[splits["train"]]
    X_val, y_val = X.iloc[splits["val"]], y[splits["val"]]
    X_cal, y_cal = X.iloc[splits["cal"]], y[splits["cal"]]
    X_test, y_test = X.iloc[splits["test"]], y[splits["test"]]

    # Optional rep_is_well_known noise on TRAIN ONLY. Val/cal/test stay
    # clean so eval metrics reflect real-world inference, not the noised
    # training distribution.
    noise_stats = {"eligible": 0, "flipped": 0}
    if args.rep_well_known_noise > 0:
        X_train, noise_stats = apply_rep_well_known_noise(
            X_train, args.rep_well_known_noise, args.seed + 7,
        )
        print(
            f"[noise] flipped rep_is_well_known=1→0 on {noise_stats['flipped']:,} "
            f"of {noise_stats['eligible']:,} train rows "
            f"({args.rep_well_known_noise:.1%})",
            flush=True,
        )

    # Train.
    t0 = time.monotonic()
    model = train_lgb(X_train, y_train, X_val, y_val, args.num_boost_round)
    train_time = time.monotonic() - t0

    # Native dump for debugging / re-eval.
    lgb_path = output_dir / f"{MODEL_NAME}_{MODEL_VERSION}.lgb"
    model.save_model(str(lgb_path))
    print(f"[train] native → {lgb_path.name}", flush=True)

    # Calibrator (fit on dedicated cal holdout — NOT on the early-stop val).
    iso, knots = fit_calibrator(model, X_cal, y_cal)

    # Evaluate on test, with slices that probe specific failure modes.
    # The "well_known=0" slice is the critical one: a high FP rate there
    # means the model has learned `not well-known → malicious`, which would
    # mishandle every novel benign domain at inference time.
    test_df = df.iloc[splits["test"]].reset_index(drop=True)
    well_known = test_df["rep_is_well_known"].fillna(0).astype(np.int8).to_numpy()
    is_known_cdn = test_df["registrable_is_known_cdn"].fillna(0).astype(np.int8).to_numpy()
    slice_masks: dict[str, np.ndarray] = {
        "rep_is_well_known=1": well_known == 1,
        "rep_is_well_known=0 (novel-domain)": well_known == 0,
        "registrable_is_known_cdn=1": is_known_cdn == 1,
        "neither well-known nor CDN": (well_known == 0) & (is_known_cdn == 0),
    }
    eval_results = evaluate(
        model, iso, X_test, y_test, output_dir, slice_masks=slice_masks,
    )

    # SHAP on test.
    shap_results = shap_analysis(model, X_test, output_dir, cap=args.shap_cap)

    # ONNX export.
    onnx_path = export_onnx(model, feature_names, output_dir)

    # Metadata.
    split_sizes = {name: int(len(idx)) for name, idx in splits.items()}
    save_metadata(
        output_dir,
        feature_names=feature_names,
        ordinal_maps=ordinal_maps,
        calibrator_knots=knots,
        onnx_path=onnx_path,
        eval_results=eval_results,
        shap_results=shap_results,
        dataset_meta=dataset_meta,
        split_sizes=split_sizes,
        training_time_s=train_time,
        best_iteration=int(model.best_iteration or 0),
        cli_args=args,
    )

    print(f"\n[done] {output_dir}", flush=True)
    print(f"        AUC (cal) = {eval_results['auc_calibrated']:.4f}", flush=True)
    print(f"        AP  (cal) = {eval_results['ap_calibrated']:.4f}", flush=True)
    print(f"        train_time = {train_time:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
