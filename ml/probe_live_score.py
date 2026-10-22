"""One-shot probe: pull a few recent flows from production CH/PG, run them
through the new lgb_v1_cnn ONNX using build_detector_dataset.py's exact
feature pipeline, and compare to what control plane recorded in
detector_scores.

Diverge → bug in Rust feature extraction.
Agree   → model is genuinely producing low scores; not a Rust bug.

Run via SSH tunnels:
  ssh -fN -L 9000:127.0.0.1:9000 root@127.0.0.1
  ssh -fN -L 5433:127.0.0.1:5432 root@127.0.0.1
  uv run python probe_live_score.py
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd
import clickhouse_connect

import build_detector_dataset as bdd
import embed_detector_dataset as edd

ML_DIR = Path(__file__).parent
MODEL = ML_DIR / "models" / "detector_lgb_v1_cnn" / "detector_lgb_v1.onnx"
META = ML_DIR / "models" / "detector_lgb_v1_cnn" / "detector_lgb_v1_meta.json"
CNN_ONNX = ML_DIR / "models" / "detector_cnn_v1" / "cnn_embedding.onnx"

PG_URL = "host=localhost port=5433 dbname=nameserver user=nameserver_admin sslmode=disable"
CH_HOST = "localhost"
CH_PORT = 8123


def main() -> int:
    print("[ch] connecting...", flush=True)
    ch = clickhouse_connect.get_client(host=CH_HOST, port=CH_PORT, database="nameserver")

    # Pull last 30 min of flows; small sample.
    print("[ch] fetching recent flows...", flush=True)
    df = bdd.fetch_ch_flows(ch, days=1, limit=200)
    if df.empty:
        print("no flows", file=sys.stderr)
        return 1
    print(f"[ch] {len(df)} flows", flush=True)

    df = bdd.derive_features(df)
    df = bdd.enrich_reputation(PG_URL, df)
    df = bdd.enrich_nrd(PG_URL, df)
    df = bdd.enrich_popularity(PG_URL, df)

    # Add CNN embedding columns.
    print("[cnn] running embeddings...", flush=True)
    cnn_session = ort.InferenceSession(str(CNN_ONNX))
    unique_labels = edd.collect_unique_labels(df)
    label_to_vec = edd.batch_embed(cnn_session, sorted(unique_labels))
    streams = edd.build_stream_vectors(df, label_to_vec)
    df = edd.attach_columns(df, streams)

    # Reduce to model's expected feature_names in order.
    with open(META) as f:
        meta = json.load(f)
    feature_names = meta["feature_names"]
    ordinal_maps = meta.get("ordinal_maps", {})

    # Apply ordinal encoding the same way the trainer does (alphabetical sort).
    for col, mapping in ordinal_maps.items():
        if col in df.columns:
            df[col] = df[col].astype(str).map(mapping).astype("Float32")

    missing = [c for c in feature_names if c not in df.columns]
    if missing:
        print(f"[!] missing cols: {missing[:10]}{'...' if len(missing) > 10 else ''}",
              file=sys.stderr)
        for c in missing:
            df[c] = np.nan

    X = df[feature_names].astype(np.float32).values

    # Run model.
    print("[onnx] running model...", flush=True)
    sess = ort.InferenceSession(str(MODEL))
    out = sess.run(None, {"features": X})
    p_mal = out[1][:, 1]  # P(malicious)

    df["py_p_mal"] = p_mal

    # Print histogram.
    hist = pd.cut(df["py_p_mal"],
                  bins=[0, 0.01, 0.1, 0.3, 0.5, 0.7, 1.01],
                  include_lowest=True).value_counts().sort_index()
    print("\n=== Python (build_detector_dataset.py + ONNX) score distribution ===")
    for bucket, n in hist.items():
        print(f"  {str(bucket):20}  n={n}")
    print(f"  min={df['py_p_mal'].min():.4f}  max={df['py_p_mal'].max():.4f}  "
          f"mean={df['py_p_mal'].mean():.4f}  p95={df['py_p_mal'].quantile(0.95):.4f}")

    # Compare to detector_scores from CH for the same flow_ids.
    flow_ids = df["flow_id"].astype(str).tolist()
    print(f"\n=== Looking up {len(flow_ids)} flows in detector_scores ===")
    rust_query = f"""
        SELECT domain, ml_probability, ml_class
        FROM nameserver.detector_scores
        WHERE predicted_at >= now() - INTERVAL 1 DAY
          AND domain IN (SELECT DISTINCT domain FROM nameserver.flow_novelty
                         WHERE flow_id IN ({','.join(f"'{fid}'" for fid in flow_ids)}))
    """
    rust_rows = ch.query(rust_query).result_rows
    rust_by_domain: dict[str, list[float]] = {}
    for r in rust_rows:
        rust_by_domain.setdefault(r[0], []).append(r[1])

    diffs = []
    for _, row in df.iterrows():
        d = row["domain"]
        py = row["py_p_mal"]
        rust_scores = rust_by_domain.get(d, [])
        if rust_scores:
            rust = float(np.mean(rust_scores))
            diffs.append((d, py, rust, py - rust))

    print(f"\n=== Top 15 by |python - rust| ===")
    diffs.sort(key=lambda x: -abs(x[3]))
    print(f"  {'domain':50s}  {'py_mal':>7s}  {'rust_mal':>8s}  {'diff':>7s}")
    for d, py, rust, diff in diffs[:15]:
        print(f"  {d[:50]:50s}  {py:7.4f}  {rust:8.4f}  {diff:7.4f}")

    print(f"\n=== Summary: |python - rust| ===")
    if diffs:
        absdiff = np.abs([d[3] for d in diffs])
        print(f"  mean={absdiff.mean():.4f}  max={absdiff.max():.4f}  p95={np.quantile(absdiff, 0.95):.4f}")
        print(f"  n compared = {len(diffs)}")
    else:
        print("  no overlap between python output and rust scores")

    return 0


if __name__ == "__main__":
    sys.exit(main())
