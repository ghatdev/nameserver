"""Probe what the new lgb_v1_cnn ONNX scores for TIF-labeled flows
specifically. If these score high, the live model is working and
production "all flows compressed near 0" is just because real traffic
is mostly benign. If these ALSO score low, the model has a real
generalization problem (or feature drift since training).
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
    ch = clickhouse_connect.get_client(host=CH_HOST, port=CH_PORT, database="nameserver")

    # Pull recent flows whose domain is in incident_labels with malicious verdict layer=dns.
    # Joining at flow level via PG → CH is ugly. Easier: pull a normal flow
    # batch + tag those whose domain is TIF after the fact.
    print("[ch] fetching last 7 days of flows...", flush=True)
    df = bdd.fetch_ch_flows(ch, days=7, limit=2000)
    if df.empty:
        print("no flows")
        return 1

    # Pull TIF positive registrables from PG.
    import psycopg2
    print("[pg] fetching TIF/malicious-labeled domains...", flush=True)
    with psycopg2.connect(PG_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT domain
                FROM incident_labels
                WHERE verdict = 'malicious' AND layer = 'dns'
            """)
            tif = {r[0] for r in cur.fetchall()}
    print(f"[pg] {len(tif):,} malicious-labeled DNS domains", flush=True)

    # Tag flows. CH domains have trailing dot; strip both sides.
    df["domain_clean"] = df["domain"].str.rstrip(".")
    df["registrable_clean"] = df["registrable"].astype(str).str.rstrip(".")
    df["is_tif"] = df["registrable_clean"].isin(tif) | df["domain_clean"].isin(tif)
    print(f"[ch] {df['is_tif'].sum()} flows match TIF / {len(df)}", flush=True)
    print(f"     sample registrable: {df['registrable'].head(3).tolist()}")
    print(f"     sample tif example: {next(iter(tif), None)}")
    if df["is_tif"].sum() == 0:
        print("[!] no TIF flows — checking exact match logic")
        # Show what the injector probed.
        sample_recent = df["registrable_clean"].head(5).tolist()
        print(f"     recent registrables: {sample_recent}")
        # Try one in tif lookup directly
        for r in sample_recent:
            print(f"     '{r}' in tif: {r in tif}")
        return 1

    df = bdd.derive_features(df)
    df = bdd.enrich_reputation(PG_URL, df)
    df = bdd.enrich_nrd(PG_URL, df)
    df = bdd.enrich_popularity(PG_URL, df)

    print("[cnn] running embeddings...", flush=True)
    cnn_session = ort.InferenceSession(str(CNN_ONNX))
    unique_labels = edd.collect_unique_labels(df)
    label_to_vec = edd.batch_embed(cnn_session, sorted(unique_labels))
    streams = edd.build_stream_vectors(df, label_to_vec)
    df = edd.attach_columns(df, streams)

    with open(META) as f:
        meta = json.load(f)
    feature_names = meta["feature_names"]
    ordinal_maps = meta.get("ordinal_maps", {})

    for col, mapping in ordinal_maps.items():
        if col in df.columns:
            df[col] = df[col].astype(str).map(mapping).astype("Float32")

    for c in feature_names:
        if c not in df.columns:
            df[c] = np.nan

    X = df[feature_names].astype(np.float32).values
    sess = ort.InferenceSession(str(MODEL))
    out = sess.run(None, {"features": X})
    df["py_p_mal"] = out[1][:, 1]

    print("\n=== Python ONNX score by group ===")
    for group, sub in df.groupby("is_tif"):
        label = "TIF (malicious)" if group else "non-TIF"
        print(f"  {label:20}  n={len(sub):4}  mean={sub['py_p_mal'].mean():.4f}  "
              f"p50={sub['py_p_mal'].quantile(0.5):.4f}  "
              f"p95={sub['py_p_mal'].quantile(0.95):.4f}  "
              f"max={sub['py_p_mal'].max():.4f}")

    print("\n=== Top 10 TIF flows by py_p_mal ===")
    tif_rows = df[df["is_tif"]].sort_values("py_p_mal", ascending=False).head(10)
    for _, r in tif_rows.iterrows():
        print(f"  py={r['py_p_mal']:.4f}  {r['domain'][:60]}  "
              f"first_contact={r.get('is_first_contact', 0)}  "
              f"age_min={r.get('age_minutes_at_flow', 0):.0f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
