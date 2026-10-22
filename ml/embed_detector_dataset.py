"""Inject CNN embeddings into the detector feature parquet.

Reads `data/detector_features.parquet`, runs the detector CNN
(`models/detector_cnn_v1/cnn_embedding.onnx` or similar) over four
streams per flow, max-pools per stream, and writes an expanded parquet
with 128 new columns the LightGBM trainer will automatically pick up.

Streams (`docs/detector-cnn-design.md` §3.1):
  query_reg_emb_0..31       — registrable label of `domain`
  query_sub_emb_0..31       — subdomain labels of `domain`, max-pool
  cname_target_emb_0..31    — labels across every CNAME target, max-pool
  ns_host_emb_0..31         — labels across every NS hostname in
                              `path_server_names`, max-pool

Strategy: collect every DNS label needed across the whole parquet
(usually 100K–1M unique labels), batch-embed them once, then assemble
per-flow vectors by dict lookup. Much faster than per-row inference.

Missing streams emit the zero vector (not NaN). LightGBM would
otherwise learn "CNAME absent → malicious" as a shortcut, which
wouldn't generalize.

Run:
    uv run ml/embed_detector_dataset.py
    uv run ml/embed_detector_dataset.py \
        --onnx models/detector_cnn_v1/cnn_embedding.onnx \
        --in data/detector_features.parquet \
        --out data/detector_features_cnn.parquet
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort
import pandas as pd
import tldextract

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"
MODELS_DIR = ML_DIR / "models"

# Character vocabulary — must match train_cnn.py exactly, or embeddings
# will be nonsense.
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
CHAR_TO_IDX: dict[str, int] = {c: i + 1 for i, c in enumerate(CHARS)}
MAX_LEN = 63
PAD_IDX = 0
EMBEDDING_DIM = 32

STREAM_NAMES: list[str] = [
    "query_reg",
    "query_sub",
    "cname_target",
    "ns_host",
]


def encode_label(label: str) -> np.ndarray:
    """Encode a single DNS label to a length-MAX_LEN int64 array."""
    lower = label.lower()[:MAX_LEN]
    encoded = [CHAR_TO_IDX.get(c, 0) for c in lower]
    encoded.extend([PAD_IDX] * (MAX_LEN - len(encoded)))
    return np.asarray(encoded, dtype=np.int64)


def extract_labels_from_fqdn(fqdn: str) -> tuple[str, list[str]]:
    """Return (registrable_label, subdomain_labels) for an FQDN.

    Uses tldextract with private-domains enabled so `user.github.io`
    splits to (user, []) rather than (github, [user]).
    """
    if not fqdn:
        return "", []
    fqdn = fqdn.rstrip(".")
    ext = tldextract.extract(fqdn)
    reg = ext.domain or ""
    subs = [s for s in (ext.subdomain.split(".") if ext.subdomain else []) if s]
    return reg, subs


def normalize_chain_targets(raw: Any) -> list[str]:
    """CNAME chain can arrive as list[str] / ndarray / None — normalize."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw else []
    try:
        return [str(x).rstrip(".") for x in raw if x]
    except TypeError:
        return []


def collect_unique_labels(df: pd.DataFrame) -> set[str]:
    """Walk every row and collect every DNS label we'll need to embed."""
    unique: set[str] = set()
    for _, row in df.iterrows():
        # query
        reg, subs = extract_labels_from_fqdn(str(row.get("domain") or ""))
        if reg:
            unique.add(reg)
        unique.update(subs)
        # cname targets
        for target in normalize_chain_targets(row.get("cname_chain")):
            t_reg, t_subs = extract_labels_from_fqdn(target)
            if t_reg:
                unique.add(t_reg)
            unique.update(t_subs)
        # ns hostnames — Nested array, strings or None
        for ns in normalize_chain_targets(row.get("path_server_names")):
            n_reg, n_subs = extract_labels_from_fqdn(ns)
            if n_reg:
                unique.add(n_reg)
            unique.update(n_subs)
    unique.discard("")
    return unique


def batch_embed(
    session: ort.InferenceSession,
    labels: list[str],
    batch_size: int = 2048,
) -> dict[str, np.ndarray]:
    """Run ONNX over every unique label; return {label: 32-dim vector}."""
    if not labels:
        return {}
    print(f"[embed] {len(labels):,} unique labels ...", flush=True)
    all_embeds = np.empty((len(labels), EMBEDDING_DIM), dtype=np.float32)
    for start in range(0, len(labels), batch_size):
        chunk = labels[start : start + batch_size]
        arr = np.stack([encode_label(lbl) for lbl in chunk])
        out = session.run(None, {"label_chars": arr})[0]
        all_embeds[start : start + len(chunk)] = out
        if (start // batch_size) % 20 == 0:
            print(f"  ... {start + len(chunk):,} / {len(labels):,}", flush=True)
    return {lbl: all_embeds[i] for i, lbl in enumerate(labels)}


ZERO_VEC = np.zeros(EMBEDDING_DIM, dtype=np.float32)


def pool_labels(
    labels: list[str],
    label_to_vec: dict[str, np.ndarray],
) -> np.ndarray:
    """Element-wise max across a set of labels. Empty → zero vector."""
    if not labels:
        return ZERO_VEC
    vecs = [label_to_vec.get(lbl, ZERO_VEC) for lbl in labels if lbl]
    if not vecs:
        return ZERO_VEC
    return np.max(np.stack(vecs), axis=0)


def build_stream_vectors(
    df: pd.DataFrame,
    label_to_vec: dict[str, np.ndarray],
) -> dict[str, np.ndarray]:
    """Produce a (N, 32) array for each of the four streams."""
    n = len(df)
    out: dict[str, np.ndarray] = {
        name: np.zeros((n, EMBEDDING_DIM), dtype=np.float32)
        for name in STREAM_NAMES
    }

    for i, row in enumerate(df.itertuples(index=False)):
        if i % 100_000 == 0 and i > 0:
            print(f"  ... assembled {i:,} / {n:,}", flush=True)

        domain = getattr(row, "domain", "") or ""
        reg, subs = extract_labels_from_fqdn(str(domain))
        out["query_reg"][i] = label_to_vec.get(reg, ZERO_VEC) if reg else ZERO_VEC
        out["query_sub"][i] = pool_labels(subs, label_to_vec)

        # CNAME stream
        cname_labels: list[str] = []
        for target in normalize_chain_targets(getattr(row, "cname_chain", None)):
            t_reg, t_subs = extract_labels_from_fqdn(target)
            if t_reg:
                cname_labels.append(t_reg)
            cname_labels.extend(t_subs)
        out["cname_target"][i] = pool_labels(cname_labels, label_to_vec)

        # NS stream
        ns_labels: list[str] = []
        for ns in normalize_chain_targets(
            getattr(row, "path_server_names", None)
        ):
            n_reg, n_subs = extract_labels_from_fqdn(ns)
            if n_reg:
                ns_labels.append(n_reg)
            ns_labels.extend(n_subs)
        out["ns_host"][i] = pool_labels(ns_labels, label_to_vec)

    return out


def attach_columns(df: pd.DataFrame, streams: dict[str, np.ndarray]) -> pd.DataFrame:
    """Append the 128 embedding columns to the dataframe in-place-ish."""
    for name, arr in streams.items():
        for i in range(EMBEDDING_DIM):
            df[f"{name}_emb_{i}"] = arr[:, i].astype("float32")
    return df


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--onnx", type=Path,
        default=MODELS_DIR / "detector_cnn_v1" / "cnn_embedding.onnx",
        help="Path to the detector CNN ONNX (embedding head only).",
    )
    parser.add_argument(
        "--in", dest="input_parquet", type=Path,
        default=DATA_DIR / "detector_features.parquet",
    )
    parser.add_argument(
        "--out", dest="output_parquet", type=Path,
        default=DATA_DIR / "detector_features_cnn.parquet",
    )
    parser.add_argument("--batch-size", type=int, default=2048)
    args = parser.parse_args()

    if not args.onnx.exists():
        print(f"[!] ONNX model not found: {args.onnx}", file=sys.stderr)
        return 2
    if not args.input_parquet.exists():
        print(f"[!] input parquet not found: {args.input_parquet}", file=sys.stderr)
        return 2

    print(f"[onnx] loading {args.onnx}", flush=True)
    session = ort.InferenceSession(str(args.onnx))

    print(f"[in]   reading {args.input_parquet}", flush=True)
    df = pd.read_parquet(args.input_parquet)
    print(f"       rows={len(df):,} cols={df.shape[1]}", flush=True)

    print("[scan] collecting unique labels ...", flush=True)
    unique_labels = collect_unique_labels(df)
    label_list = sorted(unique_labels)
    print(f"       {len(label_list):,} unique labels", flush=True)

    label_to_vec = batch_embed(session, label_list, batch_size=args.batch_size)

    print("[pool] building per-flow stream vectors ...", flush=True)
    streams = build_stream_vectors(df, label_to_vec)

    print("[attach] appending 128 embedding columns ...", flush=True)
    df = attach_columns(df, streams)

    args.output_parquet.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.output_parquet, index=False)
    print(f"[out] wrote {len(df):,} rows x {df.shape[1]} cols "
          f"to {args.output_parquet}", flush=True)

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_parquet": str(args.input_parquet),
        "output_parquet": str(args.output_parquet),
        "cnn_onnx_path": str(args.onnx),
        "cnn_onnx_sha256": sha256_file(args.onnx),
        "embedding_dim": EMBEDDING_DIM,
        "streams": STREAM_NAMES,
        "new_columns": [
            f"{s}_emb_{i}" for s in STREAM_NAMES for i in range(EMBEDDING_DIM)
        ],
        "rows": int(len(df)),
        "unique_labels_embedded": len(label_list),
    }
    meta_path = args.output_parquet.with_suffix(".meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"[meta] {meta_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
