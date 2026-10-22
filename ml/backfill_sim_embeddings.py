"""Backfill `domain_label_embeddings.sim_embedding` via the trained
contrastive ONNX model.

Walks every row in `domain_label_embeddings` where `sim_embedding IS
NULL` and populates it by running the label through
`models/detector_cnn_sim_v1/cnn_sim_embedding.onnx`.

Idempotent: re-running only embeds rows that are still NULL. Safe to
interrupt and resume.

Run:
    uv run ml/backfill_sim_embeddings.py
    uv run ml/backfill_sim_embeddings.py --batch-size 1024 --commit-every 8
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import psycopg2
from psycopg2.extras import execute_values

ML_DIR = Path(__file__).parent
MODELS_DIR = ML_DIR / "models" / "detector_cnn_sim_v1"

DEFAULT_PG_URL = (
    "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
)

# Vocabulary identical to train_cnn_sim.py — same encoder contract.
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(CHARS)}
MAX_LEN = 63
PAD_IDX = 0


def encode_label(label: str) -> list[int]:
    s = label.lower()[:MAX_LEN]
    return [CHAR_TO_IDX.get(c, 0) for c in s]


def encode_batch(labels: list[str]) -> np.ndarray:
    arr = np.zeros((len(labels), MAX_LEN), dtype=np.int64)
    for i, lab in enumerate(labels):
        ids = encode_label(lab)
        arr[i, :len(ids)] = ids
    return arr


def vector_literal(emb: np.ndarray) -> str:
    """Format a numpy float vector as a pgvector text literal."""
    # `[v1,v2,...]` — pgvector parses this without a cast on UPDATE.
    return "[" + ",".join(f"{x:.6f}" for x in emb) + "]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--onnx",
        type=Path,
        default=MODELS_DIR / "cnn_sim_embedding.onnx",
    )
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument(
        "--commit-every",
        type=int,
        default=8,
        help="Commit after this many batches",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after embedding this many rows (0 = all)",
    )
    args = parser.parse_args()

    if not args.onnx.exists():
        print(f"[err] ONNX not found at {args.onnx}", flush=True, file=sys.stderr)
        return 1

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    print(f"[onnx] loading {args.onnx}", flush=True)
    sess = ort.InferenceSession(str(args.onnx))

    # Two connections: server-side cursor on `read_conn` would be
    # invalidated by every commit on the same connection, so writes go
    # through a separate `write_conn`.
    with psycopg2.connect(pg_url) as read_conn:
        with psycopg2.connect(pg_url) as write_conn:
            with read_conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM domain_label_embeddings "
                    "WHERE sim_embedding IS NULL"
                )
                row = cur.fetchone()
                total_remaining = row[0] if row else 0
            print(f"[pg] rows needing backfill: {total_remaining:,}", flush=True)

            if total_remaining == 0:
                print("[done] nothing to backfill", flush=True)
                return 0

            target = total_remaining if args.limit <= 0 else min(
                total_remaining, args.limit,
            )

            embedded = 0
            batch_no = 0
            t0 = time.time()
            with read_conn.cursor(name="dle_backfill") as src_cur:
                src_cur.itersize = args.batch_size
                src_cur.execute(
                    "SELECT label FROM domain_label_embeddings "
                    "WHERE sim_embedding IS NULL"
                )
                with write_conn.cursor() as upd_cur:
                    buffer: list[str] = []
                    for (label,) in src_cur:
                        buffer.append(label)
                        if len(buffer) < args.batch_size:
                            continue
                        embedded += flush_batch(sess, upd_cur, buffer)
                        buffer = []
                        batch_no += 1
                        if batch_no % args.commit_every == 0:
                            write_conn.commit()
                            elapsed = time.time() - t0
                            rate = embedded / elapsed if elapsed > 0 else 0.0
                            print(
                                f"[progress] {embedded:,}/{target:,} "
                                f"({100 * embedded / target:.1f}%) "
                                f"@ {rate:.0f} rows/s",
                                flush=True,
                            )
                        if args.limit > 0 and embedded >= args.limit:
                            break
                    if buffer:
                        embedded += flush_batch(sess, upd_cur, buffer)
                    write_conn.commit()

            elapsed = time.time() - t0
            print(
                f"[done] embedded {embedded:,} rows in {elapsed:.0f}s "
                f"({embedded / elapsed:.0f} rows/s)",
                flush=True,
            )
    return 0


def flush_batch(
    sess: ort.InferenceSession,
    upd_cur,
    labels: list[str],
) -> int:
    """Embed `labels` via ONNX and bulk-update sim_embedding."""
    if not labels:
        return 0
    inputs = encode_batch(labels)
    out = sess.run(None, {"label_chars": inputs})[0]  # (N, 64) float32
    # L2-normalize defensively — the trainer normalizes inside the
    # graph but a fresh ONNX export was a degree of freedom we want to
    # eliminate from the storage path.
    norms = np.linalg.norm(out, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    out = out / norms
    rows = [(label, vector_literal(emb)) for label, emb in zip(labels, out)]
    # Bulk UPDATE via VALUES join: one round-trip per batch instead of
    # one UPDATE per row.
    execute_values(
        upd_cur,
        "UPDATE domain_label_embeddings AS d "
        "SET sim_embedding = v.emb::vector "
        "FROM (VALUES %s) AS v(label, emb) "
        "WHERE d.label = v.label",
        rows,
    )
    return len(rows)


if __name__ == "__main__":
    sys.exit(main())
