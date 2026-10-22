"""Compile domain similarity index for scoring chain Step 3.5.

Reads well_known_domains + domain_ns_map from PostgreSQL, runs CNN label
embeddings via ONNX Runtime, serializes to compiled/similarity_index.bin
(MessagePack format) for Rust consumption.

Usage:
    uv run python compile_similarity_index.py
    uv run python compile_similarity_index.py --pg-port 5433
    uv run python compile_similarity_index.py --model-dir models/label_cnn_maxpool --limit 100000
"""

from __future__ import annotations

import argparse
import time
from collections import defaultdict
from pathlib import Path

import msgpack
import numpy as np
import psycopg2
import tldextract

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"
COMPILED_DIR = Path(__file__).parent.parent / "compiled"


def load_cnn_model(model_dir: Path) -> tuple:
    """Load CNN ONNX model and metadata."""
    import json
    import onnxruntime as ort

    meta_path = model_dir / "cnn_metadata.json"
    onnx_path = model_dir / "cnn_embedding.onnx"

    if not meta_path.exists() or not onnx_path.exists():
        raise FileNotFoundError(f"CNN model not found in {model_dir}")

    with open(meta_path) as f:
        meta = json.load(f)

    session = ort.InferenceSession(str(onnx_path))
    return session, meta


def embed_labels(
    session, meta: dict, labels: list[str], batch_size: int = 2048,
) -> dict[str, list[float]]:
    """Batch-embed registrable labels using CNN ONNX model."""
    char_to_idx = meta["char_to_idx"]
    max_len = meta["max_len"]
    input_name = meta.get("input_name", "label_chars")

    result: dict[str, list[float]] = {}

    for start in range(0, len(labels), batch_size):
        batch = labels[start : start + batch_size]
        encoded = []
        for label in batch:
            chars = [char_to_idx.get(c, 0) for c in label.lower()[:max_len]]
            chars += [0] * (max_len - len(chars))
            encoded.append(chars)

        input_array = np.array(encoded, dtype=np.int64)
        outputs = session.run(None, {input_name: input_array})
        embeddings = outputs[0]  # (batch_size, embedding_dim)

        for i, label in enumerate(batch):
            result[label] = embeddings[i].tolist()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile similarity index")
    parser.add_argument("--pg-port", type=int, default=5433)
    parser.add_argument("--pg-user", type=str, default="nameserver_admin")
    parser.add_argument("--pg-db", type=str, default="nameserver")
    parser.add_argument("--model-dir", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    parser.add_argument("--output", type=str, default=str(COMPILED_DIR / "similarity_index.bin"))
    parser.add_argument("--limit", type=int, default=100_000,
                        help="Max unique labels for Tier 2 embedding index")
    args = parser.parse_args()

    conninfo = f"host=localhost port={args.pg_port} user={args.pg_user} dbname={args.pg_db}"

    # Load CNN model
    model_dir = Path(args.model_dir)
    print(f"Loading CNN model from {model_dir.name} ...")
    session, meta = load_cnn_model(model_dir)
    embedding_dim = meta["embedding_dim"]
    print(f"  Embedding dim: {embedding_dim}")

    # Connect to PostgreSQL
    print(f"\nConnecting to PostgreSQL (port {args.pg_port}) ...")
    conn = psycopg2.connect(conninfo)
    cur = conn.cursor()

    # Read well_known_domains
    print("Reading well_known_domains ...")
    cur.execute("SELECT domain FROM well_known_domains")
    wk_domains = [row[0].rstrip(".") for row in cur.fetchall()]
    print(f"  {len(wk_domains):,} well-known domains")

    # Also include high-traffic domains from our own resolver
    print("Reading high-traffic domains ...")
    cur.execute("SELECT domain FROM domains WHERE query_count >= 5 ORDER BY query_count DESC LIMIT 50000")
    traffic_domains = [row[0].rstrip(".") for row in cur.fetchall()]
    print(f"  {len(traffic_domains):,} traffic domains")

    wk_domains = list(set(wk_domains) | set(traffic_domains))
    print(f"  {len(wk_domains):,} total unique domains")

    # Read domain_ns_map
    print("Reading domain_ns_map ...")
    cur.execute("SELECT registrable_domain, ns_domain FROM domain_ns_map")
    ns_map: dict[str, list[str]] = defaultdict(list)
    for reg, ns in cur.fetchall():
        ns_map[reg.rstrip(".")].append(ns.rstrip("."))
    print(f"  {len(ns_map):,} registrable domains with NS data")

    conn.close()

    # Extract registrable labels and group domains
    print("\nExtracting registrable labels ...")
    label_to_domains: dict[str, list[dict]] = defaultdict(list)

    for domain in wk_domains:
        ext = tldextract.extract(domain)
        label = ext.domain
        if not label:
            continue
        registrable = ext.registered_domain
        ns_domains = ns_map.get(registrable, [])
        label_to_domains[label].append({
            "domain": domain,
            "ns_domains": ns_domains,
        })

    print(f"  {len(label_to_domains):,} unique labels")

    # Limit for Tier 2 (sort by number of domains per label, keep most popular)
    if len(label_to_domains) > args.limit:
        sorted_labels = sorted(
            label_to_domains.keys(),
            key=lambda l: len(label_to_domains[l]),
            reverse=True,
        )
        kept = set(sorted_labels[: args.limit])
        label_to_domains = {l: v for l, v in label_to_domains.items() if l in kept}
        print(f"  Limited to {len(label_to_domains):,} labels (top by domain count)")

    # Compute CNN embeddings
    unique_labels = sorted(label_to_domains.keys())
    print(f"\nComputing CNN embeddings for {len(unique_labels):,} labels ...")
    start = time.monotonic()
    embeddings = embed_labels(session, meta, unique_labels)
    elapsed = time.monotonic() - start
    print(f"  Done in {elapsed:.1f}s ({len(embeddings) / max(elapsed, 0.001):.0f} labels/sec)")

    # Build index
    label_index: dict[str, list[dict]] = {}
    entries: list[dict] = []

    for label in unique_labels:
        domains = label_to_domains[label]
        label_index[label] = domains
        entries.append({
            "label": label,
            "embedding": embeddings[label],
            "domains": domains,
        })

    index = {
        "label_index": label_index,
        "entries": entries,
        "embedding_dim": embedding_dim,
    }

    # Serialize with MessagePack
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = msgpack.packb(index, use_bin_type=True)
    output_path.write_bytes(data)

    # Stats
    n_with_ns = sum(
        1 for doms in label_index.values()
        if any(d["ns_domains"] for d in doms)
    )

    print(f"\n{'='*60}")
    print(f"Similarity index compiled!")
    print(f"  Output:     {output_path}")
    print(f"  Size:       {len(data) / 1024 / 1024:.1f} MB")
    print(f"  Labels:     {len(label_index):,}")
    print(f"  Embeddings: {len(entries):,} × {embedding_dim}d")
    print(f"  With NS:    {n_with_ns:,} ({100 * n_with_ns / max(len(label_index), 1):.0f}%)")


if __name__ == "__main__":
    main()
