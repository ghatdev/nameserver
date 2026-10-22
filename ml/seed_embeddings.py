"""Seed domain_label_embeddings table from well_known_domains + domain_ns_map.

One-off script to populate the pgvector table so Tier 1/2 similarity
search has data before live traffic fills it organically.

Usage:
    uv run python seed_embeddings.py
    uv run python seed_embeddings.py --pg-port 5433 --limit 50000
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import psycopg2
import tldextract

MODELS_DIR = Path(__file__).parent / "models"


def load_cnn(model_dir: Path):
    """Load CNN ONNX model."""
    import onnxruntime as ort

    meta_path = model_dir / "cnn_metadata.json"
    with open(meta_path) as f:
        meta = json.load(f)
    session = ort.InferenceSession(str(model_dir / "cnn_embedding.onnx"))
    return session, meta


def embed_labels_batch(session, meta: dict, labels: list[str], batch_size: int = 2048) -> dict[str, list[float]]:
    """Batch-embed labels using CNN ONNX."""
    char_to_idx = meta["char_to_idx"]
    max_len = meta["max_len"]
    input_name = meta.get("input_name", "label_chars")
    result: dict[str, list[float]] = {}

    for start in range(0, len(labels), batch_size):
        batch = labels[start:start + batch_size]
        encoded = []
        for label in batch:
            chars = [char_to_idx.get(c, 0) for c in label.lower()[:max_len]]
            chars += [0] * (max_len - len(chars))
            encoded.append(chars)
        outputs = session.run(None, {input_name: np.array(encoded, dtype=np.int64)})
        for i, label in enumerate(batch):
            result[label] = outputs[0][i].tolist()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed domain_label_embeddings from well_known_domains")
    parser.add_argument("--pg-port", type=int, default=5433)
    parser.add_argument("--pg-user", type=str, default="nameserver_admin")
    parser.add_argument("--pg-db", type=str, default="nameserver")
    parser.add_argument("--model-dir", type=str, default=str(MODELS_DIR / "label_cnn_maxpool"))
    parser.add_argument("--limit", type=int, default=50000)
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()

    conninfo = f"host=localhost port={args.pg_port} user={args.pg_user} dbname={args.pg_db}"

    # Load CNN
    print(f"Loading CNN model from {Path(args.model_dir).name} ...")
    session, meta = load_cnn(Path(args.model_dir))

    # Connect to PostgreSQL
    print(f"Connecting to PostgreSQL (port {args.pg_port}) ...")
    conn = psycopg2.connect(conninfo)
    cur = conn.cursor()

    # Read well_known_domains
    print("Reading well_known_domains ...")
    cur.execute("SELECT domain FROM well_known_domains")
    wk_domains = [row[0].rstrip(".") for row in cur.fetchall()]
    print(f"  {len(wk_domains):,} domains")

    # Also include high-traffic domains
    print("Reading high-traffic domains ...")
    cur.execute("SELECT domain FROM domains WHERE query_count >= 5 ORDER BY query_count DESC LIMIT 50000")
    traffic_domains = [row[0].rstrip(".") for row in cur.fetchall()]
    print(f"  {len(traffic_domains):,} traffic domains")

    all_domains = list(set(wk_domains) | set(traffic_domains))

    # Read NS map
    print("Reading domain_ns_map ...")
    cur.execute("SELECT registrable_domain, ns_domain FROM domain_ns_map")
    ns_map: dict[str, list[str]] = defaultdict(list)
    for reg, ns in cur.fetchall():
        ns_map[reg.rstrip(".")].append(ns.rstrip("."))

    # Extract labels
    print("Extracting registrable labels ...")
    label_to_data: dict[str, dict] = {}
    for domain in all_domains:
        ext = tldextract.extract(domain)
        label = ext.domain
        if not label or len(label) < 2:
            continue
        registrable = ext.registered_domain
        ns_domains = ns_map.get(registrable, [])

        if label not in label_to_data:
            label_to_data[label] = {"domains": [], "ns_domains": []}
        label_to_data[label]["domains"].append(domain)
        if ns_domains:
            label_to_data[label]["ns_domains"] = list(set(label_to_data[label]["ns_domains"]) | set(ns_domains))

    # Limit
    if len(label_to_data) > args.limit:
        sorted_labels = sorted(label_to_data.keys(), key=lambda l: len(label_to_data[l]["domains"]), reverse=True)
        label_to_data = {l: label_to_data[l] for l in sorted_labels[:args.limit]}

    unique_labels = sorted(label_to_data.keys())
    print(f"  {len(unique_labels):,} unique labels")

    # Compute embeddings
    print(f"Computing CNN embeddings ...")
    start = time.monotonic()
    embeddings = embed_labels_batch(session, meta, unique_labels)
    print(f"  Done in {time.monotonic() - start:.1f}s")

    # Insert into PostgreSQL
    print(f"Inserting into domain_label_embeddings ...")
    inserted = 0
    for i in range(0, len(unique_labels), args.batch_size):
        batch = unique_labels[i:i + args.batch_size]
        for label in batch:
            data = label_to_data[label]
            emb = embeddings[label]
            emb_str = "[" + ",".join(f"{v:.6f}" for v in emb) + "]"
            cur.execute(
                "INSERT INTO domain_label_embeddings (label, embedding, domains, ns_domains, updated_at) "
                "VALUES (%s, %s, %s, %s, NOW()) "
                "ON CONFLICT (label) DO UPDATE SET "
                "  embedding = EXCLUDED.embedding, "
                "  domains = EXCLUDED.domains, "
                "  ns_domains = EXCLUDED.ns_domains, "
                "  updated_at = NOW()",
                (label, emb_str, json.dumps(data["domains"][:10]), json.dumps(data["ns_domains"][:20])),
            )
            inserted += 1
        conn.commit()
        if (i + args.batch_size) % 10000 == 0:
            print(f"  {min(i + args.batch_size, len(unique_labels)):,} / {len(unique_labels):,} ...")

    conn.close()

    n_with_ns = sum(1 for d in label_to_data.values() if d["ns_domains"])
    print(f"\n{'='*60}")
    print(f"Seeded domain_label_embeddings:")
    print(f"  Labels:  {inserted:,}")
    print(f"  With NS: {n_with_ns:,} ({100*n_with_ns/max(inserted,1):.0f}%)")


if __name__ == "__main__":
    main()
