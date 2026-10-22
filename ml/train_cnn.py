"""Train character-level CNN for domain label classification.

Trains a CNN on individual DNS labels (registrable labels and subdomain labels
separately) rather than full FQDNs. This prevents subdomain complexity from
being conflated with malicious character patterns.

After training, exports the embedding extractor as ONNX. At inference time,
the same CNN is called once per label, then embeddings are aggregated:
  - Registrable label → reg_emb_0..31
  - Subdomain labels  → aggregated into sub_emb_0..31 (max-pool or concat)

Usage:
    uv run python train_cnn.py
    uv run python train_cnn.py --variant concat --epochs 20
    uv run python train_cnn.py --extract --variant maxpool
"""

import argparse
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, random_split
from sklearn.metrics import roc_auc_score, classification_report
import tldextract

# Character vocabulary — no dot (labels never contain dots)
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(CHARS)}  # 0 = padding
VOCAB_SIZE = len(CHARS) + 1  # +1 for padding
MAX_LEN = 63  # DNS label maximum per RFC 1035
PAD_IDX = 0

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


class LabelDataset(Dataset):
    """Dataset of individual DNS labels with binary labels."""

    def __init__(self, labels_text: list[str], labels_y: list[int]):
        self.labels_text = labels_text
        self.labels_y = labels_y

    def __len__(self):
        return len(self.labels_text)

    def __getitem__(self, idx):
        label = self.labels_text[idx].lower()
        encoded = [CHAR_TO_IDX.get(c, 0) for c in label[:MAX_LEN]]
        padded = encoded + [PAD_IDX] * (MAX_LEN - len(encoded))
        return torch.tensor(padded, dtype=torch.long), torch.tensor(self.labels_y[idx], dtype=torch.float32)


class LabelCNN(nn.Module):
    """Character-level CNN for DNS label classification.

    Architecture: char embedding -> 3 parallel conv branches -> concat -> dense -> embedding -> classifier
    Operates on individual DNS labels (not full FQDNs).
    """

    def __init__(self, vocab_size=VOCAB_SIZE, embed_dim=16, num_filters=64, embedding_dim=32):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)

        self.conv3 = nn.Sequential(
            nn.Conv1d(embed_dim, num_filters, kernel_size=3, padding=1),
            nn.ReLU(),
        )
        self.conv4 = nn.Sequential(
            nn.Conv1d(embed_dim, num_filters, kernel_size=4, padding=1),
            nn.ReLU(),
        )
        self.conv5 = nn.Sequential(
            nn.Conv1d(embed_dim, num_filters, kernel_size=5, padding=2),
            nn.ReLU(),
        )

        concat_dim = num_filters * 3  # 192

        self.dropout1 = nn.Dropout(0.3)
        self.fc1 = nn.Linear(concat_dim, 64)
        self.dropout2 = nn.Dropout(0.2)
        self.fc_embed = nn.Linear(64, embedding_dim)
        self.fc_out = nn.Linear(embedding_dim, 1)

    def get_embedding(self, x):
        """Extract embedding (without classification head)."""
        e = self.embedding(x)       # (batch, seq_len, embed_dim)
        e = e.transpose(1, 2)       # (batch, embed_dim, seq_len)

        c3 = self.conv3(e).max(dim=2).values
        c4 = self.conv4(e).max(dim=2).values
        c5 = self.conv5(e).max(dim=2).values

        cat = torch.cat([c3, c4, c5], dim=1)
        cat = self.dropout1(cat)

        h = torch.relu(self.fc1(cat))
        h = self.dropout2(h)
        return torch.relu(self.fc_embed(h))

    def forward(self, x):
        embed = self.get_embedding(x)
        out = torch.sigmoid(self.fc_out(embed))
        return out.squeeze(-1)


def load_dataset(path: Path) -> tuple[list[str], list[int]]:
    """Load dataset (Parquet or CSV) and return (domains, labels)."""
    import pandas as pd

    if str(path).endswith(".parquet"):
        df = pd.read_parquet(path, columns=["domain", "label"])
    else:
        df = pd.read_csv(path, usecols=["domain", "label"], low_memory=False)
    return df["domain"].tolist(), df["label"].astype(int).tolist()


def prepare_label_dataset(
    domains: list[str], labels: list[int],
) -> tuple[list[str], list[int]]:
    """Split FQDNs into individual DNS labels for training.

    - Malicious domains: registrable label marked malicious.
    - Benign domains: registrable label AND each subdomain label marked benign.
    - Deduplicate by label string with majority-vote for conflicts.
    """
    label_counts: Counter[str] = Counter()  # label_text -> {0: count, 1: count}
    label_votes: dict[str, list[int]] = {}

    for domain, y in zip(domains, labels):
        ext = tldextract.extract(domain)
        reg_label = ext.domain
        if not reg_label:
            continue

        # Registrable label gets the domain's label
        label_votes.setdefault(reg_label, [0, 0])
        label_votes[reg_label][y] += 1
        label_counts[reg_label] += 1

        # Subdomain labels: always marked benign for benign domains.
        # For malicious domains, subdomain labels are excluded (most malicious
        # domains have no subdomains; those that do have benign-looking subdomains
        # like "www" or "login" that we don't want to mark malicious).
        if y == 0 and ext.subdomain:
            for sub_label in ext.subdomain.split("."):
                sub_label = sub_label.strip()
                if not sub_label:
                    continue
                label_votes.setdefault(sub_label, [0, 0])
                label_votes[sub_label][0] += 1
                label_counts[sub_label] += 1

    # Majority-vote deduplication
    out_labels: list[str] = []
    out_y: list[int] = []
    conflicts = 0
    for label_text, votes in label_votes.items():
        if votes[0] > 0 and votes[1] > 0:
            conflicts += 1
        # Majority vote: if tied, lean benign (fewer FPs)
        y = 1 if votes[1] > votes[0] else 0
        out_labels.append(label_text)
        out_y.append(y)

    n_mal = sum(out_y)
    n_ben = len(out_y) - n_mal
    print(f"  Label dataset: {len(out_y):,} unique labels ({n_mal:,} malicious, {n_ben:,} benign)")
    print(f"  Conflicts (both classes): {conflicts:,} (resolved by majority vote)")
    return out_labels, out_y


def train_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    for batch_x, batch_y in loader:
        batch_x, batch_y = batch_x.to(device), batch_y.to(device)
        optimizer.zero_grad()
        output = model(batch_x)
        loss = criterion(output, batch_y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(batch_y)
        preds = (output >= 0.5).float()
        correct += (preds == batch_y).sum().item()
        total += len(batch_y)
    return total_loss / total, correct / total


def evaluate(model, loader, device):
    model.eval()
    all_probs = []
    all_labels = []
    total_loss = 0
    criterion = nn.BCELoss()
    with torch.no_grad():
        for batch_x, batch_y in loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            output = model(batch_x)
            loss = criterion(output, batch_y)
            total_loss += loss.item() * len(batch_y)
            all_probs.extend(output.cpu().numpy())
            all_labels.extend(batch_y.cpu().numpy())

    all_probs_arr = np.array(all_probs)
    all_labels_arr = np.array(all_labels)
    auc = roc_auc_score(all_labels_arr, all_probs_arr)
    avg_loss = total_loss / len(all_labels_arr)
    return avg_loss, auc, all_probs_arr, all_labels_arr


def export_onnx(model, embedding_dim, output_dir):
    """Export embedding extractor (without classification head) as ONNX."""
    model.eval()

    class EmbeddingExtractor(nn.Module):
        def __init__(self, cnn):
            super().__init__()
            self.cnn = cnn

        def forward(self, x):
            return self.cnn.get_embedding(x)

    extractor = EmbeddingExtractor(model)
    extractor.eval()

    dummy_input = torch.zeros(1, MAX_LEN, dtype=torch.long)
    onnx_path = output_dir / "cnn_embedding.onnx"

    torch.onnx.export(
        extractor,
        dummy_input,
        str(onnx_path),
        input_names=["label_chars"],
        output_names=["embedding"],
        dynamic_axes={"label_chars": {0: "batch_size"}, "embedding": {0: "batch_size"}},
        opset_version=17,
        dynamo=False,
    )

    import onnxruntime as ort
    session = ort.InferenceSession(str(onnx_path))
    test_input = np.zeros((1, MAX_LEN), dtype=np.int64)
    result = session.run(None, {"label_chars": test_input})
    assert result[0].shape == (1, embedding_dim), f"Expected (1, {embedding_dim}), got {result[0].shape}"

    print(f"  ONNX embedding model -> {onnx_path} ({onnx_path.stat().st_size / 1024:.1f} KB)")
    return onnx_path


def encode_label(label: str) -> list[int]:
    """Encode a single DNS label to character indices."""
    return [CHAR_TO_IDX.get(c, 0) for c in label.lower()[:MAX_LEN]]


def extract_label_embedding(model, labels: list[str], device, batch_size=2048) -> np.ndarray:
    """Extract embeddings for a list of individual labels. Returns (N, embedding_dim)."""
    model.eval()
    dataset = LabelDataset(labels, [0] * len(labels))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

    embeddings = []
    with torch.no_grad():
        for batch_x, _ in loader:
            batch_x = batch_x.to(device)
            embed = model.get_embedding(batch_x)
            embeddings.append(embed.cpu().numpy())

    return np.concatenate(embeddings, axis=0)


def extract_split_embeddings(
    model, domains: list[str], labels: list[int],
    device, embedding_dim: int,
    variant: str, max_slots: int,
    batch_size: int = 2048,
) -> "pd.DataFrame":
    """Extract per-label embeddings for all domains, aggregated per variant.

    Returns DataFrame with columns:
      domain, label,
      reg_emb_0..reg_emb_{dim-1},
      sub_emb_0..sub_emb_{dim-1}  (maxpool)
      OR sub0_emb_0.., sub1_emb_0.., sub2_emb_0..  (concat)
    """
    import pandas as pd

    model.eval()

    # Collect all unique labels to embed in one pass
    unique_labels: set[str] = set()
    parsed_domains: list[tuple[str, str, list[str]]] = []  # (domain, reg_label, sub_labels)

    for domain in domains:
        ext = tldextract.extract(domain)
        reg_label = ext.domain or ""
        sub_labels = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []

        parsed_domains.append((domain, reg_label, sub_labels))
        if reg_label:
            unique_labels.add(reg_label)
        for s in sub_labels:
            unique_labels.add(s)

    # Batch-embed all unique labels
    unique_list = sorted(unique_labels)
    print(f"  Embedding {len(unique_list):,} unique labels ...")
    if unique_list:
        emb_matrix = extract_label_embedding(model, unique_list, device, batch_size)
        label_to_emb = {lbl: emb_matrix[i] for i, lbl in enumerate(unique_list)}
    else:
        label_to_emb = {}

    zero_emb = np.zeros(embedding_dim, dtype=np.float32)

    # Build per-domain embeddings
    records: list[dict] = []
    reg_cols = [f"reg_emb_{i}" for i in range(embedding_dim)]

    for idx, (domain, reg_label, sub_labels) in enumerate(parsed_domains):
        if (idx + 1) % 100_000 == 0:
            print(f"    {idx + 1:,} / {len(parsed_domains):,} ...")

        record: dict = {"domain": domain, "label": labels[idx]}

        # Registrable embedding
        reg_emb = label_to_emb.get(reg_label, zero_emb)
        for i, col in enumerate(reg_cols):
            record[col] = float(reg_emb[i])

        # Subdomain embedding(s)
        if variant == "maxpool":
            if sub_labels:
                sub_embs = np.array([label_to_emb.get(s, zero_emb) for s in sub_labels])
                pooled = sub_embs.max(axis=0)
            else:
                pooled = zero_emb
            for i in range(embedding_dim):
                record[f"sub_emb_{i}"] = float(pooled[i])
        else:
            for slot in range(max_slots):
                if slot < len(sub_labels):
                    emb = label_to_emb.get(sub_labels[slot], zero_emb)
                else:
                    emb = zero_emb
                for i in range(embedding_dim):
                    record[f"sub{slot}_emb_{i}"] = float(emb[i])

        records.append(record)

    return pd.DataFrame(records)


def main():
    parser = argparse.ArgumentParser(description="Train label-level CNN for domain classification")
    parser.add_argument("--dataset", type=str, default=str(DATA_DIR / "dataset.parquet"))
    parser.add_argument("--output", type=str, help="Output directory")
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--embedding-dim", type=int, default=32)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--variant", choices=["maxpool", "concat"], default="maxpool",
                        help="Subdomain embedding aggregation: maxpool or concat")
    parser.add_argument("--max-subdomain-slots", type=int, default=3,
                        help="Max subdomain slots for concat variant")
    parser.add_argument("--extract", action="store_true",
                        help="Also extract split embeddings for all domains")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}. Run build_dataset.py first.")
        raise SystemExit(1)

    # Output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = MODELS_DIR / f"cnn_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Device
    device = torch.device("mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # Load data
    print(f"Loading dataset from {dataset_path} ...")
    domains, domain_labels = load_dataset(dataset_path)
    print(f"  Total: {len(domains):,} ({sum(domain_labels):,} malicious, {len(domain_labels) - sum(domain_labels):,} benign)")

    # Prepare label-level dataset
    print("\nPreparing label-level dataset ...")
    label_texts, label_ys = prepare_label_dataset(domains, domain_labels)

    # Split
    full_dataset = LabelDataset(label_texts, label_ys)
    val_size = int(len(full_dataset) * args.test_size)
    train_size = len(full_dataset) - val_size
    train_dataset, val_dataset = random_split(full_dataset, [train_size, val_size],
                                               generator=torch.Generator().manual_seed(42))

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size, shuffle=False, num_workers=0)

    print(f"  Train: {train_size:,}  |  Val: {val_size:,}")

    # Model
    model = LabelCNN(embedding_dim=args.embedding_dim).to(device)
    param_count = sum(p.numel() for p in model.parameters())
    print(f"  Model parameters: {param_count:,}")

    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)

    # Train
    print(f"\nTraining for {args.epochs} epochs ...")
    start = time.monotonic()
    best_auc = 0.0
    best_epoch = 0

    for epoch in range(args.epochs):
        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, val_auc, _, _ = evaluate(model, val_loader, device)
        scheduler.step(val_loss)

        marker = ""
        if val_auc > best_auc:
            best_auc = val_auc
            best_epoch = epoch + 1
            torch.save(model.state_dict(), output_dir / "best_model.pt")
            marker = " *"

        print(f"  Epoch {epoch+1:2d}/{args.epochs}  train_loss={train_loss:.4f}  train_acc={train_acc:.4f}  "
              f"val_loss={val_loss:.4f}  val_auc={val_auc:.4f}{marker}")

    training_time = time.monotonic() - start
    print(f"\nBest AUC: {best_auc:.4f} at epoch {best_epoch}")
    print(f"Training time: {training_time:.1f}s")

    # Load best model
    model.load_state_dict(torch.load(output_dir / "best_model.pt", weights_only=True))

    # Final evaluation
    val_loss, val_auc, val_probs, val_labels_arr = evaluate(model, val_loader, device)
    val_preds = (val_probs >= 0.5).astype(int)
    print(f"\nFinal validation:")
    print(f"  AUC: {val_auc:.4f}")
    print(classification_report(val_labels_arr, val_preds, target_names=["benign", "malicious"]))

    # Export ONNX
    model_cpu = model.to("cpu")
    onnx_path = export_onnx(model_cpu, args.embedding_dim, output_dir)

    # Save metadata
    metadata = {
        "version": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_name": "label_chars",
        "variant": args.variant,
        "max_subdomain_slots": args.max_subdomain_slots,
        "max_len": MAX_LEN,
        "vocab_size": VOCAB_SIZE,
        "char_to_idx": CHAR_TO_IDX,
        "embedding_dim": args.embedding_dim,
        "epochs": args.epochs,
        "best_epoch": best_epoch,
        "best_auc": best_auc,
        "training_time_seconds": training_time,
        "total_labels": len(label_texts),
        "total_domains": len(domains),
        "model_params": param_count,
    }
    meta_path = output_dir / "cnn_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata -> {meta_path}")

    # Extract split embeddings
    if args.extract:
        print(f"\nExtracting split embeddings ({args.variant}) for {len(domains):,} domains ...")
        emb_df = extract_split_embeddings(
            model_cpu, domains, domain_labels,
            device=torch.device("cpu"),
            embedding_dim=args.embedding_dim,
            variant=args.variant,
            max_slots=args.max_subdomain_slots,
        )
        emb_path = output_dir / "embeddings.parquet"
        emb_df.to_parquet(emb_path, index=False)
        n_emb_cols = len([c for c in emb_df.columns if c.endswith("emb_0")])
        print(f"  Embeddings -> {emb_path} ({len(emb_df):,} domains, {n_emb_cols} embedding groups)")

    print(f"\n{'='*50}")
    print(f"Label CNN training complete!")
    print(f"  Output:     {output_dir}")
    print(f"  AUC:        {best_auc:.4f}")
    print(f"  Variant:    {args.variant}")
    print(f"  Embedding:  {args.embedding_dim}-dim per label")
    print(f"  ONNX:       {onnx_path.name}")
    if not args.extract:
        print(f"\nNext: run with --extract to generate embeddings for LightGBM training")


if __name__ == "__main__":
    main()
