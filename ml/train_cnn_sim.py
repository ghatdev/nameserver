"""Train the contrastive char-level label embedder (Stage 2c).

Replaces the `pg_trgm + levenshtein` tier-2 lookup in
`crates/nameserver-control/src/similarity.rs` with a single HNSW ANN
call against a contrastive embedding produced by this CNN.

This is a SECOND CNN, distinct from `models/detector_cnn_v1/` (which
is a BCE-trained classification CNN whose embedding clusters by class
rather than by lexical similarity).

Usage:
    uv run ml/train_cnn_sim.py
    uv run ml/train_cnn_sim.py --epochs 30 --batch-size 512
    uv run ml/train_cnn_sim.py --extract        # ONNX export from best checkpoint

Pipeline (single command does all of these):
    1. Load anchors from data/sim_anchors.parquet (run build_sim_anchors.py first)
    2. Train SimLabelCNN with InfoNCE on online perturbations
    3. After each epoch, eval on the three sim_eval_*.parquet slices
    4. Track best slice-3 recall@5; save best checkpoint
    5. Export ONNX from best checkpoint to models/detector_cnn_sim_v1/

Requires data/sim_anchors.parquet AND data/sim_eval_*.parquet to exist.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
# safetensors is the pickle-free serialization format for tensor state.
# Checkpoints round-trip via a strict tensor-only schema (no arbitrary
# code execution surface during deserialization).
from safetensors.torch import load_file as safetensors_load
from safetensors.torch import save_file as safetensors_save

sys.path.insert(0, str(Path(__file__).parent))

import perturb  # noqa: E402

# Vocabulary identical to train_cnn.py — same encoder contract so Rust
# inference can reuse the same char-id mapping at runtime.
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(CHARS)}
VOCAB_SIZE = len(CHARS) + 1
MAX_LEN = 63
PAD_IDX = 0

ML_DIR = Path(__file__).parent
DATA_DIR = ML_DIR / "data"
MODELS_DIR = ML_DIR / "models"


def encode_label(label: str) -> list[int]:
    s = label.lower()[:MAX_LEN]
    return [CHAR_TO_IDX.get(c, 0) for c in s]


def encode_batch(labels: list[str]) -> torch.Tensor:
    out = torch.zeros(len(labels), MAX_LEN, dtype=torch.long)
    for i, lab in enumerate(labels):
        ids = encode_label(lab)
        out[i, :len(ids)] = torch.tensor(ids, dtype=torch.long)
    return out


# --- Model ---------------------------------------------------------------


class SimLabelCNN(nn.Module):
    """Contrastive char-level CNN.

    Same trunk as `train_cnn.py`'s LabelCNN — three parallel convs over
    a char embedding, max-pool each, concat — but the classifier head
    is replaced by a 64-dim embedding projection followed by L2-norm.

    Forward output is the L2-normalized embedding directly. There is
    no `get_embedding` distinction because the embedding *is* the
    output.
    """

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int = 16,
        num_filters: int = 64,
        embedding_dim: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embedding_dim = embedding_dim
        self.char_embed = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
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
        concat_dim = num_filters * 3
        self.proj = nn.Sequential(
            nn.Linear(concat_dim, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, embedding_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        e = self.char_embed(x)              # (B, L, embed_dim)
        e = e.transpose(1, 2)               # (B, embed_dim, L)
        c3 = self.conv3(e).max(dim=2).values
        c4 = self.conv4(e).max(dim=2).values
        c5 = self.conv5(e).max(dim=2).values
        h = torch.cat([c3, c4, c5], dim=1)
        emb = self.proj(h)
        return F.normalize(emb, p=2, dim=1)


# --- Loss ---------------------------------------------------------------


class InfoNCELoss(nn.Module):
    """Symmetric InfoNCE / NT-Xent loss with learnable temperature.

    Given two batches of L2-normalized embeddings (anchors and their
    positives), each row in `anchor` is positive-paired with the
    corresponding row in `positive`. Every other row in `positive`
    serves as a negative for `anchor[i]`, and vice versa.

    Temperature is learned in log-space (clamped to a sensible range)
    per the SimCLR-style recipe.
    """

    def __init__(self, init_log_temp: float = math.log(0.07)):
        super().__init__()
        self.log_temp = nn.Parameter(torch.tensor(init_log_temp, dtype=torch.float32))

    @property
    def temperature(self) -> float:
        return float(self.log_temp.detach().exp().clamp(0.01, 1.0).item())

    def forward(self, anchor: torch.Tensor, positive: torch.Tensor) -> torch.Tensor:
        temp = self.log_temp.exp().clamp(0.01, 1.0)
        logits = (anchor @ positive.T) / temp
        labels = torch.arange(anchor.size(0), device=anchor.device)
        loss_a = F.cross_entropy(logits, labels)
        loss_b = F.cross_entropy(logits.T, labels)
        return (loss_a + loss_b) / 2


# --- Dataset --------------------------------------------------------------


class ContrastiveLabelDataset(Dataset):
    """One sample = (encoded anchor, encoded online-perturbed positive).

    Each worker holds its own RNG seeded with `(epoch_seed, worker_id)`
    so positives differ across workers but are reproducible end-to-end.
    """

    def __init__(self, anchors: list[str], epoch_seed: int):
        self.anchors = anchors
        self.epoch_seed = epoch_seed

    def __len__(self) -> int:
        return len(self.anchors)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        # Per-sample RNG keeps things deterministic even with shuffle.
        rng = random.Random((self.epoch_seed * 1_000_003) ^ idx)
        anchor = self.anchors[idx]
        try:
            result = perturb.generate(anchor, rng)
            positive = result.label
        except perturb.PerturbError:
            # Pathological anchor (rare). Use a same-string copy with a
            # known-safe append so the sample isn't lost — won't add
            # signal but also won't crash training.
            positive = anchor + ("x" if anchor[-1] != "x" else "y")
        a_ids = torch.tensor(
            encode_label(anchor) + [PAD_IDX] * (MAX_LEN - len(anchor)),
            dtype=torch.long,
        )[:MAX_LEN]
        # Re-pad if anchor was longer than MAX_LEN (encode_label already truncated)
        if a_ids.size(0) < MAX_LEN:
            pad = torch.zeros(MAX_LEN - a_ids.size(0), dtype=torch.long)
            a_ids = torch.cat([a_ids, pad])
        p_ids = encode_label(positive)
        p_pad = p_ids + [PAD_IDX] * (MAX_LEN - len(p_ids))
        p_tensor = torch.tensor(p_pad[:MAX_LEN], dtype=torch.long)
        return a_ids, p_tensor


# --- Eval -----------------------------------------------------------------


@dataclass
class SliceMetrics:
    name: str
    n_queries: int
    recall_at_1: float = 0.0
    recall_at_5: float = 0.0
    recall_at_10: float = 0.0
    mrr: float = 0.0
    overlap_top5: float = 0.0  # only used by lev_replay slice

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "n_queries": self.n_queries,
            "recall@1": self.recall_at_1,
            "recall@5": self.recall_at_5,
            "recall@10": self.recall_at_10,
            "mrr": self.mrr,
            "overlap_top5": self.overlap_top5,
        }


@torch.no_grad()
def embed_strings(model: SimLabelCNN, strings: list[str], device: torch.device,
                  batch_size: int = 4096) -> np.ndarray:
    model.eval()
    out: list[np.ndarray] = []
    for i in range(0, len(strings), batch_size):
        chunk = strings[i:i + batch_size]
        x = encode_batch(chunk).to(device)
        emb = model(x).cpu().numpy()
        out.append(emb)
    return np.concatenate(out, axis=0) if out else np.zeros((0, model.embedding_dim))


def build_corpus_index(model: SimLabelCNN, corpus: list[str],
                       device: torch.device) -> tuple[np.ndarray, list[str]]:
    """Embed the entire corpus once for cosine-similarity retrieval."""
    emb = embed_strings(model, corpus, device)
    return emb, corpus


def topk_neighbors(query_emb: np.ndarray, corpus_emb: np.ndarray,
                   k: int) -> np.ndarray:
    """Cosine top-k. Both inputs assumed L2-normalized → dot product == cosine."""
    sims = query_emb @ corpus_emb.T
    # argpartition is faster than full argsort for large corpora
    if sims.shape[1] <= k:
        idx = np.argsort(-sims, axis=1)
    else:
        part = np.argpartition(-sims, kth=k - 1, axis=1)[:, :k]
        # sort the top-k partition
        sub = np.take_along_axis(sims, part, axis=1)
        order = np.argsort(-sub, axis=1)
        idx = np.take_along_axis(part, order, axis=1)
    return idx


def evaluate_slice(
    slice_df: pd.DataFrame,
    model: SimLabelCNN,
    corpus: list[str],
    corpus_emb: np.ndarray,
    device: torch.device,
    is_lev_replay: bool = False,
) -> SliceMetrics:
    """Run retrieval on a slice and compute recall@k + MRR.

    Each row of the slice has `anchor` (query) and `targets` (list of
    labels expected in the result set).
    """
    if slice_df.empty:
        return SliceMetrics(name="empty", n_queries=0)

    anchors = slice_df["anchor"].tolist()
    targets_lists = [list(t) for t in slice_df["targets"].tolist()]

    a_emb = embed_strings(model, anchors, device)
    idx = topk_neighbors(a_emb, corpus_emb, k=10)

    n = len(anchors)
    hits1 = hits5 = hits10 = 0
    mrr_sum = 0.0
    overlap_sum = 0.0

    for q_i, targets in enumerate(targets_lists):
        # Get the predicted top-10 strings, masking the query itself.
        top_strings: list[str] = []
        for cand_i in idx[q_i]:
            cand = corpus[cand_i]
            if cand == anchors[q_i]:
                continue
            top_strings.append(cand)
            if len(top_strings) >= 10:
                break

        top1 = set(top_strings[:1])
        top5 = set(top_strings[:5])
        top10 = set(top_strings[:10])

        target_set = set(targets)
        if target_set & top1:
            hits1 += 1
        if target_set & top5:
            hits5 += 1
        if target_set & top10:
            hits10 += 1

        # MRR — first index where any target appears
        rr = 0.0
        for rank, s in enumerate(top_strings, start=1):
            if s in target_set:
                rr = 1.0 / rank
                break
        mrr_sum += rr

        # Lev-replay-specific overlap metric (top-5 of model vs top-5
        # from production levenshtein, the slice's `targets` list).
        if is_lev_replay:
            lev_top5 = set(targets[:5])
            if lev_top5:
                overlap_sum += len(top5 & lev_top5) / len(lev_top5)

    return SliceMetrics(
        name=str(slice_df["slice"].iloc[0]),
        n_queries=n,
        recall_at_1=hits1 / n,
        recall_at_5=hits5 / n,
        recall_at_10=hits10 / n,
        mrr=mrr_sum / n,
        overlap_top5=overlap_sum / n if is_lev_replay else 0.0,
    )


# --- ONNX export ----------------------------------------------------------


def export_onnx(model: SimLabelCNN, out_dir: Path) -> Path:
    # ONNX export traces the model — keep both model and dummy input on
    # CPU so the ONNX graph is portable and trace doesn't fail on MPS
    # placeholder storage allocation. The exported ONNX is device-
    # agnostic anyway (Rust inference uses ort on CPU).
    model = model.to("cpu")
    model.eval()
    onnx_path = out_dir / "cnn_sim_embedding.onnx"
    dummy = torch.zeros(1, MAX_LEN, dtype=torch.long)
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["label_chars"],
        output_names=["embedding"],
        dynamic_axes={
            "label_chars": {0: "batch_size"},
            "embedding": {0: "batch_size"},
        },
        opset_version=17,
        dynamo=False,
    )
    # Verify shape contract.
    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    test_in = np.zeros((2, MAX_LEN), dtype=np.int64)
    out = sess.run(None, {"label_chars": test_in})
    assert out[0].shape == (2, model.embedding_dim), (
        f"ONNX output shape mismatch: expected (2, {model.embedding_dim}), "
        f"got {out[0].shape}"
    )
    print(f"  ONNX -> {onnx_path} ({onnx_path.stat().st_size / 1024:.1f} KB)")
    return onnx_path


# --- Training loop --------------------------------------------------------


@dataclass
class TrainConfig:
    epochs: int = 30
    batch_size: int = 512
    lr: float = 1e-3
    weight_decay: float = 1e-4
    warmup_steps: int = 500
    embedding_dim: int = 64
    seed: int = 42
    num_workers: int = 4
    early_stop_patience: int = 5
    eval_corpus_max: int = 50_000  # cap for in-RAM cosine eval
    init_log_temp: float = math.log(0.07)


@dataclass
class EpochReport:
    epoch: int
    train_loss: float
    temperature: float
    elapsed_s: float
    slices: dict[str, dict[str, object]] = field(default_factory=dict)


def cosine_warmup_lr(step: int, total_steps: int, warmup_steps: int,
                     base_lr: float) -> float:
    if step < warmup_steps:
        return base_lr * (step + 1) / warmup_steps
    progress = (step - warmup_steps) / max(1, total_steps - warmup_steps)
    return base_lr * 0.5 * (1.0 + math.cos(math.pi * progress))


def train_loop(
    anchors: list[str],
    eval_slices: dict[str, pd.DataFrame],
    eval_corpus: list[str],
    cfg: TrainConfig,
    out_dir: Path,
) -> tuple[SimLabelCNN, list[EpochReport]]:
    device = torch.device("cuda" if torch.cuda.is_available()
                          else "mps" if torch.backends.mps.is_available()
                          else "cpu")
    print(f"[device] {device}", flush=True)

    model = SimLabelCNN(embedding_dim=cfg.embedding_dim).to(device)
    loss_fn = InfoNCELoss(init_log_temp=cfg.init_log_temp).to(device)
    optimizer = torch.optim.AdamW(
        list(model.parameters()) + list(loss_fn.parameters()),
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )

    steps_per_epoch = math.ceil(len(anchors) / cfg.batch_size)
    total_steps = steps_per_epoch * cfg.epochs

    reports: list[EpochReport] = []
    best_score = -1.0
    best_state: dict[str, torch.Tensor] | None = None
    best_epoch = 0
    best_path = out_dir / "best_model.safetensors"
    best_meta_path = out_dir / "best_model.meta.json"
    no_improve = 0

    global_step = 0
    for epoch in range(1, cfg.epochs + 1):
        ds = ContrastiveLabelDataset(anchors, epoch_seed=cfg.seed * 100 + epoch)
        loader = DataLoader(
            ds,
            batch_size=cfg.batch_size,
            shuffle=True,
            num_workers=cfg.num_workers,
            drop_last=True,
            persistent_workers=cfg.num_workers > 0,
            pin_memory=torch.cuda.is_available(),
        )

        model.train()
        loss_fn.train()
        t0 = time.time()
        loss_sum = 0.0
        n_batches = 0

        for anchor_ids, positive_ids in loader:
            anchor_ids = anchor_ids.to(device, non_blocking=True)
            positive_ids = positive_ids.to(device, non_blocking=True)

            lr = cosine_warmup_lr(global_step, total_steps,
                                  cfg.warmup_steps, cfg.lr)
            for pg in optimizer.param_groups:
                pg["lr"] = lr

            anchor_emb = model(anchor_ids)
            positive_emb = model(positive_ids)
            loss = loss_fn(anchor_emb, positive_emb)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            loss_sum += loss.item()
            n_batches += 1
            global_step += 1

        train_loss = loss_sum / max(1, n_batches)
        elapsed = time.time() - t0

        # --- Eval at end of epoch ----------------------------------------
        model.eval()
        loss_fn.eval()
        # Build the eval corpus once per epoch (the only thing that
        # changes is the model's embeddings; the corpus strings are fixed).
        corpus_emb = embed_strings(model, eval_corpus, device)

        slice_results: dict[str, SliceMetrics] = {}
        for slice_name, slice_df in eval_slices.items():
            metrics = evaluate_slice(
                slice_df, model, eval_corpus, corpus_emb, device,
                is_lev_replay=(slice_name == "lev_replay"),
            )
            slice_results[slice_name] = metrics

        report = EpochReport(
            epoch=epoch,
            train_loss=train_loss,
            temperature=loss_fn.temperature,
            elapsed_s=elapsed,
            slices={k: v.to_dict() for k, v in slice_results.items()},
        )
        reports.append(report)

        # Headline log line — slice-3 recall@5 is the load-bearing metric
        s3 = slice_results.get("pg_trgm_miss")
        s3_r5 = s3.recall_at_5 if s3 else 0.0
        s1 = slice_results.get("synthetic")
        s1_r5 = s1.recall_at_5 if s1 else 0.0
        s2 = slice_results.get("lev_replay")
        s2_overlap = s2.overlap_top5 if s2 else 0.0
        print(
            f"[epoch {epoch:>2}/{cfg.epochs}] "
            f"loss={train_loss:.4f} τ={loss_fn.temperature:.4f} "
            f"slice1.R@5={s1_r5:.3f} "
            f"slice2.overlap={s2_overlap:.3f} "
            f"slice3.R@5={s3_r5:.3f} "
            f"({elapsed:.0f}s)",
            flush=True,
        )

        # Track best by slice-3 recall@5. Best state stays in RAM via
        # deepcopy — no disk round-trip during training, so no pickle
        # surface in the inner loop.
        if s3_r5 > best_score:
            best_score = s3_r5
            best_state = copy.deepcopy(model.state_dict())
            best_epoch = epoch
            no_improve = 0
            print(f"  [best] slice3.R@5 improved to {best_score:.3f} (epoch {epoch})",
                  flush=True)
        else:
            no_improve += 1
            if no_improve >= cfg.early_stop_patience:
                print(f"[early-stop] {no_improve} epochs without improvement",
                      flush=True)
                break

    # Persist the best state to disk via safetensors (pickle-free).
    if best_state is not None:
        safetensors_save(best_state, str(best_path))
        best_meta_path.write_text(json.dumps({
            "epoch": best_epoch,
            "score": best_score,
            "embedding_dim": cfg.embedding_dim,
        }, indent=2))
        # Restore best weights into `model` for ONNX export.
        model.load_state_dict(best_state)
        print(f"[best] saved -> {best_path} (epoch {best_epoch}, "
              f"slice3.R@5={best_score:.3f})", flush=True)

    return model, reports


# --- CLI ------------------------------------------------------------------


def load_eval_slices() -> tuple[dict[str, pd.DataFrame], list[str]]:
    """Load the three eval slices and assemble a corpus.

    Corpus = union of all positive-target labels across slices + the
    val anchors. The corpus is what ANN searches against; everything we
    expect to retrieve must be in it.
    """
    paths = {
        "synthetic": DATA_DIR / "sim_eval_synthetic.parquet",
        "lev_replay": DATA_DIR / "sim_eval_levenshtein_replay.parquet",
        "pg_trgm_miss": DATA_DIR / "sim_eval_pg_trgm_misses.parquet",
    }
    slices: dict[str, pd.DataFrame] = {}
    for name, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(
                f"missing eval slice {path} — run build_sim_eval.py first"
            )
        slices[name] = pd.read_parquet(path)

    corpus_set: set[str] = set()
    for df in slices.values():
        for targets in df["targets"]:
            for t in targets:
                corpus_set.add(t)
    return slices, sorted(corpus_set)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--anchors", type=Path, default=DATA_DIR / "sim_anchors.parquet",
    )
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--embedding-dim", type=int, default=64)
    parser.add_argument("--num-workers", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--out-dir", type=Path,
        default=MODELS_DIR / "detector_cnn_sim_v1",
    )
    parser.add_argument(
        "--extract", action="store_true",
        help="Skip training, just export ONNX from existing best_model.pt",
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    print(f"[anchors] loading {args.anchors}", flush=True)
    if not args.anchors.exists():
        print(f"[err] anchors not found — run build_sim_anchors.py first",
              flush=True, file=sys.stderr)
        return 1
    anchors_df = pd.read_parquet(args.anchors)
    train_anchors = anchors_df.loc[
        anchors_df["bucket"] == "train", "label"
    ].tolist()
    if not train_anchors:
        print("[err] no train-bucket anchors", flush=True, file=sys.stderr)
        return 1
    print(f"[anchors] {len(train_anchors):,} train anchors", flush=True)

    eval_slices, eval_corpus = load_eval_slices()
    print(f"[eval] slices: " +
          ", ".join(f"{k}={len(v):,}" for k, v in eval_slices.items()),
          flush=True)
    print(f"[eval] corpus size: {len(eval_corpus):,}", flush=True)

    cfg = TrainConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        embedding_dim=args.embedding_dim,
        num_workers=args.num_workers,
        seed=args.seed,
    )

    if args.extract:
        ck_path = args.out_dir / "best_model.safetensors"
        if not ck_path.exists():
            print(f"[err] no checkpoint at {ck_path}",
                  flush=True, file=sys.stderr)
            return 1
        device = torch.device(
            "cuda" if torch.cuda.is_available()
            else "mps" if torch.backends.mps.is_available()
            else "cpu"
        )
        model = SimLabelCNN(embedding_dim=args.embedding_dim).to(device)
        # safetensors loader: tensor-only schema, no pickle, no RCE.
        state = safetensors_load(str(ck_path), device=str(device))
        model.load_state_dict(state)
        export_onnx(model, args.out_dir)
        return 0

    model, reports = train_loop(
        train_anchors, eval_slices, eval_corpus, cfg, args.out_dir,
    )

    # ONNX export from best checkpoint
    onnx_path = export_onnx(model, args.out_dir)

    # Persist metadata
    final_report = reports[-1] if reports else None
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vocab_size": VOCAB_SIZE,
        "max_len": MAX_LEN,
        "chars": CHARS,
        "embedding_dim": args.embedding_dim,
        "training": {
            "epochs_run": len(reports),
            "batch_size": cfg.batch_size,
            "lr": cfg.lr,
            "seed": cfg.seed,
        },
        "epoch_reports": [
            {
                "epoch": r.epoch,
                "train_loss": r.train_loss,
                "temperature": r.temperature,
                "elapsed_s": r.elapsed_s,
                "slices": r.slices,
            }
            for r in reports
        ],
        "onnx_path": str(onnx_path),
    }
    meta_path = args.out_dir / "sim_metadata.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"[meta] -> {meta_path}", flush=True)

    if final_report and "pg_trgm_miss" in final_report.slices:
        final_score = final_report.slices["pg_trgm_miss"]["recall@5"]
        print(f"\n[final] best slice3.R@5 across run: see best_model.pt", flush=True)
        print(f"[final] last epoch slice3.R@5: {final_score}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
