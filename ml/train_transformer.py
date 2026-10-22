"""Fine-tune pre-trained transformer models for domain classification.

Compares three approaches:
  A) URLBert-tiny (3.7M, URL-specific pre-training)
  B) DistilBERT (66M, general world knowledge)
  C) DomURLs_BERT (100M, domain+URL pre-training)

Usage:
    uv run python train_transformer.py --model urlbert-tiny
    uv run python train_transformer.py --model distilbert
    uv run python train_transformer.py --model domurls-bert
    uv run python train_transformer.py --model all  # run all three
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"

MODEL_CONFIGS: dict[str, dict] = {
    "urlbert-tiny": {
        "hf_name": "CrabInHoney/urlbert-tiny-base-v3",
        "max_len": 64,  # pre-trained with max_len=64
        "batch_size": 256,
        "lr": 2e-5,
        "epochs": 3,
        "description": "URL-specific pre-training (3.7M params)",
    },
    "distilbert": {
        "hf_name": "distilbert-base-uncased",
        "max_len": 128,
        "batch_size": 64,
        "lr": 2e-5,
        "epochs": 3,
        "description": "General world knowledge (66M params)",
    },
    "minilm": {
        "hf_name": "microsoft/MiniLM-L12-H384-uncased",
        "max_len": 128,
        "batch_size": 128,
        "lr": 3e-5,
        "epochs": 3,
        "description": "Distilled knowledge, compact (33M params)",
    },
    "domurls-bert": {
        "hf_name": "amahdaouy/DomURLs_BERT",
        "max_len": 128,
        "batch_size": 64,
        "lr": 2e-5,
        "epochs": 3,
        "description": "Domain+URL pre-training (100M params)",
    },
    "deberta-v3-small": {
        "hf_name": "microsoft/deberta-v3-small",
        "max_len": 128,
        "batch_size": 64,
        "lr": 1e-5,  # lower LR for DeBERTa stability
        "epochs": 3,
        "description": "Disentangled attention, 128K vocab (141M params)",
    },
}

# FP domains from real traffic — the critical test
FP_TEST_DOMAINS = [
    ("mobile.events.data.microsoft.com", 0),  # benign
    ("calendar-api.proton.me", 0),
    ("cdn.discordapp.com", 0),
    ("www.akamai.com", 0),
    ("firebaselogging-pa.googleapis.com", 0),
    ("alive.github.com", 0),
    ("raw.githubusercontent.com", 0),
    ("imap.gmail.com", 0),
    ("a37ouvkmxrnoqb-ats.iot.us-west-2.amazonaws.com", 0),
    ("98cd9fda0f5c966c153fce4484f8be3690c42508d9c8a35e544813238116c0b.us-east-1.prod.service.minerva.devices.a2z.com", 0),
]

MAL_TEST_DOMAINS = [
    ("naver-login-verify.evil.xyz", 1),  # malicious
    ("xpsiowkeoryxl.com", 1),
    ("bancewallet.com", 1),
    ("kb-secure-banking.top", 1),
    ("apple.appleidil.com", 1),
]


class DomainDataset(Dataset):
    def __init__(self, domains: list[str], labels: list[int], tokenizer: AutoTokenizer, max_len: int) -> None:
        self.domains = domains
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.domains)

    def __getitem__(self, idx: int) -> dict:
        encoding = self.tokenizer(
            self.domains[idx],
            max_length=self.max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def check_tokenizer(tokenizer: AutoTokenizer, model_name: str) -> None:
    """Show how the tokenizer handles our FP domains."""
    print(f"\n  Tokenizer check ({model_name}):")
    test_domains = [
        "calendar-api.proton.me",
        "a2z.com",
        "mobile.events.data.microsoft.com",
        "xpsiowkeoryxl.com",
    ]
    for d in test_domains:
        tokens = tokenizer.tokenize(d)
        print(f"    {d:<45} → {tokens}")


def train_and_evaluate(
    model_key: str,
    config: dict,
    train_domains: list[str],
    train_labels: list[int],
    val_domains: list[str],
    val_labels: list[int],
) -> dict:
    """Fine-tune a transformer model and evaluate."""
    print(f"\n{'='*60}")
    print(f"Model: {model_key} — {config['description']}")
    print(f"{'='*60}")

    # DeBERTa-v3 has NaN issues on MPS — force CPU for stability
    if "deberta" in config["hf_name"].lower():
        device = torch.device("cpu")
    else:
        device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"  Device: {device}")

    # Load tokenizer + model
    print(f"  Loading {config['hf_name']} ...")
    tokenizer = AutoTokenizer.from_pretrained(config["hf_name"])
    model = AutoModelForSequenceClassification.from_pretrained(
        config["hf_name"], num_labels=2,
    ).to(device)

    param_count = sum(p.numel() for p in model.parameters())
    print(f"  Parameters: {param_count:,}")

    # Check tokenizer
    check_tokenizer(tokenizer, model_key)

    # Create datasets
    train_ds = DomainDataset(train_domains, train_labels, tokenizer, config["max_len"])
    val_ds = DomainDataset(val_domains, val_labels, tokenizer, config["max_len"])

    train_loader = DataLoader(train_ds, batch_size=config["batch_size"], shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=config["batch_size"])

    # Optimizer + scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=config["lr"], weight_decay=0.01)
    total_steps = len(train_loader) * config["epochs"]
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps,
    )

    # Training loop
    start = time.monotonic()
    best_auc = 0.0
    best_state = None

    for epoch in range(config["epochs"]):
        model.train()
        total_loss = 0.0
        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            total_loss += loss.item()

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            if (batch_idx + 1) % 100 == 0:
                print(f"    Epoch {epoch+1} batch {batch_idx+1}/{len(train_loader)} loss={loss.item():.4f}")

        avg_loss = total_loss / len(train_loader)

        # Validation
        model.eval()
        all_probs = []
        all_labels = []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)

                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                probs = torch.softmax(outputs.logits, dim=1)[:, 1].cpu().numpy()
                all_probs.extend(probs)
                all_labels.extend(batch["labels"].numpy())

        auc = roc_auc_score(all_labels, all_probs)
        print(f"  Epoch {epoch+1}/{config['epochs']}  loss={avg_loss:.4f}  val_auc={auc:.4f}")

        if auc > best_auc:
            best_auc = auc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    training_time = time.monotonic() - start
    print(f"\n  Best AUC: {best_auc:.4f} ({training_time:.0f}s)")

    # Load best model
    if best_state:
        model.load_state_dict(best_state)
    model.to(device)

    # Final evaluation
    model.eval()
    all_probs = []
    all_labels = []
    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=1)[:, 1].cpu().numpy()
            all_probs.extend(probs)
            all_labels.extend(batch["labels"].numpy())

    y_pred = [1 if p >= 0.9 else 0 for p in all_probs]
    print(f"\n  Classification report (threshold=0.9):")
    print(classification_report(all_labels, y_pred, target_names=["benign", "malicious"]))

    # FP test — the critical check
    print(f"  FP domain test (should be <0.5):")
    for domain, expected_label in FP_TEST_DOMAINS:
        enc = tokenizer(domain, max_length=config["max_len"], padding="max_length",
                       truncation=True, return_tensors="pt")
        with torch.no_grad():
            out = model(input_ids=enc["input_ids"].to(device),
                       attention_mask=enc["attention_mask"].to(device))
            prob = torch.softmax(out.logits, dim=1)[0, 1].item()
        status = "✓" if prob < 0.5 else "✗ FP!"
        print(f"    {prob:.4f}  {status}  {domain[:60]}")

    print(f"\n  Malicious domain test (should be >0.9):")
    for domain, expected_label in MAL_TEST_DOMAINS:
        enc = tokenizer(domain, max_length=config["max_len"], padding="max_length",
                       truncation=True, return_tensors="pt")
        with torch.no_grad():
            out = model(input_ids=enc["input_ids"].to(device),
                       attention_mask=enc["attention_mask"].to(device))
            prob = torch.softmax(out.logits, dim=1)[0, 1].item()
        status = "✓" if prob > 0.9 else "✗ FN!"
        print(f"    {prob:.4f}  {status}  {domain[:60]}")

    # Save
    output_dir = MODELS_DIR / f"transformer_{model_key}"
    output_dir.mkdir(parents=True, exist_ok=True)
    model.cpu().save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"\n  Saved → {output_dir}")

    return {
        "model": model_key,
        "params": param_count,
        "best_auc": best_auc,
        "training_time": training_time,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune transformers for domain classification")
    parser.add_argument("--model", type=str, default="urlbert-tiny",
                       choices=list(MODEL_CONFIGS.keys()) + ["all"],
                       help="Which model to fine-tune")
    parser.add_argument("--dataset", type=str, default=str(DATA_DIR / "dataset.parquet"))
    parser.add_argument("--sample", type=int, default=500000,
                       help="Max samples per class for training (default: 500K)")
    args = parser.parse_args()

    # Load dataset
    print("Loading dataset ...")
    ds = pd.read_parquet(args.dataset)
    print(f"  Total: {len(ds):,}")

    # Sample balanced dataset
    mal = ds[ds["label"] == 1]["domain"].tolist()
    ben = ds[ds["label"] == 0]["domain"].tolist()

    import random
    random.seed(42)
    mal_sample = random.sample(mal, min(args.sample, len(mal)))
    ben_sample = random.sample(ben, min(args.sample, len(ben)))

    all_domains = mal_sample + ben_sample
    all_labels = [1] * len(mal_sample) + [0] * len(ben_sample)
    print(f"  Sampled: {len(mal_sample):,} malicious + {len(ben_sample):,} benign")

    # Split
    train_domains, val_domains, train_labels, val_labels = train_test_split(
        all_domains, all_labels, test_size=0.1, random_state=42, stratify=all_labels,
    )
    print(f"  Train: {len(train_domains):,}  Val: {len(val_domains):,}")

    # Run experiments
    models_to_run = list(MODEL_CONFIGS.keys()) if args.model == "all" else [args.model]
    results = []

    for model_key in models_to_run:
        config = MODEL_CONFIGS[model_key]
        result = train_and_evaluate(
            model_key, config, train_domains, train_labels, val_domains, val_labels,
        )
        results.append(result)

    # Summary
    if len(results) > 1:
        print(f"\n{'='*60}")
        print("COMPARISON")
        print(f"{'='*60}")
        print(f"{'Model':<20} {'Params':>10} {'AUC':>8} {'Time':>8}")
        for r in results:
            print(f"{r['model']:<20} {r['params']:>10,} {r['best_auc']:>8.4f} {r['training_time']:>7.0f}s")


if __name__ == "__main__":
    main()
