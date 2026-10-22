# Transformer Experiments — Status & Plan

## What we tested locally (2026-03-20)

| Model | Params | Device | AUC | FP test | Status |
|-------|--------|--------|-----|---------|--------|
| URLBert-tiny | 3.7M | MPS | 0.929 | 10/10 FP | Done — BPE fragments brands |
| MiniLM-L12 | 33M | MPS | 0.961 | 9/10 FP (microsoft.com 0.64) | Done — world knowledge helps marginally |
| DeBERTa-v3-small | 141M | MPS | NaN | — | **Failed — MPS incompatible** |
| DeBERTa-v3-small | 141M | CPU | — | — | Killed — too slow (~4-6 hours) |

## Key findings

### 1. Tokenizer comparison matters
- URLBert-tiny BPE: `microsoft` → `m##ic##ro##so##f##t` (6 pieces) — no semantic understanding
- BERT/MiniLM/DeBERTa WordPiece: `microsoft` → `microsoft` (1 token) — knows brands
- **Winner: Standard BERT WordPiece or DeBERTa SentencePiece (128K vocab)**

### 2. Architecture is NOT the bottleneck
MiniLM with proper tokenizer (knows `microsoft`, `proton`, `calendar` as single tokens) still flags `calendar-api.proton.me` at 0.997. The model learns "subdomain = suspicious" from training data regardless of architecture.

### 3. Training data distribution IS the bottleneck
Our dataset: benign = short clean domains, malicious = subdomains on platforms. ANY model fine-tuned on this learns the wrong association.

## What to run on GPU (RunPod)

When GPU is available, run these experiments:

### Experiment 1: DeBERTa-v3-small (141M)
```bash
python train_transformer.py --model deberta-v3-small --sample 200000
```
Confirms: does disentangled attention + 128K vocab help?
Expected: likely same FP pattern as MiniLM.

### Experiment 2: DeBERTa-v3-small with traffic data augmentation
Add ClickHouse traffic domains (4.7K with subdomains) to benign training, weighted higher.
Test: does the model learn that subdomains on known parents are benign?

### Experiment 3: ModernBERT-base (149M)
```bash
# Add to train_transformer.py configs
python train_transformer.py --model modernbert --sample 200000
```
Test: does 2T token pre-training (2024 web data) provide better domain knowledge?

### Experiment 4: Pre-train on DNS data first
1. Collect all unique domains from ClickHouse + Tranco 1M + CT logs
2. MLM pre-training on domain corpus (~10M domains)
3. Then fine-tune on labeled data
Test: does domain-specific pre-training solve the subdomain FP?

## Models to still evaluate

| Model | Params | Why try | License | HuggingFace |
|-------|--------|---------|---------|-------------|
| DeBERTa-v3-small | 141M | 128K vocab, disentangled attention | MIT | microsoft/deberta-v3-small |
| DeBERTa-v3-base | 184M | Larger DeBERTa | MIT | microsoft/deberta-v3-base |
| ModernBERT-base | 149M | RoPE, 2T tokens, 2024 data | Apache 2.0 | answerdotai/ModernBERT-base |
| DomURLs_BERT | ~100M | Domain-specific pre-training | unclear | amahdaouy/DomURLs_BERT |

## Parallel path: Scoring chain

Regardless of transformer results, a scoring chain (ML pattern + knowledge layer) is needed.
The chain approach works with ANY model (CNN, LightGBM, or transformer).
See scoring chain design in separate doc.
