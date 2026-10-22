# ML Research Log

## 2026-03-19: Pipeline Audit & Data Expansion

### Finding: features.py disconnected from dataset.csv

**Problem:** `features.py` was reading legacy `malicious_domains.csv` (183K, phishing+malware only), NOT `dataset.csv` (738K). Result: 337K DGA and 53K C2 domains had zero structured features in LightGBM training. CNN was trained on the full dataset correctly, but LightGBM was trained on incomplete data.

**Fix:** Rewrote `features.py` to read from `dataset.parquet` as single source of truth.

### Finding: Per-category evaluation reveals model weaknesses

Ran `evaluate_categories.py` on the old 738K dataset (before expansion):

| Category | N (val) | Recall @0.9 |
|----------|---------|-------------|
| DGA | 67,432 | 92.7% |
| malware | 707 | 90.7% |
| phishing | 35,959 | 80.6% |
| C2 | 10,701 | 80.0% |
| Benign FP | - | 0.79% |

SHAP analysis: all top 15 features are CNN embeddings + Group B. Group A lexical features barely register. Model is riding entirely on CNN.

### Decision: Two-dataset architecture

CNN and LightGBM have different data requirements.

- **CNN dataset:** Big. All feeds, old data. Only needs domain + label. Currently 2.5M.
- **LightGBM dataset:** Small (~200K), curated. Needs real Group B features. Quality > quantity.

**Why:** CNN learns character patterns (more data = better). LightGBM learns feature interactions (clean data = better, saturates at ~100-200K).

### Data expansion: 738K to 2.5M

| Source | Before | After | Type |
|--------|--------|-------|------|
| Tranco | 70K | 689K | benign |
| Majestic | 91K | 874K | benign |
| JPCERTCC (NEW) | 0 | 244K | phishing (APAC, 2019-2025) |
| PhiUSIIL (NEW) | 0 | 135K | phishing (academic) |
| blackbook (NEW) | 0 | 18K | malware (historical) |
| Phishing.Database | 155K | 155K | phishing (changed to ALL historical, pending rebuild) |
| Others | same | same | - |

**Ratio:** 1.57M benign (61.7%) : 970K malicious (38.3%) = 1.6:1. Acceptable for CNN.

### CNN training on 2.5M

| Metric | 738K dataset | 2.5M dataset |
|--------|-------------|--------------|
| AUC | 0.981 | 0.974 |
| Benign precision | 0.86 | 0.93 |
| Malicious recall | 0.96 | 0.87 |
| Training time | 526s | 2008s |

AUC slightly lower — expected with 3.4x more diverse data (especially benign). Benign precision improved significantly (0.86 → 0.93) which matters more for a DNS resolver (FP > FN).

### Format migration: CSV to Parquet

All pipeline scripts migrated from CSV to Parquet:
- `dataset.parquet`: 29MB → 12MB (2.5x smaller)
- `features.parquet`: 92MB → 19MB (4.8x smaller)
- `embeddings.parquet`: 219MB → 116MB (1.9x smaller)

Benefits: typed columns, null-aware, compressed, fast pandas I/O.

### Group B coverage analysis

Checked which domains in the 2.5M dataset have infrastructure features:

| Category | Has Group B | Total | Coverage |
|----------|------------|-------|----------|
| traffic | 2,867 | 2,867 | 100% |
| phishing | 97,850 | 557,668 | 17.5% |
| tranco | 70,514 | 689,044 | 10.2% |
| malware | 1,900 | 21,669 | 8.8% |
| majestic | 29,320 | 874,280 | 3.4% |
| c2 | 82 | 53,448 | 0.2% |
| **dga** | **0** | **337,277** | **0.0%** |

Total with Group B: 202K — close to the 200K target for LightGBM.

### Decision: DGA domains and NXDOMAIN

**Insight:** DGA domains that don't resolve (NXDOMAIN) are NOT active threats. The DNS resolver already returns NXDOMAIN — no blocking needed. The real threat is DGA domains that DO resolve (active C2 server).

**Implication for training:**
- Don't train LightGBM on NXDOMAIN DGA as "malicious" — that teaches the wrong signal
- Only use DGA/C2 domains that actually resolved — the rare dangerous ones
- The detection pattern: CNN says "DGA-like" + domain resolves to IP + suspicious infra = MAL
- CNN embedding already encodes the DGA character pattern; LightGBM adds the "is it alive?" signal

**Decision:** Build LightGBM dataset from the 202K domains that have real Group B data. Don't artificially resolve dead DGA domains.

### Next: Build curated LightGBM dataset

Use the 202K domains with Group B coverage:
- ~103K benign (tranco + majestic + traffic)
- ~98K phishing (from resolved_malicious.csv)
- ~2K malware
- ~82 C2
- DGA coverage comes from CNN embeddings — any domain with DGA-like embedding + resolves = candidate

---

### Experiment: Curated LightGBM dataset (202K with real Group B)

Built `lgb_features.parquet`: only domains with real Group B data (resolution cache + traffic + SQLite). No NaN — filled with explicit values (avg_ttl=0 for missing TTL, ip_country="unknown", etc.).

**Composition:** 102K benign, 98K phishing, 2K malware, 82 C2, 0 DGA.

**Results vs previous (full 738K dataset with NaN Group B):**

| Metric | Full 738K | Curated 202K | Change |
|--------|-----------|-------------|--------|
| AUC | 0.990 | 0.987 | -0.003 |
| Phishing recall @0.9 | 80.6% | 84.2% | **+3.6%** |
| Malware recall @0.9 | 90.7% | 89.7% | -1.0% |
| Benign FP rate | 0.79% | 0.65% | **-0.14%** |
| Traffic FP rate | 7.9% | 6.8% | **-1.1%** |

**SHAP improvement:** Group A features now visible in top 15 (digit_count, tld, label_length). Previously all top 15 were CNN embeddings. Real Group B data lets the model learn feature interactions.

**Observation:** No DGA in LightGBM training. DGA detection fully delegated to CNN embeddings. This is correct — NXDOMAIN DGA is not an active threat, and resolvable DGA looks like C2 (which is in the dataset).

**Traffic FP still high (6.8%):** CDN subdomains and API endpoints look suspicious to the model (long random subdomains, unfamiliar TLDs). Need more benign subdomain diversity or subdomain-specific features.

---

### Experiment: Subdomain feature engineering

Added 4 new features: `subdomain_entropy`, `subdomain_length`, `subdomain_digit_ratio`, `registrable_length`. Hypothesis: separate subdomain features from registrable domain features to reduce CDN subdomain FP.

**SHAP results:** `subdomain_length` ranked #8 (0.339), `subdomain_entropy` ranked #14 (0.187). The model uses them.

**Results:**

| Metric | Before (v2) | After (v3) | Change |
|--------|-------------|------------|--------|
| Phishing recall | 84.2% | 84.4% | +0.2% |
| Majestic FP | 0.22% | 0.14% | **-0.08%** |
| Traffic FP | 6.8% | 7.6% | +0.8% |
| Tranco FP | 0.58% | 0.81% | +0.23% |

**Observation:** Majestic FP improved significantly. Traffic FP didn't improve — CDN subdomains with random hashes still trigger. The fundamental issue is that `b.thumbs.redditmedia.com` looks exactly like `evil-hash.phishing-cdn.com` without knowing redditmedia is a legitimate parent domain.

**C2-DGA hypothesis verification:** C2 entropy (2.26) is closer to normal domains than DGA (3.16). C2 is a mix of DGA-generated and manually-registered infrastructure, not purely DGA. Heavy `.ru` TLD presence in ThreatFox C2 data.

---

### CNN training comparison across dataset sizes

| Dataset | AUC | Benign prec | Mal recall | Ratio (ben:mal) |
|---------|-----|------------|------------|-----------------|
| 738K (v1) | 0.981 | 0.86 | 0.96 | 2.3:1 |
| 2.5M (v2) | 0.974 | 0.93 | 0.87 | 1.6:1 |
| 2.87M (v3, +historical) | 0.965 | 0.89 | 0.85 | 1.2:1 |

**Observation:** AUC decreases as dataset grows and ratio approaches 1:1. More malicious data (especially 328K historical phishing from Phishing.Database ALL) makes the classification harder. Benign precision dropped from 0.93 → 0.89 — the near-equal ratio is pushing the CNN toward more aggressive classification.

**Decision:** 1:1.2 ratio is acceptable. The CNN embedding is not the final classifier — LightGBM with threshold tuning handles the production prior (99%+ benign). CNN AUC 0.965 is still strong for embedding quality.

### Feature design overhaul

Comprehensive feature audit revealed:
1. **avg_ttl is broken** — cache TTL ≠ authoritative TTL (training/inference mismatch)
2. **ip_asn overfits** — raw ASN has no ordinal relationship, tree memorizes individual ASNs
3. **ip_country biased** — penalizes non-KR hosting without impersonation context
4. **CT logs replace RDAP** — crt.sh has better coverage, no rate limits, public data

New feature design: 8 groups, 94 total features (53 existing, 41 new).
See `ml/docs/feature-design.md` for full specification.

Research validation (via web search of papers):
- Groups A, B, G, H have strongest evidence (EXPOSURE, Notos, CISA, Unit42)
- Group D (SOA) has weakest evidence — low priority
- LightGBM confirmed as right model choice (NeurIPS 2022)
- Key risk: feedback loop in Group H features (use external feeds only for reputation)

### C2-DGA hypothesis verification

C2 entropy (mean 2.26) is closer to normal domains (2.71) than DGA (3.16). C2 is NOT just DGA — it's a mix of DGA-generated and manually-registered infrastructure. Heavy .ru TLD presence in ThreatFox data.

### Experiment: Phase 1 features (has_mx, has_txt, NS features, tld_category, a_record_count)

Added 12 new features from Phase 1 (highest impact, data already available):
- DNS response: has_mx, has_txt, a_record_count
- NS infrastructure: ns_count, ns_name_entropy, ns_name_length, ns_is_registrar_default
- Domain string: tld_category, total_fqdn_length, max_label_length

**Results (68 features, 202K curated dataset):**

| Metric | v3 (previous) | v4 (+Phase1) | Change |
|--------|--------------|--------------|--------|
| AUC | 0.987 | 0.989 | +0.002 |
| Phishing recall | 84.4% | 85.1% | +0.7% |
| Malware recall | 89.7% | 91.4% | +1.7% |
| Traffic FP | 7.6% | **2.7%** | **-4.9%** |
| Overall FP | 0.81% | **0.55%** | **-0.26%** |
| FP count | 166 | **92** | **-74** |

**Key insight:** `a_record_count` is the 3rd most important SHAP feature (0.544). It dramatically reduced traffic FP — CDN subdomains have many A records (CDN IP anycast), which the model now correctly distinguishes from phishing. `has_txt` (#7), `ns_count` (#12) also contribute meaningfully.

**Remaining:** cert_age_days and cert_count are in the feature set but all -1/0 (no CT data yet). Need crt.sh bulk query to fill.

### Design shift: "how old" → "how young" (NRD-based domain age)

**Original plan:** Get `domain_age_days` (how old) for all training domains via RDAP or CT logs.

**Problem:** "How old" requires registration dates for ALL domains. RDAP is rate-limited (2 req/sec), crt.sh PostgreSQL is unstable for bulk, CT log scanning takes days. Our historical phishing feeds (2019-2024) are too old for NRD lists. Getting exact age for 200K domains is impractical.

**New approach:** "How young" — check if domain appears in NRD (Newly Registered Domain) lists. Only need recent data (last 30-90 days), freely available from WhoisDS (70K domains/day, 1500+ gTLDs).

**Why equivalent for ML:** The detection signal is "young = suspicious," not "old = safe." A 2-year-old domain and a 10-year-old domain are equally "not young." The model learns:
- NRD match (age known, < 30 days) → suspicious signal
- No NRD match (age unknown) → rely on other features
- Tranco/Majestic (known established) → safe signal

**Training data strategy:**
- Recent phishing (last 90 days) → exact `domain_age_days` from WhoisDS
- Historical phishing → NULL (can't prove they were young, LightGBM handles missing)
- Benign (Tranco/Majestic) → 365+ (established)
- The pattern "young AND malicious-looking = phishing" only needs recent examples

**Features:**
- `is_nrd_7d` (bool) — registered in last 7 days
- `is_nrd_30d` (bool) — registered in last 30 days
- `domain_age_days` (float, nullable) — exact if from NRD, NULL otherwise

**Data sources:**
- WhoisDS: daily ZIP files, base64-encoded date URLs, ~70K domains/day
- cenk/nrd: GitHub mirror, pre-aggregated rolling windows (30/60 day)
- Coverage: gTLDs only. No ccTLDs (.kr, .jp, .uk).

**For inference (future):**
- certstream-server-rust: real-time CT stream → domain first-cert cache
- Sunlight names tiles: bulk cert-based NRD from LE logs
- Our DNS first_seen_days from SQLite (complementary signal)

### CT Log Scanning — Research & Feasibility

**Goal:** Enrich training data with `cert_age_days` and `cert_count` from Certificate Transparency logs.

**crt.sh PostgreSQL (tested, rejected):**
- Public replica, but 5 concurrent connections, unstable (hot standby conflicts)
- `certificate_identity` view deprecated → now uses FTS on `certificate` table
- Popular domains cause recovery conflicts → queries fail
- Not feasible for 200K domain bulk enrichment

**certificate-transparency-go (tested, viable):**
- Installed `ctclient` and `scanlog` from `github.com/google/certificate-transparency-go`
- `ctclient get-entries`: bulk download entries by index range
- `ctclient bisect`: find index at specific timestamp (useful for "scan last 90 days")
- `scanlog`: regex filter on CN/SAN, parallel fetch
- Tested on Google Argon 2025h1 log (1.4B entries)
- Throughput: ~240 entries/sec with CLI tools. Custom Go code with `scanner.Scanner` library would be faster.

**Approach (for future implementation):**
1. Write Go scanner using `scanner.Scanner` from certificate-transparency-go library
2. Use `bisect` to find index for 90 days ago
3. Scan from that index to current, extract all domain names + timestamps
4. Build domain → {first_cert_timestamp, cert_count} lookup table
5. Match against training domains, save as `ct_cache.parquet`
6. Feed into `build_lgb_dataset.py`

**Estimated effort:** 1-2 days for Go scanner. Scan time: 1-2 days for 90 days of log entries on control plane server (better bandwidth to Google).

**Decision:** Defer to separate workstream. Phase 1 features already show strong results (traffic FP 2.7%, phishing recall 85.1%). CT features will add incremental improvement to phishing detection. Not blocking current iteration.

**For real-world inference:** CT lookup at query time deferred. Will implement as async cached lookup in control plane (like RDAP) when ready.

### Production deployment: training/inference mismatch discovered

**Deployed model → 47% of real traffic flagged as malicious.**

Root cause: 8 features (has_mx, has_txt, ns_count, ns_name_*, soa_refresh, soa_minimum) were trained from `resolve_data.py` which queries A + MX + TXT + NS + SOA separately per domain. But at inference, the ML scorer only sees the A query response — these features are ALWAYS false/0.

In training: `ns_count=0` means "malicious" (72% of malicious, 1% of benign).
At inference: `ns_count=0` for ALL domains → model treats everything as malicious.

Fix: excluded those 8 features, retrained, redeployed. FP rate returned to normal.

**Lesson: every training feature MUST be verified against what's available at inference time.**

### CNN knowledge gap: subdomain FPs

After fixing the mismatch, remaining FPs are all **benign subdomains with complex names**:
- `mobile.events.data.microsoft.com` (emb_24=7.23 — highest activation)
- `aps1-device-telemetry-gw.iot.i.tplinknbu.com` (IoT device)
- `www.akamai.com`, `cdn.discordapp.com` (CDN)
- `calendar-api.proton.me` (service endpoint)

CNN embedding analysis:
- `emb_24`: benign mean=0.01, malicious mean=4.35. FP domains score 1.3-7.2 (malicious range)
- `emb_20`: benign mean=0.09, malicious mean=3.01. FP domains score 1.4-4.5
- Safe domains (google.com, proton.me): emb_24=0.00, emb_20=0.00

**CNN creates a binary world:** short clean domain → zero activation → safe. Any subdomain complexity → activates like malicious. Can't distinguish `calendar-api.proton.me` (benign) from `naver-login-verify.evil.xyz` (phishing).

**Root cause:** This is a knowledge/context problem, not a pattern problem. The CNN detects character complexity correctly — but character complexity ≠ malicious. Distinguishing IoT/CDN subdomains from phishing requires knowing that `proton.me` is legitimate, which is factual knowledge not learnable from characters.

**Explored approaches:**
1. More benign training data → won't help (CNN sees same characters for both)
2. Scoring chain (ML + knowledge layer) → practical, deterministic
3. Transformer with pretraining → could learn token relationships but needs 10M+ data
4. LLM-as-judge for edge cases → expensive but has world knowledge
5. Contrastive learning on flow data → infrastructure-based, not character-based

## 2026-03-21: domain_ns_map Bootstrap Infrastructure

### Problem
Scoring chain's NS reputation step provides biggest adjustments (Stable: -0.5, Known: -0.3), but `domain_ns_map` only has entries from live traffic (minutes of data). Domains like proton.me, microsoft.com, discord.com get `NsTrust::New` — chain can't help them.

### Solution: Tranco top 100K bootstrap

Built 3-component pipeline:

1. **`ml/resolve_ns.py`**: Downloads Tranco top 100K, resolves NS records via dnspython (async, concurrency=100). Outputs TSV: `registrable_domain\tns1,ns2,...`
2. **Control plane API `POST /api/ns-map/import`**: Accepts TSV, inserts into `domain_ns_map` with `first_seen = now - 90d`, `observation_count = 100` (immediate Stable trust). Uses `INSERT OR IGNORE` — organic traffic data takes priority.
3. **CLI `nameserver ns-map import <file>`**: Reads TSV, sends to API in batches of 5000. Also `nameserver ns-map status` for stats.

### Design decisions
- **Backdated entries**: Bootstrap domains get `first_seen = 90 days ago` + `observation_count = 100` to immediately qualify as Stable (requires >= 30 days + >= 10 observations). Tranco top 100K are definitionally trustworthy.
- **INSERT OR IGNORE**: Organic traffic observations (real timestamps, real counts) are more valuable than bootstrap. Don't overwrite.
- **Python for resolution**: Follows existing `resolve_data.py` pattern. dnspython handles NS queries natively.

### Scoring chain weight optimization idea (parked)
User insight: chain weights (-0.5, -0.3, +0.1, etc.) are hand-tuned guesses. This is a constrained optimization problem, not a pattern learning problem. Can be solved with `scipy.optimize.minimize` once all chain features are implemented.

### Unified well-known domain management

Refactored benign domain lists (Tranco, Majestic) from flat files in `ml/data/` to database-backed entities in the control plane, following the same pattern as feeds and filter lists.

**Architecture:**
- `well_known_list` table in SQLite (parallel to `blocklist`/`allowlist`)
- Tranco + Majestic seeded in `filter_lists` with `list_type = 'well_known'`
- Auto-pull weekly, format parsers for `csv_tranco_zip` and `csv_majestic`
- `GET /api/well-known/domains` exports domains for NS resolution and ML training
- `build_dataset.py --control-url` reads benign domains from DB instead of downloading
- `resolve_ns.py --control-url` reads from DB instead of dataset.parquet
- Well-known list changes do NOT trigger filter recompilation (they're not blocking)

**Naming: "well_known"** — neutral, means "widely recognized." Does NOT assert safety — well-known domains can still be hijacked (which is what the scoring chain's NS change detection catches).

### NRD integration (cenk/nrd)

Added NRD (Newly Registered Domains) to the scoring chain as Step 5a.

**Data source:** cenk/nrd — pre-aggregated rolling windows from WhoisDS data.
- `nrd-last-10-days.txt` (699K domains, daily refresh)
- `nrd-last-30-days.txt` (2M domains, weekly refresh)
- Format: plain text, one domain per line, `#` comments
- Coverage: gTLDs only (no ccTLDs)

**Architecture:** Same as well_known — `nrd_list` table, seeded in `filter_lists`, auto-pulled.

**Scoring chain Step 5a (NRD):**
- Checks registrable domain against NRD list
- `is_nrd_10d` → +0.15 (very new, strong suspicion)
- `is_nrd_30d` (but not 10d) → +0.05 (new, moderate suspicion)
- Runs for ALL domains (not just untrusted NS) — a typosquat of a well-known domain would be newly registered

**API:** `GET /api/nrd/check/{domain}` for debugging NRD status.

### Embedding similarity experiment for Step 3.5 impersonation detection

**Question:** Can general embedding models detect domain impersonation better than Levenshtein?

**Models tested:** all-MiniLM-L6-v2 (80MB), all-mpnet-base-v2 (420MB), EmbeddingGemma-300m (300M params, Gemma 3)

**Key finding:** MiniLM and MPNet completely fail on confusable substitutions (`amaz0n→amazon`: 0.15-0.17). EmbeddingGemma is dramatically better.

**EmbeddingGemma with `task: sentence similarity` instruction:**

| Impersonation pair | Cosine |
|-------------------|--------|
| sh1nhan → shinhan | 0.943 |
| naverr → naver | 0.934 |
| rnicrosoft → microsoft | 0.920 |
| amzn → amazon | 0.864 |
| naver-verify → naver | 0.843 |
| amazon-login → amazon | 0.837 |
| kakao-pay-secure → kakao | 0.821 |
| kaka0 → kakao | 0.799 |
| g00gle → google | 0.750 |
| dlscord → discord | 0.725 |
| amaz0n → amazon | 0.694 |
| a2z → amazon | 0.680 |

| Unrelated pair | Cosine |
|---------------|--------|
| amazon ↔ wikipedia | 0.664 |
| shinhan ↔ proton | 0.663 |
| naver ↔ youtube | 0.646 |
| naver ↔ DGA hash | 0.538 |

**Threshold: 0.672** — clean separation (imp_min=0.680 > unr_max=0.664). Gap is thin (0.016) but exists. Combined with NS verification (different NS = impersonation), false positives are eliminated.

**Instruction prompt matters:** `sentence similarity` was the only prompt with positive overlap. `clustering` collapsed everything. `no prompt` had the best gap but negative overlap.

**Conclusion:** EmbeddingGemma + sentence similarity instruction + NS check is a viable approach for Step 3.5. Needs ONNX export (300M params, ~600MB) and precomputed well-known domain embeddings. Deferred for now — layered approach (confusable + Levenshtein + brand alias) is simpler to implement first.

### Next
- Deploy NRD integration
- Pull NRD lists: `nameserver filters pull cenk-nrd-10d` + `cenk-nrd-30d`
- Verify scoring chain: recent phishing domain → NRD + ML → higher score
- Then: Step 3.5 impersonation detection, Phase 2 features

---

## 2026-03-21: Scoring Chain Implementation + Transformer Results

### Transformer results (RunPod A40)

| Model | Params | AUC | FP fixed | Key finding |
|-------|--------|-----|----------|-------------|
| URLBert-tiny | 3.7M | 0.929 | 0/10 | BPE fragments brands |
| MiniLM-L12 | 33M | 0.961 | 1/10 (microsoft 0.64) | World knowledge marginal |
| DistilBERT | 66M | 0.969 | 2/10 (microsoft 0.04, google 0.14) | Helps top brands only |
| DeBERTa-v3 | 141M | NaN | — | MPS incompatible, CPU too slow |

**Conclusion:** World knowledge helps for TOP brands (Microsoft, Google) but insufficient for smaller ones (Proton, Discord, Akamai). Training data distribution dominates model architecture. Scoring chain is the right approach.

### Scoring chain v2 — implemented and deployed

6-step pipeline in `scoring_chain.rs`:
- Step 0: Pre-filter (PTR, mDNS, DNS-SD, .local → skip)
- Step 1: ML score (CNN + LightGBM)
- Step 2: DNSSEC check (BOGUS → +suspicion)
- Step 3: NS reputation from `domain_ns_map` table
- Step 4: Hosting platform subdomain impersonation check
- Step 5: Temporal check (traffic history)
- Step 6: Final score combination

**domain_ns_map table:** Auto-populates from every flow. After minutes of traffic: icloud.com→awsdns (6 obs), cspserver.net→awsdns (3 obs). Already reducing FP scores: amazonaws.com ML 0.977 → chain 0.677 (-0.3).

### What's NOT implemented yet

From the chain design:
- ❌ Step 3.5: Impersonation via infrastructure comparison (string-similar + different NS)
- ❌ NS consistency / hijack detection (NS change alerting)
- ❌ Batch bootstrap of domain_ns_map (resolve Tranco top 100K)
- ❌ NRD integration (WhoisDS daily lists)

From ML improvements:
- ❌ CNN/LightGBM still gives single subdomain too high score (cdn.discordapp.com → 0.97)
- ❌ Need to retrain with better subdomain features or more benign subdomain data
- ❌ Transformer experiments incomplete (DeBERTa, ModernBERT not tested)

### Key insight: ML + chain separation

ML detects suspicious patterns. Chain adds contextual knowledge. Neither replaces the other. ML improvements (better features, transformer) and chain improvements (NS reputation, impersonation detection) are independent workstreams.

## 2026-03-20: Transformer Experiments + Traffic Data

### Per-label feature engineering — failed

Attempted to compute ngram/entropy per DNS label (not whole domain). Result: no clean separation between FP benign and malicious. `google` scores as "random" (low ngram), phishing domains use real words (`bancewallet`). Per-label features are same signal as whole-domain features, just computed differently. Knowledge gap can't be solved by feature engineering.

### Transformer model comparison

| Model | Params | AUC | FP test (10 domains) | Key finding |
|-------|--------|-----|---------------------|-------------|
| Our CNN | 27K | 0.976 | 10/10 FP | Character patterns only |
| URLBert-tiny | 3.7M | 0.929 | 10/10 FP | URL-specific BPE too fragmented |
| MiniLM-L12 | 33M | 0.961 | 9/10 FP (microsoft.com slightly improved) | World knowledge in tokenizer NOT enough |
| DeBERTa-v3-small | 141M | (running) | — | Disentangled attention + 128K vocab |

**Critical finding:** URLBert-tiny's BPE tokenizer fragments `microsoft` into `m##ic##ro##so##f##t` (6 pieces). No semantic understanding despite URL-specific pre-training. MiniLM knows `microsoft` as single token but still flags `mobile.events.data.microsoft.com` at 0.64 (below 0.9 but still FP).

**Root cause confirmed:** The problem is NOT the model architecture or tokenizer — it's the **training data distribution**. Our dataset has:
- Benign: mostly short clean domains (google.com, naver.com)
- Malicious: lots of subdomains (phishing on platforms)
- Any model learns "subdomain = suspicious" from this distribution

### Tokenizer comparison

| Model | `microsoft` | `proton` | `calendar` | `a2z` |
|-------|-----------|---------|-----------|------|
| URLBert-tiny | m##ic##ro##so##f##t | p##ro##ton | ca##l##en##da##r | a##2##z |
| MiniLM/BERT/DeBERTa | `microsoft` (1 token) | `proton` (1 token) | `calendar` (1 token) | `a2##z` |
| ModernBERT | `microsoft` | `pro``ton` | `calendar` | `a``2``z` |

### Traffic data addition

Added 1,707 new benign domains from ClickHouse DNS traffic to `dataset.parquet`. These include CDN subdomains, IoT endpoints, APIs — exactly the FP patterns. Verified: 0 overlap with malicious feeds, 0 high-entropy DGA, 0 risky TLDs.

However, 1,707/2.87M = 0.06% — too small to change CNN training. The real impact requires either:
1. Much more traffic data accumulation over time
2. Targeted use in LightGBM training data (resolved.parquet)
3. Scoring chain (separate knowledge layer)

### Data plane: auth_ttl + full record preservation (deployed)

**TTL fix:** `response.ttl` was cache-decremented (RFC 1035 §7.4). Added `original_ttl` to `CachedAnswer` and `ResolveResult` in recursor.rs. Flow now has `auth_ttl` (authoritative) alongside `min_ttl` (cache-decremented). ClickHouse column `response_auth_ttl` added.

**Record preservation:** Previously MX, NS, TXT, SOA, CAA dropped TTLs. NS and MX were hardcoded `"[]"` in SQLite. Now all 18+ record types saved with TTLs: A, AAAA, CNAME, NS, MX, TXT, SOA, CAA, SRV, PTR, DNAME, NAPTR, HTTPS, SVCB, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA + OtherRecord catch-all.

**Control plane fix:** `processing.rs` now extracts real MX/NS/TXT/SOA from `flow.response.all_records` into SQLite. ML scorer reads `has_mx`, `has_txt`, `a_record_count`, `ns_count`, `referral_hop_count`.

**Deployed:** Both DNS server + control plane. Accumulation clock started for temporal features.

---

## Logging cleanup (same day)

Stripped all privacy-sensitive data from hot-path logs across both nameserver-dns and nameserver-control. Removed per-query domain/IP/score logging. Deployed to production. Cleared 79MB of old journal logs containing domain names.

## 2026-03-28: Feature Set v2 + Scoring Chain Redesign

### Problem: 13/28 non-embedding features NaN at inference

Audit found the Rust ml.rs `extract_features()` was missing 13 features the ONNX model expected (subdomain_entropy SHAP #2, ns_name_length SHAP #5, tld_category SHAP #10, etc.). Meanwhile it extracted 19 features the model didn't use. The model ran on ~half its intended signal.

### Root cause: mixed-scope features + training/inference mismatch

Old features computed on `fqdn_no_tld` (mixed registrable + subdomain). `hyphen_count` couldn't distinguish "hyphens in registrable" (phishing) from "hyphens in subdomain" (CDN). Features like `cert_age_days` had no real training data (all -1/0).

### v2 Design: 85 features (21 handcrafted + 64 CNN)

**Group A (12, was 18):** Strict scope split into registrable (8), subdomain (2), structural (2). All `reg_*` features computed on SLD label only. `sub_entropy` kept (SHAP #2). Removed 6 redundant/derivable features.

**Group B (5, was 10):** Only features with real SHAP signal AND reliable inference source. Kept avg_auth_ttl, has_cname, a_record_count, ns_name_entropy, ns_name_length. Removed cert_*, domain_age_days, ns_is_registrar_default, cname_target_is_free_hosting.

**Group F (4, NEW):** Reputation features from `domain_reputation`. Continuous, not binary. Design: "veto" (reduce FP) not "override" (free pass). ns_observation_count, well_known_rank_norm, domain_seen_days, cname_target_entropy.

**4 candidates validated against production data and rejected:**
- `avg_resolve_ms`: 63% of domains 50-200ms regardless of intent → geography, not malice
- `avg_chain_depth`: 96% depth <2 → determined by TLD structure + has_cname
- `has_dnssec`: 23/1.63M = 0.001% → no discriminative power
- `has_mx`: Phishing typosquats (naverj.com, shinahn.com) also have MX; biased sample from MX-query-only flows

### Scoring chain v2

**Added:** Well-known fast path (is_well_known + known NS → safe).
**Reduced:** ML threshold gate 0.3 → 0.15. Similarity magnitudes -0.2/+0.3 → -0.15/+0.2. NRD simplified to single +0.1.
**Tightened:** Hosting platform requires keyword AND brand (was OR).
**Removed:** NS trust adjustments (stable -0.5, known_provider -0.3) → model has ns_observation_count. Temporal step → model has domain_seen_days.
**Result:** Adjustment range [-0.95, +0.95] → [-0.25, +0.65]. Model does more, chain corrects less.

Full design: `ml/docs/feature-design.md` (v2)

### Training data fix: subdomain bias + benign traffic data

**Problem:** `has_subdomain` (SHAP #1, 2.79) and `sub_label_count` (SHAP #2) were training data artifacts — Tranco/Majestic have bare domains, malicious have subdomains. Model learned "has subdomain = malicious."

**Fix:** Removed both features + added 4,026 verified benign subdomains from real flow traffic (resolved via public DNS 1.1.1.1 to avoid domains table contamination). Domains verified by registrable domain against known-safe list (Apple, Google, Naver, Kakao, etc.).

**Result:** FP on real traffic dropped **64% → 13%**. SHAP now driven by CNN patterns (#1 sub_emb_15 1.52) and sub_entropy (#2 0.67) instead of subdomain presence.

### Data contamination discoveries

1. **Registrable-level reputation leak:** domain_reputation keyed by registrable. Phishing subdomains on hosting platforms (weebly.com, vercel.app) inherited host's clean reputation. 15.2% of malicious training data contaminated. Fix: temporal features deferred until FQDN-level data available.

2. **Batch resolve contamination:** resolve_data.py goes through our resolver → inserts into domains table. 280K training domains got uniform query_count=7 and identical first_seen on March 26. Only 12,640 pre-batch domains have real traffic data.

3. **has_infra_data guard checked v1 feature names:** `avg_ttl`/`unique_ip_count`/`ip_asn` (removed in v2) → every domain got `no_infra_data` override. Fixed to check v2 names.

### Deployed v2 model (2026-03-28)

84 features, AUC 0.9652. Detection: 98% at threshold 0.5, 81% at 0.9.
Model + scoring chain deployed atomically via Nix deploy-rs (model files packaged as Nix derivation).
First live detection: `vpnblock.appsu.it` — unknown C2/beacon domain, scored 1.0 malicious.
