# Feature Design Document (v2 — 2026-03-28)

## Design Principles

1. **Scope separation**: Every feature is computed on exactly one domain part (registrable label, subdomain, or TLD). No mixed-scope features.
2. **Model vs chain**: ML model handles continuous patterns. Scoring chain handles binary decisions, list matching, and per-flow signals.
3. **Inference parity**: Every training feature must be available at inference from `domain_reputation` (single query). No training/inference mismatch.
4. **Validated signals**: Features rejected by real production data analysis are excluded, regardless of theoretical appeal.

## Threat Patterns and Detection Signals

### Phishing
- Brand mimicry in registrable label → `reg_entropy`, `reg_confusable_count`, CNN `reg_emb_*`
- Crafted registration name → `reg_hyphen_count`, `reg_ngram_score`, `reg_cv_ratio`
- Free/new TLD → `tld_category`
- No established infrastructure → `ns_observation_count`, `avg_auth_ttl`
- Hosting platform abuse → scoring chain Step 7 (keyword AND brand)
- Recently registered → scoring chain Step 5 (NRD)

### DGA / Active C2
- Random registrable label → `reg_entropy`, CNN `reg_emb_*`
- Random subdomain → `sub_entropy`, CNN `sub_emb_*`
- Low TTL (fast-flux) → `avg_auth_ttl`
- Unknown NS → `ns_name_entropy`, `ns_name_length`
- No reputation history → `ns_observation_count`, `domain_seen_days`

### Supply Chain C2 (e.g., models.litellm.cloud)
- Clean labels defeat lexical/CNN features → caught by infrastructure signals
- Unknown NS, no observation history → `ns_observation_count`, `well_known_rank_norm`
- New domain → `domain_seen_days`, scoring chain NRD

### DNS Tunneling
- High subdomain entropy → `sub_entropy`
- Deep subdomain nesting → `sub_label_count`
- CNN `sub_emb_*` captures character patterns in subdomain labels

## Feature Groups (85 total: 21 handcrafted + 64 CNN)

### Group A — Lexical (12 features)

All from domain name string. No DNS resolution needed.

**Registrable scope** (SLD label — e.g., "proton", "shinhan-verify", "a3f8c2b"):

| Feature | Type | Description |
|---------|------|-------------|
| reg_entropy | float | Shannon entropy of SLD label |
| reg_length | int | Character count of SLD label (no TLD) |
| reg_hyphen_count | int | Hyphens in SLD label only |
| reg_digit_count | int | Digits in SLD label only |
| reg_cv_ratio | float | Consonant/vowel ratio of SLD label |
| reg_ngram_score | float | English bigram frequency of SLD label |
| reg_is_punycode | bool | SLD starts with xn-- (IDN) |
| reg_confusable_count | int | Unicode homoglyph substitutions in SLD |

**Subdomain scope** (everything left of registrable — e.g., "calendar-api", "cdn.assets"):

| Feature | Type | Description |
|---------|------|-------------|
| sub_entropy | float | Shannon entropy of full subdomain string |
| sub_label_count | int | Number of subdomain labels (depth) |

**Structural / TLD:**

| Feature | Type | Description |
|---------|------|-------------|
| tld_category | ordinal | free/newgtld/gtld/cctld |
| has_subdomain | bool | Whether subdomain part exists |

### Group B — Infrastructure (5 features)

All from `domain_reputation` table (single SQL query). EMA-smoothed or accumulated.

| Feature | Type | Source column | Update logic | Description |
|---------|------|--------------|-------------|-------------|
| avg_auth_ttl | float | avg_auth_ttl | EMA 0.9/0.1 | Authoritative TTL (fast-flux detection) |
| has_cname | bool | has_cname | sticky OR | CDN/hosting indicator |
| a_record_count | int | a_record_count | GREATEST | Max A records observed (CDN anycast) |
| ns_name_entropy | float | *computed* | from ns_domains[0] | Shannon entropy of primary NS domain |
| ns_name_length | int | *computed* | from ns_domains[0] | Character count of primary NS domain |

### Group F — Reputation (4 features, NEW)

All from `domain_reputation` + `well_known_domains`. Continuous values (not binary).
Design: "veto" signals to reduce FP, not "override" to grant free pass.

| Feature | Type | Source | Description |
|---------|------|--------|-------------|
| ns_observation_count | int | domain_reputation | Times we've observed this domain's NS |
| well_known_rank_norm | float | well_known_domains.rank / 1M | Tranco popularity (0 = top, NaN = unranked) |
| domain_seen_days | float | (now - first_seen).days() | How long we've been observing this domain |
| cname_target_entropy | float | cname_targets[0] | Shannon entropy of CNAME target string |

**Training data strategy for Group F:**
- Query `domain_reputation` for each training domain → ns_obs, domain_seen_days
- Join `well_known_domains` → well_known_rank_norm
- From resolve_data.py cname_chain → cname_target_entropy
- Inject 20% NaN into benign Group F columns (prevent "NaN = malicious" shortcut)

### Group C — CNN Embeddings (64 features)

Split-label CNN: each DNS label embedded independently, then aggregated.

| Feature | Dims | Scope |
|---------|------|-------|
| reg_emb_0..31 | 32 | Registrable label character patterns |
| sub_emb_0..31 | 32 | Subdomain labels (maxpool across labels) |

CNN model: char embedding (vocab=38, dim=16) → 3 parallel conv (kernel 3,4,5) → maxpool → dense(64) → embedding(32).
Same model called per-label. MAX_LEN=63 per RFC 1035.

## Removed Features (with evidence)

### Removed from Group A (old → new scope split)
| Old Feature | Reason |
|-------------|--------|
| total_fqdn_length | Derivable from reg_length + label_count |
| max_label_length | Correlated with reg_length; CNN handles subdomain patterns |
| has_service_keyword | Redundant with service_keyword_count |
| service_keyword_count | CNN embeddings + scoring chain cover both scopes |
| hyphen_word_count | Derivable from hyphen_count + 1 |
| subdomain_digit_ratio | Weak; CNN sub_emb captures digit patterns |
| subdomain_length | Correlated with sub_entropy; CNN sub_emb captures patterns |
| registrable_length | Nearly same as label_length minus TLD suffix |
| hyphen_count (mixed scope) | Replaced by reg_hyphen_count (SLD-scoped) |
| digit_count (mixed scope) | Replaced by reg_digit_count (SLD-scoped) |

### Removed from Group B
| Old Feature | Reason |
|-------------|--------|
| cname_depth | Training had real depth, inference was binary. Replaced by has_cname |
| ns_is_registrar_default | Static rule; scoring chain handles it |
| domain_age_days | No reliable inference source (WHOIS rate-limited) |
| cert_age_days | No real training data (all -1/0, CT pipeline never built) |
| cert_count | Same — no CT data |
| cname_target_is_free_hosting | Scoring chain Step 7 handles hosting platforms |

### Validated against production data and REJECTED
| Candidate | Production evidence | Verdict |
|-----------|-------------------|---------|
| avg_resolve_ms | 63% of domains in 50-200ms regardless of intent. Measures geography, not malice | Noise |
| avg_chain_depth | 96% of domains have depth <2. Determined by TLD structure + has_cname | Redundant |
| has_dnssec | 23 / 1,629,479 = 0.001% true. No discriminative power | Useless |
| has_mx | Phishing brands (naverj.com, shinahn.com) also have MX. Biased sample (only from MX queries), training/inference mismatch | Inverted signal |

### Stays excluded (from v1)
| Feature | Reason |
|---------|--------|
| ip_asn | Overfits to training ASNs |
| ip_country | US hosts both Google and C2 |
| unique_ip_count | Conflates CDN (benign) with fast-flux (malicious) |
| is_cdn, is_bulletproof | Live list matching → scoring chain |
| tranco_rank, feed_hit_count, query_count | Label leaks |

## Scoring Chain (post-model adjustments)

See `scoring_chain.rs` for implementation. Design principle: chain makes **small corrections** for signals the model cannot capture (per-flow, list-based, similarity).

### Steps:
0. **Skip** — PTR, mDNS, .local → exit
1. **Well-known fast path** — is_well_known AND ns_trust ∈ {stable, known_provider} → safe (0.05)
2. **ML threshold gate** — ml_score < 0.15 → exit safe
3. **DNSSEC** — BOGUS → +0.1
4. **NS edge cases** — free_dns +0.05, changed +0.1
5. **NRD** — is_nrd → +0.1
6. **Similarity** — infra fingerprint or NS comparison: same -0.15, different +0.2
7. **Hosting platform** — keyword AND brand → +0.2; keyword only → 0.0; clean → -0.1
8. **Verdict** — ≥0.9 malicious, ≥0.5 suspicious, ≥0.1 unknown, <0.1 safe

Adjustment range: [-0.25, +0.65] (down from [-0.95, +0.95] in v1).

### Removed from chain (model handles via Group F):
- NS trust adjustments (stable -0.5, known_provider -0.3) → model has ns_observation_count
- Temporal step (30d + 10 flows → -0.15) → model has domain_seen_days

## References

- EXPOSURE (Bilge et al., NDSS 2011) — 15 features, 4 categories
- Notos (Antonakakis et al., USENIX 2010) — network/zone/evidence features
- Phicious (Sabah et al., RAID 2022) — CT + pDNS
- Cloudflare (2024) — 28 features, two-stage neural
- NeurIPS 2022 — tree models outperform deep learning on tabular data
