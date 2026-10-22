# nameserver-control

> Part of **nameserver** — a prototype for validating DNS threat detection architecture.

Control plane binary for the Nameserver DNS threat detection prototype. Runs on the x86 dev server, performing threat analysis, scoring, and list building from DNS flow data.

## Purpose

Receive DNS flow documents from the data plane via NATS, analyze domains across multiple signal dimensions, produce threat scores and verdicts, and distribute updated domain lists back to the data plane.

## Module Structure (planned)

```
src/
├── main.rs                 # Entry point, tracing init, service bootstrap
├── config.rs               # TOML configuration loading
├── nats/
│   ├── mod.rs
│   ├── subscriber.rs       # ns.dns.flow receive + dispatch
│   └── publisher.rs        # ns.ctrl.list.update publish
├── store/
│   ├── mod.rs
│   ├── mongo.rs            # MongoDB connection + CRUD
│   ├── flows.rs            # flows collection operations
│   ├── domains.rs          # domains collection operations
│   └── ips.rs              # ips collection operations
├── analysis/
│   ├── mod.rs
│   ├── lexical.rs          # Entropy, N-gram, seed similarity, homoglyph
│   ├── infrastructure.rs   # GeoIP, ASN, IP blocklist
│   ├── dns_behavior.rs     # TTL, fast-flux, CNAME, DNSSEC
│   ├── registration.rs     # RDAP/WHOIS client + parsing
│   └── seeds.rs            # Seed domain list + similarity
├── scoring/
│   ├── mod.rs
│   ├── engine.rs           # Per-category score calculation
│   └── rules.rs            # Combination rule evaluation
├── builder/
│   ├── mod.rs
│   ├── xor_builder.rs      # XOR Filter construction
│   ├── fst_builder.rs      # FST construction
│   └── distributor.rs      # Build → NATS distribution
├── geoip/
│   ├── mod.rs
│   └── maxmind.rs          # MaxMind GeoLite2 reader
└── cli/
    ├── mod.rs
    └── investigate.rs       # Domain/IP lookup CLI
```

## Key Interfaces

- **NATS subscribe** — `ns.dns.flow` → processing pipeline
- **MongoDB CRUD** — flows insert, domains upsert, ips upsert, feeds insert
- **Analysis engine** — Lexical, infrastructure, DNS behavior, registration analysis
- **Scoring engine** — 4-category × 0-25 points + combination rules
- **List builder** — XOR Filter + FST construction → NATS distribution

## Dependencies

- `async-nats` — NATS client
- `mongodb` — MongoDB driver
- `maxminddb` — GeoIP lookups
- `reqwest` — HTTP client (RDAP, external feeds)
- `xorf` + `fst` — List data structure construction
- `sha2` — Checksum computation
- `clap` — CLI argument parsing
- `nameserver-common` — Shared types

## Configuration

See `CLAUDE.md` § Control Plane for configuration reference.

## Error Handling

- NATS disconnect: reconnect with backoff, buffered messages replayed via JetStream
- MongoDB disconnect: retry with backoff, pipeline paused
- RDAP/WHOIS timeout: mark as `registration_unknown`, retry later
- List build failure: keep existing lists, alert via logging
