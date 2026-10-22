# nameserver-common

> Part of **nameserver** — a prototype for validating DNS threat detection architecture.

Shared type definitions for the Nameserver DNS threat detection prototype. This crate contains message structs, enums, and constants used by `nameserver-authority`, `nameserver-resolver`, and `nameserver-control`.

## Purpose

Provide a single source of truth for all data types that cross crate boundaries. This crate contains **no business logic** — only type definitions, serialization attributes, and constants.

## Module Structure

```
src/
├── lib.rs                  # Public re-exports
├── messages/
│   ├── mod.rs              # Message module exports
│   ├── flow.rs             # DnsFlow, DnsQuery, ResolveStep, DnsResponse, DnssecResult
│   ├── event.rs            # DnsEvent, DnsEventType, DnsEventData
│   └── control.rs          # ListUpdate, ListReload, ConfigUpdate, HealthCheck
├── types/
│   ├── mod.rs              # Type module exports
│   ├── enums.rs            # FlowType, QueryType, ListAction, ResponseCode, DnssecStatus, ...
│   └── records.rs          # AllRecords, ARecord, AaaaRecord, MxRecord, SoaRecord, CaaRecord, ...
└── nats/
    ├── mod.rs              # NATS module exports
    └── subjects.rs         # Subject string constants (ns.dns.flow, ns.ctrl.*, ...)
```

## Key Interfaces

All message structs derive `Serialize`, `Deserialize`, `Debug`, and `Clone`. Serialization uses MessagePack named mode (`rmp_serde::to_vec_named`).

- **DnsFlow** — Core message published on `ns.dns.flow` after DNS resolution
- **DnsEvent** — Debug event published on `ns.dns.event` (per resolve step)
- **ListUpdate** — Control command for list data push (`ns.ctrl.list.update`)
- **ListReload** — Control command for disk-based list reload (`ns.ctrl.list.reload`)
- **ConfigUpdate** — Runtime configuration change (`ns.ctrl.config`)
- **HealthCheck** — Bidirectional health check (`ns.ctrl.health`)

## Dependencies

- `serde` — Serialization framework
- `uuid` — UUID v7 identifiers
- `rmp-serde` — MessagePack serialization (for tests/examples)

## Configuration

This crate has no runtime configuration. All types are pure data definitions.

## Error Handling

This crate defines no errors. Serialization errors are handled by consuming crates.
