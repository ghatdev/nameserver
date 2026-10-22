# Instructions

**This instruction is not optional. You must follow it exactly.**

## Core Principles

- Must measure, check existing things before create something rather than creating something directly
- Produce fully functional, executable code that achieves the intended behavior
- Never leave stubs, placeholders, `TODO`, `pass`, or `NotImplementedError`
- Stop and ask for clarification when requirements are unclear

## Verification

Run formatting, Clippy with warnings denied, Rust tests, and the local integration suite after changing DNS behavior. See `README.md` for exact commands. Preserve the separation between the resolver and the authoritative server. Do not add a required external control service to either binary.

## Database migrations

Use Atlas for PostgreSQL and `python3 tools/migrate_clickhouse.py apply` for ClickHouse. The user approved this ClickHouse runner because the distributed Atlas ClickHouse driver requires account access. Keep SQL changes in versioned migration files; never add inline schema changes to application startup.

## Logging

Do not include queried domains, client or resolved IP addresses, or profile IDs in production `info!`, `warn!`, or `error!` logs. Diagnostic details belong in `debug!` or `trace!`.
