# nameserver

Four core components in one Rust workspace:

| Binary | Purpose |
| --- | --- |
| `nameserver-resolver` | Personal recursive or forwarding DNS with caching, DNSSEC validation, domain filtering, UDP/TCP, DoH, and DoT |
| `nameserver-authority` | Authoritative DNS for your domains, using local zone files or managed zones, with optional DNSSEC signing |
| `nameserver-control` | Management API, profiles, feeds, compiled filters, zone distribution, flow analytics, reputation, and optional research/ML workers |
| `nameserver` | CLI controller and DNS diagnostics |

The two DNS servers can start independently from local files. Managed deployments use the CLI, control plane, PostgreSQL, ClickHouse, and NATS together. DNS protocol handling and validation use [Hickory DNS](https://github.com/hickory-dns/hickory-dns).

See [architecture](docs/architecture.md) for the component boundaries and [managed setup](docs/management.md) for the full stack. The CLI and control plane are core components; independent DNS startup is an operating mode.

## Build

Requires Rust 1.88 or newer.

```sh
cargo build --workspace --locked
```

Install either service independently:

```sh
cargo install --locked --path crates/nameserver-resolver
cargo install --locked --path crates/nameserver-authority
```

## Try the authoritative server

The included zone uses the reserved `example.test` domain and documentation IP addresses. Start it on an unprivileged loopback port:

```sh
target/debug/nameserver-authority --config examples/authority.toml --check
target/debug/nameserver-authority --config examples/authority.toml
```

In another terminal:

```sh
dig @127.0.0.1 -p 5354 example.test A
dig @127.0.0.1 -p 5354 www.example.test CNAME +tcp
dig @127.0.0.1 -p 5354 missing.example.test A
```

The server answers only for its configured zones. It refuses outside queries and zone transfers. To host a real domain, configure its zone and delegation as described in [configuration](docs/configuration.md).

## Try the personal resolver

```sh
target/debug/nameserver-resolver --config examples/resolver.toml --check
target/debug/nameserver-resolver --config examples/resolver.toml
```

```sh
dig @127.0.0.1 -p 5353 example.com A +dnssec
dig @127.0.0.1 -p 5353 blocked.example.test A
```

The first example resolves from the DNS roots using the bundled InterNIC root hints. It needs outbound UDP and TCP port 53. DNSSEC validation uses Hickory's built-in root trust anchors.

For forwarding through explicitly configured upstream resolvers:

```sh
target/debug/nameserver-resolver --config examples/resolver-forward.toml
```

Hickory currently labels its full recursive resolver experimental. Both modes are available; forwarding sends queries to the configured upstream operators. The supplied forwarding example uses Quad9 and Cloudflare over UDP with TCP fallback.

The examples permit loopback clients. To serve your devices, set the listening addresses and explicitly list their LAN or VPN networks. The allow list applies to IPv4 and IPv6, including IPv4 clients on dual-stack listeners. Use separate addresses when running public authoritative DNS and a personal resolver on the same host's port 53.

## Filtering and reloads

List files accept one domain per line or hosts-file entries, with `#` comments. A domain entry applies to that name and its subdomains. Allowlist matches override blocklist matches. Blocked queries return `NXDOMAIN` with a 60-second negative-cache TTL and the AD flag cleared.

Lists apply to the original query name. Inspection of CNAME targets, response IP filtering, and machine learning are outside the current feature set.

On Unix, send `SIGHUP` to reload configuration, zone files, lists, DNSSEC keys, and TLS certificates. A failed replacement keeps the current snapshot. Listener addresses, client access rules, and request limits require a restart. Resolver reloads clear its caches.

Both services handle `SIGTERM` and Ctrl+C. Default logs contain lifecycle events, without query names or client addresses. `RUST_LOG` can enable more detailed logs, including upstream library diagnostics; those may contain query data.

## Encrypted DNS and signed zones

See [configuration](docs/configuration.md) for DoH at `/dns-query`, DoT, TLS certificate reloads, and ECDSA P-256 zone signing. DoH supports GET and POST over HTTP/2 and HTTP/1.1. Private keys and personal configuration belong outside tracked examples.

## Containers

```sh
docker build --target resolver -t nameserver-resolver .
docker run --rm -p 127.0.0.1:5353:5353/udp -p 127.0.0.1:5353:5353/tcp nameserver-resolver

docker build --target authority -t nameserver-authority .
docker run --rm -p 127.0.0.1:5354:5354/udp -p 127.0.0.1:5354:5354/tcp nameserver-authority
```

The images run as an unprivileged user. Mount a configuration directory and pass `--config /path/to/config.toml` for your own deployment.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --locked
python3 tests/integration.py
```

Integration tests require Python 3, OpenSSL, and curl with HTTP/2 support. They start both binaries on temporary loopback ports, create temporary keys, and exercise real UDP, TCP, DoT, DoH, filtering, client restrictions, DNSSEC validation, authenticated denial, and reload behavior. They do not query external DNS. Set `NAMESERVER_BIN_DIR` to test an alternate binary directory.

CI runs on Linux and macOS. Pushing a `v*` tag builds archives containing all four binaries, examples, root hints, and documentation, then publishes a GitHub release.

In an extracted release archive, run `bin/nameserver-authority --config examples/authority.toml` or `bin/nameserver-resolver --config examples/resolver.toml` from the archive directory.

## Layout

```text
crates/nameserver-core/       shared configuration, policy, TLS, and service runtime
crates/nameserver-resolver/   recursive/forwarding resolver
crates/nameserver-authority/  local/managed authoritative zones and signing
crates/nameserver-control/    management API, ingestion, enrichment, optional ML
crates/nameserver-cli/        CLI controller and diagnostic commands
crates/nameserver-common/     protocol types, filters, artifact formats
atlas/                       schema and versioned migrations
ml/                          optional research tooling and inference artifacts
tools/                       migration and model-bundle utilities
examples/                    working configurations, lists, and a test zone
resources/                   public root hints
tests/                       local protocol integration tests
```

Licensed under [MIT](LICENSE).

The managed integration suite runs against the isolated Compose services after applying their migrations:

```sh
python3 tests/management.py
```

It covers CLI zone/profile updates, DoH/DoT profile routing, DNSSEC signing and validation, policy reloads, last-good zone retention, and PostgreSQL/ClickHouse flow ingestion. Automatic research workers and ML inference are disabled in the default build and sample config.
