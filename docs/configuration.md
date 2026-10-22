# Configuration

Pass a TOML file with `--config`. All data and key paths are resolved relative to that file, independently of the current working directory. `--check` loads and validates configuration, zones, lists, keys, and certificates without opening listeners. Unknown configuration fields are rejected.

## Server settings

Both binaries accept the same `[server]` table.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | Resolver `127.0.0.1:5353`; authority `127.0.0.1:5354` | Array of socket addresses serving UDP and TCP |
| `listen_dot` | `[]` | TLS listener addresses |
| `listen_doh` | `[]` | HTTPS listener addresses; `/dns-query` |
| `allow_networks` | `127.0.0.0/8`, `::1/128` | Explicit CIDRs of permitted clients; all others are refused |
| `max_in_flight` | `256` | Maximum concurrent resolutions |
| `query_timeout_secs` | `30` | Deadline for each resolution |
| `tcp_idle_timeout_secs` | `10` | Classic TCP idle and DoT handshake timeout |

Listener arrays can be empty, provided another transport is configured. TCP, DoT, and DoH addresses must be distinct. A denied client receives DNS `REFUSED`, including on encrypted transports. The application evaluates the actual peer address; it does not trust proxy forwarding headers. Put a resolver behind a VPN or configure your device networks directly.

### TLS

Add listeners and a matching PEM certificate chain and key:

```toml
[server]
listen = ["127.0.0.1:5353"]
listen_dot = ["127.0.0.1:8853"]
listen_doh = ["127.0.0.1:8443"]
allow_networks = ["127.0.0.0/8", "::1/128"]

[server.tls]
certificate = "tls/fullchain.pem"
private_key = "tls/privkey.pem"
# Optional HTTP authority check. Use the certificate's actual DNS hostname.
dns_name = "localhost"

[resolver]
mode = "forward"
upstreams = ["9.9.9.9:53", "1.1.1.1:53"]
dnssec_validation = true
```

Use a publicly trusted certificate for personal-device deployments. Certificate issuance and renewal are handled by your ACME client. Send `SIGHUP` after replacing the PEM files; new TLS connections use the replacement certificate. Invalid or mismatched replacements are rejected. Existing connections retain their established TLS session.

DoH accepts unpadded base64url DNS messages in the `dns` query parameter for GET. POST requests use `Content-Type: application/dns-message` and a DNS wire-format body. Malformed messages return HTTP 400, unsupported POST media types return 415, and oversized POST bodies return 413. Responses use `application/dns-message` and `Cache-Control: no-store`; the resolver's own DNS cache remains enabled.

## Resolver settings

### Recursive mode

```toml
[resolver]
mode = "recursive"
root_hints = "root.hints"
dnssec_validation = true
response_cache_size = 4096
nameserver_cache_size = 1024
recursion_limit = 24
```

Copy `resources/root.hints` beside this configuration. These are public bootstrap addresses, not zone data. Keep them current from [InterNIC](https://www.internic.net/domain/named.root). DNSSEC validation and QNAME minimization use Hickory's implementation. `trust_anchor` optionally supplies a DNSKEY-format trust-anchor file; normally the built-in root keys are used.

### Forward mode

```toml
[resolver]
mode = "forward"
upstreams = ["9.9.9.9:53", "1.1.1.1:53"]
dnssec_validation = true
response_cache_size = 4096
```

Upstreams are IP socket addresses, with UDP queries and TCP fallback. DNSSEC is validated locally, with an optional `trust_anchor` file for private signed namespaces. Forward mode requires at least one upstream; recursive mode requires root hints. `dnssec_validation` defaults to `true` in both modes.

Queries with the CD (checking disabled) flag bypass validation and never gain the AD (authenticated data) flag. Their resolver and cache are separate from normal validating queries. Cache-size settings apply to each view.

### Lists

```toml
[filters]
blocklists = ["lists/blocked.txt"]
allowlists = ["lists/allowed.txt"]
```

Supported entries:

```text
# One domain, or one hosts-file entry with one or more domains.
blocked.example.test
0.0.0.0 ads.example.test tracker.example.test
```

Names are normalized case-insensitively. Entries match complete DNS labels, including subdomains. Adblock rules, URL patterns, and wildcard syntax are rejected. Missing or invalid configured lists reject startup or reload, keeping an existing service's previous policy active.

## Authoritative zones

```toml
[server]
listen = ["0.0.0.0:53", "[::]:53"]
allow_networks = ["0.0.0.0/0", "::/0"]

[[zones]]
origin = "example.test"
file = "zones/example.test.zone"
```

Use your own domain and records for deployment. Zone files use the standard master-file format, including `$ORIGIN`, `$TTL`, SOA, NS, A, AAAA, CNAME, MX, TXT, wildcard records, and other record types supported by Hickory. Add another `[[zones]]` table for each domain. Duplicate origins are rejected. Increase the zone's SOA serial after changes and send `SIGHUP`.

Public authoritative servers need reachable UDP and TCP port 53, delegation at the parent, and glue records where required. Run your nameservers on separate hosts for availability. This release serves static primary zones; AXFR, IXFR, dynamic updates, and automatic secondary replication are disabled. Distribute zone files to your other hosts through your deployment process.

Ports below 1024 need operating-system privileges or port mapping. Use a service manager with `CAP_NET_BIND_SERVICE`, or map a container's unprivileged port to host port 53.

### DNSSEC signing

Create a local ECDSA P-256 combined signing key in PKCS#8 PEM format:

```sh
mkdir -p config/keys
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve \
  -out config/keys/example.test.pem
chmod 600 config/keys/example.test.pem
```

Keep the key readable by the server process. The repository ignores `config/`, PEM, DER, and key files. Add signing settings beneath the corresponding zone:

```toml
[[zones]]
origin = "example.test"
file = "zones/example.test.zone"

[zones.dnssec]
private_key = "keys/example.test.pem"
signature_validity_days = 7
```

The server publishes a flags-257 DNSKEY, signs the zone with algorithm 13, and generates NSEC proofs for negative answers. Signatures are refreshed at most daily, or after one third of their validity period when configured for fewer than three days. Configured validity can be 1–30 days. A missing or invalid signing key fails startup or rejects reload; it never switches the zone to unsigned operation.

Query the public DNSKEY to derive the DS record using your DNS tooling, validate the signed zone, and publish the DS through the domain registrar. Back up signing keys and coordinate rollover with the parent DS. Signing a zone alone does not establish its public chain of trust.
