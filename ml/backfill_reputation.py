"""Backfill domain_reputation from existing PostgreSQL + ClickHouse data.

Reads from:
  PostgreSQL: domains, resolution_history, domain_ns_map, domain_ips, ips,
              well_known_domains, nrd
  ClickHouse: flows (for domains without PostgreSQL resolution data)
Writes to:  domain_reputation (bulk insert via COPY)

Run on control node: uv run ml/backfill_reputation.py
"""

import io
import json
import math
from collections import defaultdict

import clickhouse_connect
import psycopg2
import psycopg2.extras

PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
CH_HOST = "localhost"
CH_PORT = 18123
CH_DB = "nameserver"

# Must match reputation.rs constants
FREE_TLDS = {"tk", "ml", "ga", "cf", "gq"}
NEW_GTLDS = {
    "xyz", "top", "club", "online", "site", "store", "fun", "icu", "buzz",
    "space", "website", "tech", "click", "link", "work", "life", "live",
    "host", "press", "pw", "cam", "rest", "surf",
}
MULTI_PART_TLDS = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "co.uk", "com.au",
    "co.jp", "com.br", "com.mx", "co.in",
}
KNOWN_NS = [
    "awsdns", "cloudflare.com", "google.com", "googledomains.com",
    "msft.net", "apple.com", "akam", "akadns", "ultradns",
    "nsone.net", "dynect.net", "azure-dns", "ns.oracle.com",
    "registrar-servers.com", "domaincontrol.com", "fastly",
]
REGISTRAR_NS = [
    "registrar-servers.com", "domaincontrol.com", "name-services.com",
    "sedoparking.com", "parkingcrew.net", "bodis.com", "dns-parking",
]
FREE_DNS = [
    "duckdns.org", "afraid.org", "no-ip.com", "dynu.com",
    "hopto.org", "zapto.org", "ddns.net", "sytes.net", "serveblog.net",
]


def extract_tld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return domain
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS:
        return last_two
    return parts[-1]


def classify_tld_risk(tld: str) -> float:
    if tld in FREE_TLDS:
        return 1.0
    if tld in NEW_GTLDS:
        return 0.7
    if len(tld) == 2 or "." in tld:
        return 0.3
    return 0.0


def classify_tld_type(tld: str) -> str:
    if tld in FREE_TLDS:
        return "free"
    if tld in NEW_GTLDS:
        return "new_gtld"
    if len(tld) == 2 or "." in tld:
        return "cctld"
    return "gtld"


def classify_ns_trust(ns_list: list[str]) -> str:
    if not ns_list:
        return "unknown"
    first = ns_list[0].lower()
    if any(p in first for p in FREE_DNS):
        return "free_dns"
    if any(p in first for p in REGISTRAR_NS):
        return "registrar_default"
    if any(p in first for p in KNOWN_NS):
        return "known_provider"
    return "new"


def compute_fingerprint(
    avg_ttl: float,
    avg_resolve_ms: float,
    avg_hops: float,
    has_cname: bool,
    has_dnssec: bool,
    has_mx: bool,
    has_txt: bool,
    has_soa: bool,
    a_count: int,
    ns_list: list[str],
    unique_ips: int,
    is_cdn: bool,
    domain: str,
) -> list[float]:
    fp = [0.0] * 27

    # [0] chain_depth_norm
    fp[0] = min(avg_hops / 6.0, 1.0)
    # [1] has_cname_chain
    fp[1] = 1.0 if has_cname else 0.0
    # [2] cname_depth_norm (approximate from has_cname)
    fp[2] = 0.4 if has_cname else 0.0
    # [3] answer_step_ratio (approximate)
    fp[3] = 1.0 / max(avg_hops, 1.0)
    # [4] referral_step_ratio
    fp[4] = max(0, avg_hops - 1) / max(avg_hops, 1.0)
    # [5] multi_ns_providers
    ns_regs = set()
    for ns in ns_list:
        parts = ns.rstrip(".").split(".")
        if len(parts) >= 2:
            ns_regs.add(f"{parts[-2]}.{parts[-1]}")
    fp[5] = 1.0 if len(ns_regs) >= 2 else 0.0

    # [6] auth_ttl_log_norm
    ttl = max(avg_ttl, 1)
    fp[6] = min(math.log2(ttl) / 20.0, 1.0)
    # [7] has_dnssec
    fp[7] = 1.0 if has_dnssec else 0.0
    # [8] has_mx
    fp[8] = 1.0 if has_mx else 0.0
    # [9] has_txt
    fp[9] = 1.0 if has_txt else 0.0
    # [10] has_soa
    fp[10] = 1.0 if has_soa else 0.0
    # [11] a_record_count_norm
    fp[11] = min(a_count / 8.0, 1.0)

    # [12-14] NS classification
    first_ns = ns_list[0].lower() if ns_list else ""
    fp[12] = 1.0 if any(p in first_ns for p in KNOWN_NS) else 0.0
    fp[13] = 1.0 if any(p in first_ns for p in REGISTRAR_NS) else 0.0
    fp[14] = 1.0 if any(p in first_ns for p in FREE_DNS) else 0.0

    # [15] ns_self_hosted
    domain_reg = domain.rstrip(".")
    fp[15] = 1.0 if first_ns and any(
        domain_reg.endswith(r) for r in ns_regs
    ) else 0.0

    # [16] ns_provider_diversity
    fp[16] = min(len(ns_regs) / 4.0, 1.0)
    # [17] ns_observation_norm (from observation count, set later)
    fp[17] = 0.0

    # [18] unique_ip_norm
    fp[18] = min(unique_ips / 16.0, 1.0)
    # [19] unique_asn_norm (approximate)
    fp[19] = 0.25 if unique_ips > 0 else 0.0
    # [20] is_cdn
    fp[20] = 1.0 if is_cdn else 0.0
    # [21] is_bulletproof
    fp[21] = 0.0
    # [22] resolve_ms_log_norm
    ms = max(avg_resolve_ms, 1)
    fp[22] = min(math.log2(ms) / 15.0, 1.0)
    # [23] ip_stability
    fp[23] = 0.8  # assume mostly stable for historical data

    # [24] tld_risk
    tld = extract_tld(domain)
    fp[24] = classify_tld_risk(tld)
    # [25] cname_target_diversity (approximate)
    fp[25] = 0.2 if has_cname else 0.0
    # [26] delegation_depth_norm
    fp[26] = min(max(avg_hops - 1, 0) / 4.0, 1.0)

    return fp


def build_row(
    reg: str,
    ns_info: dict,
    res_info: dict | None,
    ip_info: dict | None,
    flow_count: int,
    first_seen,
    last_seen,
    well_known: set,
    nrd_map: dict,
) -> tuple | None:
    """Build a single reputation row tuple for bulk insert."""
    tld = extract_tld(reg)
    tld_type = classify_tld_type(tld)
    ns_list = ns_info.get("ns_list", [])
    ns_trust = classify_ns_trust(ns_list)

    obs = ns_info.get("obs_count", 0)
    if obs >= 50:
        ns_trust = "stable"
    elif ns_info.get("first_seen") and ns_info.get("last_seen"):
        days = (ns_info["last_seen"] - ns_info["first_seen"]).days
        if days >= 30 and obs >= 10:
            ns_trust = "stable"

    avg_ttl = res_info["avg_ttl"] if res_info else 300.0
    avg_ms = res_info["avg_ms"] if res_info else 100.0
    avg_hops = res_info["avg_hops"] if res_info else 1.0
    has_cname = res_info["has_cname"] if res_info else False
    has_dnssec = res_info["has_dnssec"] if res_info else False
    has_mx = res_info["has_mx"] if res_info else False
    has_txt = res_info.get("has_txt", False) if res_info else False
    has_soa = res_info.get("has_soa", False) if res_info else False
    a_count = res_info["a_count"] if res_info else 0
    unique_ips = ip_info["unique_ips"] if ip_info else 0
    is_cdn = ip_info["is_cdn"] if ip_info else False

    fp = compute_fingerprint(
        avg_ttl, avg_ms, avg_hops, has_cname, has_dnssec, has_mx,
        has_txt, has_soa, a_count, ns_list, unique_ips, is_cdn, reg,
    )
    fp[17] = min(math.log2(obs + 1) / 10.0, 1.0)
    fp_str = "[" + ",".join(f"{v:.6f}" for v in fp) + "]"

    is_well_known = reg in well_known or f"{reg}." in well_known
    is_nrd = reg in nrd_map or f"{reg}." in nrd_map
    nrd_source = nrd_map.get(reg) or nrd_map.get(f"{reg}.")
    ns_json = json.dumps([ns.rstrip(".") for ns in ns_list[:20]])

    if first_seen is None:
        return None

    return (
        reg, flow_count, first_seen, last_seen or first_seen,
        tld, tld_type, ns_trust, ns_json, obs,
        fp_str,
        avg_ttl, avg_ttl, avg_ms, avg_hops,
        has_cname, has_dnssec, has_mx,
        unique_ips, a_count,
        ip_info.get("asn") if ip_info else None,
        ip_info.get("country") if ip_info else None,
        is_cdn,
        is_nrd, nrd_source, is_well_known,
        last_seen or first_seen,
    )


UPSERT_SQL = """INSERT INTO domain_reputation (
    registrable_domain, total_flow_count, first_seen, last_seen,
    tld, tld_type, ns_trust, ns_domains, ns_observation_count,
    infra_fingerprint,
    avg_auth_ttl, min_auth_ttl, avg_resolve_ms, avg_chain_depth,
    has_cname, has_dnssec, has_mx,
    unique_ip_count, a_record_count,
    primary_asn, primary_country, is_cdn,
    is_nrd, nrd_source, is_well_known,
    updated_at
) VALUES (
    %s, %s, %s, %s,
    %s, %s, %s, %s::jsonb, %s,
    %s::vector(27),
    %s, %s, %s, %s,
    %s, %s, %s,
    %s, %s,
    %s, %s, %s,
    %s, %s, %s,
    %s
)
ON CONFLICT (registrable_domain) DO UPDATE SET
    total_flow_count = GREATEST(domain_reputation.total_flow_count, EXCLUDED.total_flow_count),
    ns_trust = EXCLUDED.ns_trust,
    ns_domains = EXCLUDED.ns_domains,
    ns_observation_count = GREATEST(domain_reputation.ns_observation_count, EXCLUDED.ns_observation_count),
    infra_fingerprint = EXCLUDED.infra_fingerprint,
    avg_auth_ttl = EXCLUDED.avg_auth_ttl,
    min_auth_ttl = EXCLUDED.min_auth_ttl,
    avg_resolve_ms = EXCLUDED.avg_resolve_ms,
    avg_chain_depth = EXCLUDED.avg_chain_depth,
    has_cname = EXCLUDED.has_cname OR domain_reputation.has_cname,
    has_dnssec = EXCLUDED.has_dnssec OR domain_reputation.has_dnssec,
    has_mx = EXCLUDED.has_mx OR domain_reputation.has_mx,
    unique_ip_count = GREATEST(domain_reputation.unique_ip_count, EXCLUDED.unique_ip_count),
    a_record_count = GREATEST(domain_reputation.a_record_count, EXCLUDED.a_record_count),
    primary_asn = COALESCE(EXCLUDED.primary_asn, domain_reputation.primary_asn),
    primary_country = COALESCE(EXCLUDED.primary_country, domain_reputation.primary_country),
    is_cdn = EXCLUDED.is_cdn OR domain_reputation.is_cdn,
    is_nrd = EXCLUDED.is_nrd OR domain_reputation.is_nrd,
    nrd_source = COALESCE(EXCLUDED.nrd_source, domain_reputation.nrd_source),
    is_well_known = EXCLUDED.is_well_known OR domain_reputation.is_well_known,
    updated_at = GREATEST(domain_reputation.updated_at, EXCLUDED.updated_at)
"""


def flush_batch(cur, batch: list):
    if not batch:
        return
    psycopg2.extras.execute_batch(cur, UPSERT_SQL, batch, page_size=2000)


def main():
    conn = psycopg2.connect(PG_URL)
    conn.autocommit = False
    cur = conn.cursor()

    # ── Phase 1: Load reference data ──
    print("Loading well_known_domains...")
    cur.execute("SELECT domain FROM well_known_domains")
    well_known = {row[0].rstrip(".") for row in cur.fetchall()}
    print(f"  {len(well_known)} well-known domains")

    print("Loading NRD...")
    cur.execute("SELECT domain, source FROM nrd")
    nrd_map = {}
    for domain, source in cur.fetchall():
        nrd_map[domain.rstrip(".")] = source
    print(f"  {len(nrd_map)} NRD entries")

    # ── Phase 2: Load PostgreSQL aggregate data ──
    print("Loading domain_ns_map...")
    cur.execute(
        "SELECT registrable_domain, array_agg(ns_domain ORDER BY observation_count DESC), "
        "SUM(observation_count), MIN(first_seen), MAX(last_seen) "
        "FROM domain_ns_map GROUP BY registrable_domain"
    )
    ns_data = {}
    for reg, ns_list, obs_count, first_seen, last_seen in cur.fetchall():
        ns_data[reg] = {
            "ns_list": ns_list or [],
            "obs_count": obs_count or 0,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    print(f"  {len(ns_data)} registrable domains with NS data")

    print("Loading aggregated resolution_history...")
    cur.execute(
        "SELECT domain, "
        "  COUNT(*), AVG(ttl), AVG(resolve_ms), AVG(referral_hop_count), "
        "  BOOL_OR(cname_chain IS NOT NULL), "
        "  BOOL_OR(dnssec_status = 'secure'), "
        "  BOOL_OR(jsonb_array_length(COALESCE(mx_records, '[]'::jsonb)) > 0), "
        "  BOOL_OR(has_txt), BOOL_OR(soa_json IS NOT NULL), "
        "  MAX(a_record_count), MIN(resolved_at), MAX(resolved_at) "
        "FROM resolution_history GROUP BY domain"
    )
    resolution = {}
    for row in cur.fetchall():
        resolution[row[0].rstrip(".")] = {
            "count": row[1], "avg_ttl": float(row[2] or 300),
            "avg_ms": float(row[3] or 100), "avg_hops": float(row[4] or 1),
            "has_cname": bool(row[5]), "has_dnssec": bool(row[6]),
            "has_mx": bool(row[7]), "has_txt": bool(row[8]),
            "has_soa": bool(row[9]), "a_count": int(row[10] or 0),
        }
    print(f"  {len(resolution)} domains with resolution history")

    print("Loading IP data...")
    cur.execute(
        "SELECT di.domain, COUNT(DISTINCT di.ip), BOOL_OR(i.is_cdn), "
        "  MAX(i.asn_number), MODE() WITHIN GROUP (ORDER BY i.geo_country) "
        "FROM domain_ips di LEFT JOIN ips i ON di.ip = i.ip GROUP BY di.domain"
    )
    ip_data = {}
    for domain, unique_ips, is_cdn, asn, country in cur.fetchall():
        ip_data[domain.rstrip(".")] = {
            "unique_ips": unique_ips or 0, "is_cdn": bool(is_cdn),
            "asn": asn, "country": country,
        }
    print(f"  {len(ip_data)} domains with IP data")

    print("Loading domains table...")
    cur.execute("SELECT domain, first_seen, last_seen, query_count FROM domains")
    domains = {}
    for domain, first_seen, last_seen, qc in cur.fetchall():
        domains[domain.rstrip(".")] = {
            "first_seen": first_seen, "last_seen": last_seen, "query_count": qc,
        }
    print(f"  {len(domains)} domains total")

    # ── Phase 3: ClickHouse flow data for domains without PG resolution data ──
    print("Loading ClickHouse flow aggregates for domains not in resolution_history...")
    ch = clickhouse_connect.get_client(host=CH_HOST, port=CH_PORT, database=CH_DB)
    ch_result = ch.query(
        "SELECT domain, "
        "  count() as cnt, "
        "  avg(response_auth_ttl) as avg_ttl, "
        "  avg(total_ms) as avg_ms, "
        "  avg(length(resolution_path.step)) as avg_hops, "
        "  max(length(cname_chain) > 0) as has_cname, "
        "  max(dnssec_status = 'secure') as has_dnssec, "
        "  max(length(response_ips)) as max_ips, "
        "  min(started_at) as first_seen, "
        "  max(started_at) as last_seen, "
        "  groupUniqArray(10)(arrayFilter(x -> x != '', resolution_path.server_name)) as ns_arrays "
        "FROM flows "
        "GROUP BY domain "
        "HAVING cnt >= 1"
    )
    ch_data = {}
    for row in ch_result.result_rows:
        domain = row[0].rstrip(".")
        if domain not in resolution:  # only for domains not in PG
            ns_flat = []
            for ns_arr in (row[10] or []):
                if isinstance(ns_arr, list):
                    ns_flat.extend(ns_arr)
                elif isinstance(ns_arr, str):
                    ns_flat.append(ns_arr)
            ch_data[domain] = {
                "count": row[1],
                "avg_ttl": float(row[2] or 300),
                "avg_ms": float(row[3] or 100),
                "avg_hops": float(row[4] or 1),
                "has_cname": bool(row[5]),
                "has_dnssec": bool(row[6]),
                "has_mx": False, "has_txt": False, "has_soa": False,
                "a_count": int(row[7] or 0),
                "first_seen": row[8],
                "last_seen": row[9],
                "ns_list": [ns.rstrip(".") for ns in ns_flat if ns],
            }
    print(f"  {len(ch_data)} domains from ClickHouse (not in PG resolution_history)")

    # ── Phase 4: Build and bulk insert ──
    all_registrables = set(ns_data.keys()) | set(ch_data.keys())
    print(f"\nBackfilling {len(all_registrables)} registrable domains...")

    batch = []
    count = 0
    skipped = 0

    for reg in all_registrables:
        ns_info = ns_data.get(reg, {"ns_list": [], "obs_count": 0})
        dom_info = domains.get(reg) or domains.get(f"{reg}.")
        res_info = resolution.get(reg) or resolution.get(f"{reg}.")
        ch_info = ch_data.get(reg)
        ip_info = ip_data.get(reg) or ip_data.get(f"{reg}.")

        # Use ClickHouse data as fallback for resolution info
        if res_info is None and ch_info is not None:
            res_info = ch_info
            # Also fill ns_info from CH if empty
            if not ns_info["ns_list"] and ch_info.get("ns_list"):
                ns_info = {
                    "ns_list": ch_info["ns_list"],
                    "obs_count": ch_info["count"],
                    "first_seen": ch_info["first_seen"],
                    "last_seen": ch_info["last_seen"],
                }

        first_seen = (dom_info or {}).get("first_seen") or ns_info.get("first_seen")
        last_seen = (dom_info or {}).get("last_seen") or ns_info.get("last_seen")
        flow_count = (dom_info or {}).get("query_count", 0) or 0

        row = build_row(
            reg, ns_info, res_info, ip_info,
            flow_count, first_seen, last_seen,
            well_known, nrd_map,
        )
        if row is None:
            skipped += 1
            continue

        batch.append(row)
        count += 1

        if len(batch) >= 5000:
            flush_batch(cur, batch)
            conn.commit()
            batch.clear()
            print(f"  inserted {count}...")

    flush_batch(cur, batch)
    conn.commit()
    print(f"\nDone. Backfilled {count} domains ({skipped} skipped, no first_seen).")

    # ── Phase 5: Mark well-known domains that aren't in our flow data ──
    print("Marking remaining well-known domains...")
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    wk_batch = []
    cur.execute("SELECT registrable_domain FROM domain_reputation")
    existing_regs = {row[0] for row in cur.fetchall()}

    for wk_domain in well_known:
        reg = wk_domain.rstrip(".")
        if reg in existing_regs:
            continue
        tld = extract_tld(reg)
        tld_type = classify_tld_type(tld)
        fp = [0.0] * 27
        fp[24] = classify_tld_risk(tld)
        fp_str = "[" + ",".join(f"{v:.6f}" for v in fp) + "]"
        wk_batch.append((
            reg, 0, now, now,
            tld, tld_type, "unknown", "[]", 0,
            fp_str,
            0.0, 0.0, 0.0, 0.0,
            False, False, False,
            0, 0,
            None, None, False,
            False, None, True,
            now,
        ))

    if wk_batch:
        flush_batch(cur, wk_batch)
        conn.commit()
        print(f"  added {len(wk_batch)} well-known-only domains")

    # ── Verify ──
    cur.execute("SELECT COUNT(*), COUNT(infra_fingerprint) FROM domain_reputation")
    total, with_fp = cur.fetchone()
    print(f"\ndomain_reputation: {total} rows, {with_fp} with fingerprint")

    cur.execute("SELECT COUNT(*) FROM domain_reputation WHERE is_well_known")
    print(f"  {cur.fetchone()[0]} well-known")

    cur.execute("SELECT COUNT(*) FROM domain_reputation WHERE is_nrd")
    print(f"  {cur.fetchone()[0]} NRD")

    cur.execute(
        "SELECT ns_trust, COUNT(*) FROM domain_reputation "
        "GROUP BY ns_trust ORDER BY COUNT(*) DESC"
    )
    print("  NS trust distribution:")
    for trust, cnt in cur.fetchall():
        print(f"    {trust}: {cnt}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
