"""Generate synthetic CDN subdomain benign data for ML training.

The model trained on Tranco registrable domains (label_count=2) has a severe
distribution mismatch: real DNS traffic includes CDN subdomains with 3-5 labels.
This script generates representative CDN subdomain patterns from Tranco domains
so the model learns that multi-label domains are not inherently malicious.

Usage:
    uv run python generate_cdn_benign.py
    uv run python generate_cdn_benign.py --count 5000 --patterns-per-domain 5
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

# CDN subdomain patterns observed in real traffic.
# {N} = random number, {R} = random region code, {H} = random hex.
CDN_PATTERNS: list[str] = [
    # Simple prefixes (depth 1)
    "cdn.",
    "static.",
    "img.",
    "api.",
    "m.",
    "www2.",
    "assets.",
    "media.",
    "edge.",
    "lb.",
    "content.",
    "download.",
    # Prefixes with numbers/hyphens (depth 1)
    "cdn{N}.",
    "edge{N}.",
    "lb{N}.",
    "node{N}.",
    "p{N}-content.",
    "content-{R}.",
    "scontent-{R}-{N}.",
    "{R}-edge.",
    "api-{R}.",
    # Deep subdomains (depth 2+)
    "e{N4}.dscf.",
    "a{N4}.g.",
    "p{N}-content.cdn.",
    "{R}.cdn.",
    "star-mini.c10r.",
    "dgw.c10r.",
    "gateway-asset.ce.",
    "mtls-security.svc.",
    "consumer.cloud.",
    "fprint-api.unifi-ai.",
]

REGIONS = ["us-east", "us-west", "eu-west", "ap-ne1", "ap-se1", "ssn1", "icn", "nrt"]


def expand_pattern(pattern: str) -> str:
    """Expand a CDN pattern with random values."""
    result = pattern
    if "{N4}" in result:
        result = result.replace("{N4}", str(random.randint(1000, 9999)))
    if "{N}" in result:
        result = result.replace("{N}", str(random.randint(1, 999)))
    if "{R}" in result:
        result = result.replace("{R}", random.choice(REGIONS))
    if "{H}" in result:
        result = result.replace("{H}", f"{random.randint(0, 0xFFFF):04x}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CDN subdomain benign data")
    parser.add_argument("--count", type=int, default=3000,
                        help="Number of Tranco base domains to use")
    parser.add_argument("--patterns-per-domain", type=int, default=3,
                        help="Number of CDN patterns to generate per base domain")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)

    # Load Tranco benign domains
    ben_path = DATA_DIR / "benign_domains.csv"
    if not ben_path.exists():
        print("benign_domains.csv not found. Run fetch_data.py first.")
        raise SystemExit(1)

    base_domains: list[tuple[str, int]] = []
    with open(ben_path) as f:
        for row in csv.DictReader(f):
            base_domains.append((row["domain"], int(row["rank"])))
            if len(base_domains) >= args.count:
                break

    print(f"Loaded {len(base_domains)} base domains from Tranco")

    # Generate CDN subdomains
    cdn_domains: list[tuple[str, int]] = []
    for base_domain, rank in base_domains:
        patterns = random.sample(CDN_PATTERNS, min(args.patterns_per_domain, len(CDN_PATTERNS)))
        for pattern in patterns:
            prefix = expand_pattern(pattern)
            cdn_domain = f"{prefix}{base_domain}"
            cdn_domains.append((cdn_domain, rank))

    print(f"Generated {len(cdn_domains)} CDN subdomain variants")

    # Save
    out_path = DATA_DIR / "cdn_benign_domains.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "rank"])
        for domain, rank in cdn_domains:
            writer.writerow([domain, rank])

    print(f"Saved -> {out_path}")

    # Show examples
    print("\nExamples:")
    for domain, rank in random.sample(cdn_domains, min(15, len(cdn_domains))):
        print(f"  {domain:50s}  (base rank: {rank})")


if __name__ == "__main__":
    main()
