"""Feature extraction library for domain classification.

Provides Group A (lexical/semantic) feature extraction functions, constants
(seed domains, TLD classifications), and utility functions used by
build_lgb_dataset.py and other pipeline scripts.
"""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path

import tldextract

DATA_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Constants (must match nameserver-control/src/analysis/lexical.rs)
# ---------------------------------------------------------------------------

SEED_DOMAINS: list[str] = [
    # Banks
    "kbstar.com", "shinhan.com", "wooribank.com", "hanabank.com",
    "ibk.co.kr", "nhbank.com", "kfcc.co.kr", "epostbank.go.kr",
    "toss.im", "tossbank.com",
    # Government
    "gov.kr", "nts.go.kr", "mois.go.kr", "nhis.or.kr",
    "nps.or.kr", "hira.or.kr", "wetax.go.kr",
    # Portals / Messengers
    "naver.com", "daum.net", "kakao.com", "kakaocorp.com", "line.me",
    # Delivery
    "cjlogistics.com", "hanjin.co.kr", "lotteglogis.com", "epost.go.kr",
    "baemin.com",
    # Telecom
    "skt.co.kr", "kt.com", "lguplus.com",
    # E-commerce / Services
    "coupang.com", "musinsa.com", "ssg.com", "lotteon.com",
    "daangn.com", "yanolja.com", "zigbang.com", "socar.kr",
    # Cards / Insurance
    "samsungcard.com", "hyundaicard.com", "lottecard.co.kr",
]

# Extract first label from each seed for matching
SEED_LABELS: dict[str, str] = {}
for _sd in SEED_DOMAINS:
    _label = _sd.split(".")[0]
    SEED_LABELS[_label] = _sd

HIGH_RISK_TLDS: set[str] = {"tk", "ml", "ga", "cf", "gq"}

# Free/cheap TLDs heavily used for phishing
FREE_TLDS: set[str] = {"tk", "ml", "ga", "cf", "gq", "freenom"}

# New gTLDs (post-2012 ICANN expansion)
NEW_GTLDS: set[str] = {
    "xyz", "top", "club", "online", "site", "store", "website", "space",
    "fun", "icu", "buzz", "cyou", "cfd", "sbs", "quest", "bond",
    "app", "dev", "io", "ai", "tech", "cloud", "digital", "live",
    "world", "life", "today", "network", "solutions", "services",
    "shop", "blog", "page", "link", "click", "host", "vip", "win",
    "bid", "loan", "download", "racing", "stream", "review", "party",
}

# Known registrar default NS patterns
REGISTRAR_NS_PATTERNS: list[str] = [
    "registrar-servers.com", "domaincontrol.com", "name-services.com",
    "cloudflare.com", "awsdns", "googledomains.com", "dns-parking",
    "sedoparking.com", "parkingcrew.net", "bodis.com",
]


def classify_tld(tld: str) -> str:
    """Classify TLD into category: free / newgtld / gtld / cctld."""
    tld_lower = tld.lower().strip(".")
    if tld_lower in FREE_TLDS:
        return "free"
    if tld_lower in NEW_GTLDS:
        return "newgtld"
    # Traditional gTLDs
    if tld_lower in {"com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "mobi"}:
        return "gtld"
    # Everything else is ccTLD or multi-part ccTLD (co.kr, com.br, etc.)
    return "cctld"

IMPERSONATION_KEYWORDS: list[str] = [
    "naver-login", "kakao-verify", "kb-secure", "shinhan-auth",
    "hana-bank", "woori-bank", "nhis-check", "nps-verify",
    "wetax-pay", "gov-verify", "cj-delivery", "hanjin-track",
]

SERVICE_KEYWORDS: set[str] = {
    # Banking
    "card", "bank", "banking", "pay", "finance", "loan", "credit", "auth", "secure",
    # Portal
    "cafe", "blog", "mail", "login", "account", "verify", "mypage",
    # Government
    "tax", "check", "cert", "notice", "support", "apply",
    # Delivery
    "delivery", "track", "shipping", "parcel", "status",
    # General
    "official", "service", "help", "update", "center", "alert", "app",
}

# ASCII visual confusable map: multi-char → single-char
CONFUSABLE_MAP: list[tuple[str, str]] = [
    ("rn", "m"),
    ("cl", "d"),
    ("vv", "w"),
    ("nn", "m"),
]

# Single-char confusables
CONFUSABLE_SINGLES: dict[str, str] = {
    "1": "l",
    "0": "o",
}

# Top English bigram frequencies (per 10000 chars of text)
# Used as a proxy for "how English-like" a domain label looks
BIGRAM_FREQ: dict[str, int] = {
    "th": 152, "he": 128, "in": 94, "er": 94, "an": 82, "on": 73,
    "en": 72, "at": 68, "es": 68, "ed": 65, "or": 61, "ti": 59,
    "is": 57, "it": 56, "al": 54, "ar": 52, "st": 51, "to": 50,
    "nt": 49, "ng": 47, "se": 46, "ha": 44, "ou": 44, "io": 43,
    "le": 42, "no": 42, "us": 40, "re": 39, "ea": 38, "de": 38,
    "te": 38, "ne": 37, "me": 36, "as": 36, "co": 35, "nd": 35,
    "of": 35, "li": 33, "ri": 33, "ma": 32, "si": 31, "ta": 31,
    "el": 30, "ic": 30, "ra": 30, "la": 29, "ce": 28, "ro": 28,
    "ve": 28, "ch": 27, "ge": 27, "ll": 27, "ni": 27, "pe": 26,
    "ca": 26, "lo": 26, "ss": 26, "om": 25, "pa": 25, "ur": 25,
    "di": 24, "tr": 24, "be": 23, "il": 23, "na": 23, "po": 23,
    "un": 23, "ct": 22, "ho": 22, "pr": 22, "sh": 22, "so": 22,
    "ac": 21, "ad": 21, "ec": 21, "em": 21, "fo": 21, "ly": 21,
    "ot": 21, "wa": 21, "ag": 20, "am": 20, "ap": 20, "id": 20,
    "ig": 20, "iv": 20, "mo": 20, "su": 20, "ut": 20, "wi": 20,
}

VOWELS = set("aeiou")

# Brand prefix → brand name mapping for abbreviation detection
BRAND_PREFIXES: dict[str, str] = {
    "nav": "naver", "nv": "naver", "n": "naver",
    "kak": "kakao", "kk": "kakao", "k": "kakao",
    "kb": "kbstar",
    "shin": "shinhan", "sh": "shinhan",
    "woor": "woori", "wr": "woori",
    "hana": "hana", "hn": "hana",
    "dm": "daum", "d": "daum",
    "cj": "cjlogistics",
    "nh": "nhbank",
    "cp": "coupang", "coup": "coupang",
    "ms": "musinsa", "musin": "musinsa",
    "bm": "baemin", "baem": "baemin",
    "dg": "dangeun", "dang": "dangeun",
    "ss": "ssg",
    "ts": "toss",
    "sm": "samsung", "sams": "samsung",
}

# Sorted longest-first so "shin" matches before "sh"
BRAND_PREFIXES_SORTED = sorted(BRAND_PREFIXES.keys(), key=len, reverse=True)


# ---------------------------------------------------------------------------
# Core algorithms
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (matches Rust implementation)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )


def levenshtein(a: str, b: str) -> int:
    """Levenshtein edit distance (matches Rust implementation)."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    curr = [0] * (len(b) + 1)
    for i, ca in enumerate(a):
        curr[0] = i + 1
        for j, cb in enumerate(b):
            if ca == cb:
                curr[j + 1] = prev[j]
            else:
                curr[j + 1] = 1 + min(prev[j], prev[j + 1], curr[j])
        prev, curr = curr, prev
    return prev[len(b)]


def apply_confusable_normalization(label: str) -> tuple[str, int]:
    """Apply ASCII confusable normalization. Returns (normalized, substitution_count)."""
    result = label.lower()
    count = 0

    # Multi-char confusables first (order matters: "rn" before single-char)
    for pattern, replacement in CONFUSABLE_MAP:
        while pattern in result:
            result = result.replace(pattern, replacement, 1)
            count += 1

    # Single-char confusables
    for pattern, replacement in CONFUSABLE_SINGLES.items():
        while pattern in result:
            result = result.replace(pattern, replacement, 1)
            count += 1

    return result, count


def find_closest_seed(label: str) -> tuple[str | None, int, str | None]:
    """Find closest seed domain by Levenshtein distance.

    Returns (seed_domain, distance, seed_label).
    Applies normalized distance check matching Rust implementation.
    """
    if not label:
        return None, 999, None

    best_seed: str | None = None
    best_label: str | None = None
    best_dist = 999

    for seed_label, seed_domain in SEED_LABELS.items():
        dist = levenshtein(label.lower(), seed_label.lower())
        if dist < best_dist:
            best_dist = dist
            best_seed = seed_domain
            best_label = seed_label

    # Normalized distance check (matches Rust)
    if best_dist > 0 and best_label is not None:
        max_len = max(len(label), len(best_label))
        min_len = min(len(label), len(best_label))
        if best_dist * 3 > max_len or min_len < 4:
            return None, 999, None

    return best_seed, best_dist, best_label


def find_seed_substring(label: str) -> tuple[str | None, str]:
    """Check if domain label contains a seed label as exact substring.

    Returns (matched_seed_domain, position: 'prefix'|'suffix'|'middle'|'none').
    """
    label_lower = label.lower()
    for seed_label, seed_domain in SEED_LABELS.items():
        if len(seed_label) < 3:  # skip very short seeds like "kt"
            continue
        if seed_label in label_lower and label_lower != seed_label:
            if label_lower.startswith(seed_label):
                return seed_domain, "prefix"
            elif label_lower.endswith(seed_label):
                return seed_domain, "suffix"
            else:
                return seed_domain, "middle"
    return None, "none"


def check_compound_keyword(label: str, seed_label: str | None) -> bool:
    """Check if domain is seed + separator + service keyword (or reverse)."""
    if seed_label is None:
        return False
    label_lower = label.lower()
    # Remove the seed part and check remaining for service keywords
    remainder = label_lower.replace(seed_label.lower(), "", 1).strip("-._")
    parts = [p for p in remainder.replace(".", "-").replace("_", "-").split("-") if p]
    return any(part in SERVICE_KEYWORDS for part in parts)


def detect_brand_abbreviation(label: str) -> tuple[str | None, str | None]:
    """Check if label matches brand_prefix + service_keyword pattern.

    Catches patterns like ncafe (naver+cafe), kpay (kakao+pay), shcard (shinhan+card).
    Returns (brand_name, keyword) or (None, None).
    """
    label = label.lower()
    for prefix in BRAND_PREFIXES_SORTED:
        if label.startswith(prefix) and len(label) > len(prefix):
            remainder = label[len(prefix):].lstrip("-_")
            for kw in SERVICE_KEYWORDS:
                if remainder.startswith(kw):
                    return BRAND_PREFIXES[prefix], kw
    return None, None


def ngram_score(label: str) -> float:
    """Average English bigram frequency score. Higher = more English-like."""
    label = label.lower()
    alpha_only = "".join(c for c in label if c.isalpha())
    if len(alpha_only) < 2:
        return 0.0
    bigrams = [alpha_only[i : i + 2] for i in range(len(alpha_only) - 1)]
    scores = [BIGRAM_FREQ.get(bg, 0) for bg in bigrams]
    return sum(scores) / len(bigrams)


def consonant_vowel_ratio(label: str) -> float:
    """Ratio of consonants to vowels. English ~1.5, DGA much higher."""
    alpha = [c for c in label.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    vowel_count = sum(1 for c in alpha if c in VOWELS)
    consonant_count = len(alpha) - vowel_count
    if vowel_count == 0:
        return float(consonant_count)
    return consonant_count / vowel_count


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


@dataclass
class DomainFeatures:
    """All features for a single domain (v2 design).

    Strict scope separation: every feature is computed on exactly one domain
    part (registrable label, subdomain, or TLD). No mixed-scope features.

    See ml/docs/feature-design.md for full design rationale.
    """

    domain: str

    # --- Group A: Lexical (12 features, scoped by domain part) ---

    # Registrable scope (SLD label — e.g., "proton", "shinhan-verify")
    reg_entropy: float = 0.0           # Shannon entropy of SLD label
    reg_length: int = 0                # character count of SLD label
    reg_hyphen_count: int = 0          # hyphens in SLD label only
    reg_digit_count: int = 0           # digits in SLD label only
    reg_cv_ratio: float = 0.0          # consonant/vowel ratio of SLD label
    reg_ngram_score: float = 0.0       # English bigram frequency of SLD label
    reg_is_punycode: bool = False      # SLD starts with xn-- (IDN)
    reg_confusable_count: int = 0      # Unicode homoglyph substitutions in SLD

    # Subdomain scope (left of registrable — e.g., "calendar-api", "cdn.assets")
    sub_entropy: float = 0.0           # Shannon entropy of full subdomain string

    # Structural / TLD
    tld_category: str = ""             # free/newgtld/gtld/cctld (ordinal encoded)

    # --- Group B: Infrastructure (5 features, from domain_reputation) ---
    avg_auth_ttl: float | None = None  # EMA-smoothed authoritative TTL
    has_cname: bool | None = None      # CNAME record exists
    a_record_count: int | None = None  # max A records observed
    ns_name_entropy: float | None = None  # entropy of primary NS domain
    ns_name_length: int | None = None  # length of primary NS domain

    # --- Group F: Reputation (8 features) ---
    # FQDN-level (from domains table)
    fqdn_seen_days: float | None = None          # (now - domains.first_seen).days()
    fqdn_query_count: int | None = None          # domains.query_count
    # Registrable-level (from domain_reputation / Tranco)
    ns_observation_count: int | None = None       # domain_reputation.ns_observation_count
    well_known_rank_norm: float | None = None     # Tranco rank / 1M
    cname_target_entropy: float | None = None     # entropy of CNAME target string
    # NRD (from domain_reputation, enriched by Hagezi NRD lists)
    is_nrd: bool | None = None                   # domain in any NRD list
    nrd_age_days: int | None = None              # upper bound of NRD age window (7-35)
    # NS continuity. NULL when last_ns_change_at is NULL (no provider-level
    # change ever recorded — bootstrapped or genuinely stable). Tree handles
    # NULL natively. See reputation::detect_ns_change for change semantics.
    days_since_ns_change: float | None = None    # (now - last_ns_change_at).days()

    # --- Legacy fields (kept for backward compat with other scripts) ---
    tld: str = ""
    high_risk_tld: bool = False
    is_ptr_domain: bool = False

    # --- Excluded from training (label leaks / context) ---
    feed_hit_count: int = 0
    query_count: int = 0
    tranco_rank: int = 0


def extract_group_a(domain: str) -> DomainFeatures:
    """Compute Group A (lexical) features from domain name alone.

    v2 design: strict scope separation. Every feature is computed on exactly
    one domain part (registrable label, subdomain, or TLD).
    """
    f = DomainFeatures(domain=domain)

    # Parse domain
    extracted = tldextract.extract(domain)
    label = extracted.domain  # SLD label (e.g., "proton" from "calendar-api.proton.me")
    subdomain = extracted.subdomain

    # --- Registrable scope (SLD label only) ---
    f.reg_entropy = shannon_entropy(label)
    f.reg_length = len(label)
    f.reg_hyphen_count = label.count("-")
    f.reg_digit_count = sum(1 for c in label if c.isdigit())
    f.reg_cv_ratio = consonant_vowel_ratio(label)
    f.reg_ngram_score = ngram_score(label)
    f.reg_is_punycode = label.startswith("xn--")
    _, conf_count = apply_confusable_normalization(label)
    f.reg_confusable_count = conf_count

    # --- Subdomain scope ---
    if subdomain:
        f.sub_entropy = shannon_entropy(subdomain)
    else:
        f.sub_entropy = 0.0

    # --- Structural / TLD ---
    f.tld = extracted.suffix or ""
    f.tld_category = classify_tld(f.tld)

    # --- Legacy (not in training, kept for other scripts) ---
    f.high_risk_tld = f.tld in HIGH_RISK_TLDS
    domain_stripped = domain.rstrip(".")
    f.is_ptr_domain = domain_stripped.endswith(".in-addr.arpa") or domain_stripped.endswith(".ip6.arpa")

    return f


def features_to_dict(f: DomainFeatures) -> dict:
    """Convert DomainFeatures to a flat dict for DataFrame construction.

    v2: strict scope separation. Feature names match Rust ml.rs and metadata.json.
    """
    return {
        "domain": f.domain,
        # Group A: Registrable scope
        "reg_entropy": f.reg_entropy,
        "reg_length": f.reg_length,
        "reg_hyphen_count": f.reg_hyphen_count,
        "reg_digit_count": f.reg_digit_count,
        "reg_cv_ratio": f.reg_cv_ratio,
        "reg_ngram_score": f.reg_ngram_score,
        "reg_is_punycode": f.reg_is_punycode,
        "reg_confusable_count": f.reg_confusable_count,
        # Group A: Subdomain scope
        "sub_entropy": f.sub_entropy,
        # Group A: Structural / TLD
        "tld_category": f.tld_category,
        # Group B: Infrastructure (populated by build_lgb_dataset.py)
        "avg_auth_ttl": f.avg_auth_ttl,
        "has_cname": f.has_cname,
        "a_record_count": f.a_record_count,
        "ns_name_entropy": f.ns_name_entropy,
        "ns_name_length": f.ns_name_length,
        # Group F: Reputation (populated by build_lgb_dataset.py)
        "fqdn_seen_days": f.fqdn_seen_days,
        "fqdn_query_count": f.fqdn_query_count,
        "ns_observation_count": f.ns_observation_count,
        "well_known_rank_norm": f.well_known_rank_norm,
        "cname_target_entropy": f.cname_target_entropy,
        "is_nrd": f.is_nrd,
        "nrd_age_days": f.nrd_age_days,
        "days_since_ns_change": f.days_since_ns_change,
        # Legacy (not in training)
        "tld": f.tld,
        "high_risk_tld": f.high_risk_tld,
        "is_ptr_domain": f.is_ptr_domain,
        # Excluded (label leaks)
        "feed_hit_count": f.feed_hit_count,
        "query_count": f.query_count,
        "tranco_rank": f.tranco_rank,
    }


def load_tranco_ranks() -> dict[str, int]:
    """Load Tranco ranks from benign_domains.csv for metadata (excluded from training)."""
    ranks: dict[str, int] = {}
    ben_path = DATA_DIR / "benign_domains.csv"
    if ben_path.exists():
        with open(ben_path) as f:
            for row in csv.DictReader(f):
                ranks[row["domain"]] = int(row["rank"])
    cdn_path = DATA_DIR / "cdn_benign_domains.csv"
    if cdn_path.exists():
        with open(cdn_path) as f:
            for row in csv.DictReader(f):
                ranks[row["domain"]] = int(row["rank"])
    return ranks
