"""Synthetic perturbation library for the contrastive label embedder.

Generates lexical neighbors of a DNS label by applying one of several
edit operations: single-char edits, homoglyph substitutions, adjacent
swaps, hyphen insertion/deletion, suffix-focused edits, and stacked
double-edits.

Every function takes an explicit `random.Random` so training is fully
deterministic given a seed, and the trainer can regenerate positives
each epoch without leaking randomness across workers.

The contract for `generate(anchor, rng)`:
- Always returns a non-empty DNS-legal label distinct from the anchor.
- Levenshtein(anchor, result) <= 3.
- Result length in [3, 63].
- Result matches r"^[a-z0-9-]+$" with no leading or trailing hyphen.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

DNS_CHARS: str = "abcdefghijklmnopqrstuvwxyz0123456789-"
DNS_LETTERS_DIGITS: str = "abcdefghijklmnopqrstuvwxyz0123456789"
MIN_LEN: int = 3
MAX_LEN: int = 63

# Bidirectional homoglyph table. Listed as (from, to) where each direction
# is a plausible visual confusion. Per design memo: rn<->m, 0<->o, 1<->l<->i,
# vv<->w, cl<->d, nn<->m, 5<->s, 8<->b. Order here is independent — caller
# samples uniformly from this list.
HOMOGLYPHS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("m", "rn"),
    ("0", "o"),
    ("o", "0"),
    ("1", "l"),
    ("l", "1"),
    ("1", "i"),
    ("i", "1"),
    ("vv", "w"),
    ("w", "vv"),
    ("cl", "d"),
    ("nn", "m"),
    ("5", "s"),
    ("s", "5"),
    ("8", "b"),
    ("b", "8"),
]

# Probability mass per perturbation strategy. Sums to 1.0. Tuned per design:
# single-char edits dominate (they're the everyday typo class), homoglyphs
# next (load-bearing for the moodle/google class pg_trgm misses), then
# swaps/hyphen/suffix/double-edit.
PERTURB_WEIGHTS: dict[str, float] = {
    "single_edit": 0.35,
    "homoglyph": 0.25,
    "adjacent_swap": 0.15,
    "hyphen": 0.10,
    "suffix_edit": 0.10,
    "double_edit": 0.05,
}


@dataclass(frozen=True)
class PerturbResult:
    """A successful perturbation with the strategy that produced it."""

    label: str
    strategy: str


class PerturbError(RuntimeError):
    """Raised when no valid perturbation could be produced for an anchor."""


# --- DNS-validity helpers --------------------------------------------------


def is_dns_legal(label: str) -> bool:
    """Return True iff `label` is a syntactically valid DNS label.

    DNS labels must be 1-63 chars from [a-z0-9-] with no leading or
    trailing hyphen. We also enforce MIN_LEN to keep perturbations
    semantically interesting (a 1- or 2-char label has no neighbors
    worth retrieving).
    """
    if not label:
        return False
    if len(label) < MIN_LEN or len(label) > MAX_LEN:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c in DNS_CHARS for c in label)


def levenshtein(a: str, b: str) -> int:
    """Plain Levenshtein distance. Pure Python — fine for trainer use."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
        prev = curr
    return prev[-1]


# --- Single-shot operations ------------------------------------------------


def _random_dns_char(rng: random.Random, *, allow_hyphen: bool = True) -> str:
    """Pick one DNS-legal char. Hyphen included only when caller permits."""
    pool = DNS_CHARS if allow_hyphen else DNS_LETTERS_DIGITS
    return rng.choice(pool)


def op_single_edit(label: str, rng: random.Random) -> str | None:
    """Insert, delete, or substitute one char at a random position."""
    if not label:
        return None
    op = rng.choice(("insert", "delete", "substitute"))
    if op == "insert":
        pos = rng.randint(0, len(label))
        # Do not insert hyphen at position 0 or len (would create
        # leading/trailing hyphen).
        allow_hyphen = pos not in (0, len(label))
        ch = _random_dns_char(rng, allow_hyphen=allow_hyphen)
        return label[:pos] + ch + label[pos:]
    if op == "delete":
        if len(label) <= MIN_LEN:
            return None
        pos = rng.randint(0, len(label) - 1)
        return label[:pos] + label[pos + 1:]
    # substitute
    pos = rng.randint(0, len(label) - 1)
    allow_hyphen = pos not in (0, len(label) - 1)
    original = label[pos]
    # Resample if we picked the same char (no-op).
    for _ in range(8):
        ch = _random_dns_char(rng, allow_hyphen=allow_hyphen)
        if ch != original:
            return label[:pos] + ch + label[pos + 1:]
    return None


def op_homoglyph(label: str, rng: random.Random) -> str | None:
    """Apply a homoglyph substitution if the anchor contains a source pattern.

    Iterates the homoglyph table in shuffled order and applies the first
    pattern that matches. Matches are case-sensitive (input is lowercased
    upstream). If multiple positions match, picks one uniformly.
    """
    candidates = list(HOMOGLYPHS)
    rng.shuffle(candidates)
    for src, dst in candidates:
        positions = []
        idx = 0
        while True:
            found = label.find(src, idx)
            if found == -1:
                break
            positions.append(found)
            idx = found + 1
        if not positions:
            continue
        pos = rng.choice(positions)
        candidate = label[:pos] + dst + label[pos + len(src):]
        # Reject if the substitution introduced a leading/trailing hyphen.
        if candidate.startswith("-") or candidate.endswith("-"):
            continue
        return candidate
    return None


def op_adjacent_swap(label: str, rng: random.Random) -> str | None:
    """Swap two adjacent chars at a random position."""
    if len(label) < 2:
        return None
    # Try a few positions to find one that actually changes the string
    # (e.g. "aa" swaps are no-ops).
    positions = list(range(len(label) - 1))
    rng.shuffle(positions)
    for pos in positions:
        if label[pos] == label[pos + 1]:
            continue
        candidate = label[:pos] + label[pos + 1] + label[pos] + label[pos + 2:]
        if candidate.startswith("-") or candidate.endswith("-"):
            continue
        return candidate
    return None


def op_hyphen(label: str, rng: random.Random) -> str | None:
    """Insert a hyphen at a non-edge position, or remove one if present."""
    has_hyphen = "-" in label[1:-1] if len(label) >= 3 else False
    do_remove = has_hyphen and rng.random() < 0.5
    if do_remove:
        positions = [i for i in range(1, len(label) - 1) if label[i] == "-"]
        if not positions:
            return None
        pos = rng.choice(positions)
        candidate = label[:pos] + label[pos + 1:]
        return candidate if not candidate.startswith("-") and not candidate.endswith("-") else None
    # insert
    if len(label) >= MAX_LEN:
        return None
    if len(label) < 3:
        return None
    pos = rng.randint(1, len(label) - 1)
    # Avoid creating "--" by skipping positions adjacent to existing hyphens.
    if label[pos - 1] == "-" or label[pos] == "-":
        return None
    return label[:pos] + "-" + label[pos:]


def op_suffix_edit(label: str, rng: random.Random) -> str | None:
    """Apply a single-char edit constrained to the last 3 chars.

    Phishing impersonations frequently target trailing characters
    (paypa1, googie, amaz0n) — biasing some perturbations toward the
    suffix gives the embedder more exposure to that pattern.
    """
    if len(label) < MIN_LEN + 1:
        return None
    suffix_start = max(0, len(label) - 3)
    op = rng.choice(("substitute", "insert", "delete"))
    if op == "substitute":
        pos = rng.randint(suffix_start, len(label) - 1)
        allow_hyphen = pos not in (0, len(label) - 1)
        original = label[pos]
        for _ in range(8):
            ch = _random_dns_char(rng, allow_hyphen=allow_hyphen)
            if ch != original:
                return label[:pos] + ch + label[pos + 1:]
        return None
    if op == "insert":
        pos = rng.randint(suffix_start, len(label))
        allow_hyphen = pos not in (0, len(label))
        if len(label) >= MAX_LEN:
            return None
        ch = _random_dns_char(rng, allow_hyphen=allow_hyphen)
        return label[:pos] + ch + label[pos:]
    # delete
    if len(label) <= MIN_LEN:
        return None
    pos = rng.randint(suffix_start, len(label) - 1)
    return label[:pos] + label[pos + 1:]


def op_double_edit(label: str, rng: random.Random) -> str | None:
    """Stack two single_edit operations. Output capped at edit-dist <= 3."""
    first = op_single_edit(label, rng)
    if first is None or not is_dns_legal(first):
        return None
    second = op_single_edit(first, rng)
    if second is None or not is_dns_legal(second):
        return None
    if levenshtein(label, second) > 3:
        return None
    return second


_OpFn = Callable[[str, random.Random], "str | None"]
_OPS: dict[str, _OpFn] = {
    "single_edit": op_single_edit,
    "homoglyph": op_homoglyph,
    "adjacent_swap": op_adjacent_swap,
    "hyphen": op_hyphen,
    "suffix_edit": op_suffix_edit,
    "double_edit": op_double_edit,
}


# --- Top-level entrypoint --------------------------------------------------


def _sample_strategy(rng: random.Random) -> str:
    """Sample a strategy name according to PERTURB_WEIGHTS."""
    names = list(PERTURB_WEIGHTS.keys())
    weights = [PERTURB_WEIGHTS[n] for n in names]
    return rng.choices(names, weights=weights, k=1)[0]


def generate(anchor: str, rng: random.Random, *, max_attempts: int = 32) -> PerturbResult:
    """Produce one valid perturbation of `anchor`.

    Tries up to `max_attempts` strategy samples before raising. In
    practice almost every anchor produces a valid output on the first
    or second try; the retry budget exists for pathological inputs
    (e.g. a 3-char label where every operation reduces below MIN_LEN).
    """
    if not is_dns_legal(anchor):
        raise PerturbError(f"anchor not DNS-legal: {anchor!r}")
    for _ in range(max_attempts):
        strategy = _sample_strategy(rng)
        op = _OPS[strategy]
        candidate = op(anchor, rng)
        if candidate is None:
            continue
        candidate = candidate.lower()
        if not is_dns_legal(candidate):
            continue
        if candidate == anchor:
            continue
        if levenshtein(anchor, candidate) > 3:
            continue
        return PerturbResult(label=candidate, strategy=strategy)
    raise PerturbError(f"no valid perturbation after {max_attempts} attempts: {anchor!r}")


def generate_many(
    anchor: str, rng: random.Random, n: int, *, max_attempts: int = 32,
) -> list[PerturbResult]:
    """Produce `n` distinct perturbations of `anchor`.

    Distinctness is by output string — multiple strategies may produce
    the same string (e.g. single_edit and suffix_edit can collide). We
    keep sampling until we have `n` distinct results or hit the budget.
    """
    seen: set[str] = set()
    out: list[PerturbResult] = []
    budget = n * max_attempts
    while len(out) < n and budget > 0:
        budget -= 1
        try:
            result = generate(anchor, rng, max_attempts=max_attempts)
        except PerturbError:
            continue
        if result.label in seen:
            continue
        seen.add(result.label)
        out.append(result)
    if not out:
        raise PerturbError(f"could not generate any perturbations for {anchor!r}")
    return out
