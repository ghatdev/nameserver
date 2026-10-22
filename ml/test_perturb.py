"""Unit tests for perturb.py.

Run with:
    uv run python -m pytest ml/test_perturb.py -v
or as a script:
    uv run python ml/test_perturb.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import perturb  # noqa: E402


def _check_invariants(anchor: str, result: perturb.PerturbResult) -> None:
    """Assertions every successful perturbation must satisfy."""
    assert perturb.is_dns_legal(result.label), (
        f"not DNS-legal: anchor={anchor!r} result={result.label!r}"
    )
    assert result.label != anchor, f"identity output: {anchor!r}"
    dist = perturb.levenshtein(anchor, result.label)
    assert dist <= 3, (
        f"edit distance {dist} > 3: anchor={anchor!r} result={result.label!r}"
    )
    assert dist >= 1, "edit distance must be >= 1 (would mean identity)"


# --- is_dns_legal ----------------------------------------------------------


def test_is_dns_legal_accepts_normal_labels():
    for s in ("google", "paypal", "google-com", "amazon", "abc123", "abc"):
        assert perturb.is_dns_legal(s), s


def test_is_dns_legal_rejects_edge_cases():
    cases = [
        "",                # empty
        "ab",              # too short (< MIN_LEN)
        "-google",         # leading hyphen
        "google-",         # trailing hyphen
        "GOOGLE",          # uppercase
        "good.le",         # contains dot
        "good_le",         # underscore
        "x" * 64,          # too long
    ]
    for s in cases:
        assert not perturb.is_dns_legal(s), s


# --- levenshtein -----------------------------------------------------------


def test_levenshtein_known_pairs():
    assert perturb.levenshtein("google", "google") == 0
    assert perturb.levenshtein("google", "g00gle") == 2
    assert perturb.levenshtein("amazon", "arnazon") == 2  # rn for m
    assert perturb.levenshtein("paypal", "paypa1") == 1
    assert perturb.levenshtein("abc", "xyz") == 3
    assert perturb.levenshtein("", "abc") == 3
    assert perturb.levenshtein("abc", "") == 3


# --- determinism -----------------------------------------------------------


def test_generate_is_deterministic_given_seed():
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    anchors = ["google", "amazon", "paypal", "weebly", "linkedin"]
    out_a = [perturb.generate(a, rng_a).label for a in anchors]
    out_b = [perturb.generate(a, rng_b).label for a in anchors]
    assert out_a == out_b


def test_generate_many_distinct():
    rng = random.Random(7)
    out = perturb.generate_many("google", rng, n=10)
    labels = {r.label for r in out}
    # We asked for 10 distinct results — there are far more than 10
    # neighbors at edit distance <= 3 for "google", so we should get
    # close to the requested count.
    assert len(labels) >= 5
    for r in out:
        _check_invariants("google", r)


# --- per-strategy invariants -----------------------------------------------


def _force_strategy(strategy: str, anchor: str, seeds: range) -> list[str]:
    """Run `strategy` directly across many seeds and collect non-None outputs."""
    op = perturb._OPS[strategy]
    results: list[str] = []
    for seed in seeds:
        rng = random.Random(seed)
        out = op(anchor, rng)
        if out is not None:
            results.append(out)
    return results


def test_single_edit_preserves_invariants():
    outputs = _force_strategy("single_edit", "google", range(200))
    assert outputs, "single_edit should produce at least some outputs"
    for out in outputs:
        if not perturb.is_dns_legal(out) or out == "google":
            continue  # caller in generate() filters these
        assert perturb.levenshtein("google", out) <= 1


def test_homoglyph_preserves_invariants():
    # Anchor must contain a homoglyph source pattern.
    outputs = _force_strategy("homoglyph", "amazon", range(50))
    assert outputs, "amazon contains 'm' so homoglyph must produce outputs"
    for out in outputs:
        # 'm' -> 'rn' adds 1 char, edit distance 2.
        assert perturb.levenshtein("amazon", out) <= 2


def test_homoglyph_returns_none_when_no_match():
    rng = random.Random(0)
    # "xyzxyz" contains no homoglyph source pattern.
    assert perturb.op_homoglyph("xyzxyz", rng) is None


def test_adjacent_swap_invariants():
    outputs = _force_strategy("adjacent_swap", "google", range(50))
    assert outputs
    for out in outputs:
        # Adjacent swap is always edit distance 2 (or 0 if same chars,
        # but we filter those).
        assert perturb.levenshtein("google", out) <= 2


def test_hyphen_invariants():
    outputs = _force_strategy("hyphen", "google", range(100))
    # Some seeds may produce None (e.g. tried to remove a hyphen that
    # isn't there) — that's fine, we just need *some* successes.
    assert any(outputs), "hyphen op should occasionally succeed for 'google'"
    for out in outputs:
        assert perturb.is_dns_legal(out)


def test_double_edit_bounded():
    outputs = _force_strategy("double_edit", "google", range(100))
    for out in outputs:
        # double_edit is the only strategy that can reach distance 3.
        assert perturb.levenshtein("google", out) <= 3


# --- known-pair smoke tests ------------------------------------------------


def test_homoglyph_can_produce_known_phishing_pairs():
    """Ensure the homoglyph table covers the load-bearing cases."""
    # m -> rn: amazon -> arnazon
    found_rn = False
    for seed in range(200):
        rng = random.Random(seed)
        out = perturb.op_homoglyph("amazon", rng)
        if out == "arnazon":
            found_rn = True
            break
    assert found_rn, "homoglyph table must support amazon -> arnazon"

    # 0 <-> o: google -> g00gle (needs both 'o's substituted, which is
    # one homoglyph call per 'o' — single call only does one position).
    # We accept either 'go0gle' or 'g0ogle' from a single call.
    found_zero = False
    for seed in range(200):
        rng = random.Random(seed)
        out = perturb.op_homoglyph("google", rng)
        if out in ("go0gle", "g0ogle"):
            found_zero = True
            break
    assert found_zero, "homoglyph table must support google -> g0ogle / go0gle"

    # 1 <-> l: paypal -> paypa1 (last l)
    found_one = False
    for seed in range(200):
        rng = random.Random(seed)
        out = perturb.op_homoglyph("paypal", rng)
        if out == "paypa1":
            found_one = True
            break
    assert found_one, "homoglyph table must support paypal -> paypa1"


# --- edge cases ------------------------------------------------------------


def test_short_anchor_does_not_underflow():
    """A 3-char anchor (MIN_LEN) must not produce a 2-char result."""
    rng = random.Random(0)
    for _ in range(50):
        result = perturb.generate("abc", rng)
        assert len(result.label) >= perturb.MIN_LEN


def test_long_anchor_does_not_overflow():
    """A 63-char anchor must not produce a 64-char result."""
    rng = random.Random(0)
    anchor = "a" * 63
    for _ in range(50):
        result = perturb.generate(anchor, rng)
        assert len(result.label) <= perturb.MAX_LEN


def test_invalid_anchor_raises():
    rng = random.Random(0)
    try:
        perturb.generate("--invalid--", rng)
    except perturb.PerturbError:
        return
    assert False, "expected PerturbError for invalid anchor"


def test_generate_full_invariants_sweep():
    """Hammer generate() with many seeds and many anchors."""
    anchors = [
        "google", "amazon", "paypal", "weebly", "linkedin",
        "microsoft", "apple", "facebook", "netflix", "twitter",
        "abc123", "x-y-z", "mooresoft", "a" * 20,
    ]
    rng = random.Random(123)
    n_ok = 0
    for anchor in anchors:
        for _ in range(100):
            result = perturb.generate(anchor, rng)
            _check_invariants(anchor, result)
            n_ok += 1
    assert n_ok == len(anchors) * 100


# --- main ------------------------------------------------------------------


def main() -> int:
    """Run all tests when invoked as a script."""
    test_funcs = [
        v for k, v in globals().items()
        if callable(v) and k.startswith("test_")
    ]
    failures: list[tuple[str, BaseException]] = []
    for fn in test_funcs:
        try:
            fn()
            print(f"ok  {fn.__name__}")
        except AssertionError as e:
            failures.append((fn.__name__, e))
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            failures.append((fn.__name__, e))
            print(f"ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(test_funcs) - len(failures)}/{len(test_funcs)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
