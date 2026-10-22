"""confidence_active scorer — [0, 1] estimate that a flow's resolution
reflects the domain being ACTIVELY malicious (not cleaned up / parked /
sinkholed at query time).

Motivation (`project_bulk_resolution_contamination.md` +
`project_resolution_injector.md`): our prior training set was 99.9%
from a single bulk-resolve session whose responses were mostly post-
cleanup (NODATA / sinkhole IPs). A model trained on those flows
memorizes the cleanup signature rather than the attack signature.
This scorer lets the training pipeline drop such rows.

Rule-based and transparent on purpose. LightGBM-style models that
learn the same distinction from features would need high-quality
labels for "cleaned up" vs "active" — which is exactly what we don't
have. A hand-built rule set that we can inspect and iterate on is
more honest for Stage 1.

Inputs are read from `build_detector_dataset.py`'s parquet row:
  rcode, response_ip_count, response_ips, auth_ttl, rep_ns_trust

The scorer starts at 0.5 (neutral) and moves up on signs of active
malicious resolution, down on signs of cleanup. Clamped to [0, 1].

Training usage:
  df['confidence_active'] = df.apply(score_row, axis=1)
  df = df[(df['label'] != 1.0) | (df['confidence_active'] >= THRESHOLD)]

Only positives (label=1) get filtered — for benign rows the
post-cleanup signals are less meaningful (a benign domain showing
NODATA is normal for many legitimate rarely-resolved services).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from parking_cidrs import ip_in_parking

# Default threshold: rows at 0.5 (neutral) aren't informative enough
# as positives. Below 0.3 is actively suspicious.
DEFAULT_POSITIVE_THRESHOLD = 0.5


def _iter_ips(value: Any) -> Iterable[str]:
    """Normalize the response_ips cell into an iterable of strings.

    ClickHouse arrays round-trip to pandas as list-of-str, but may show
    up as numpy arrays, Python lists, or None depending on how the
    parquet was built.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        # Shouldn't happen for this column but guard anyway.
        return (value,) if value else ()
    try:
        return tuple(str(x) for x in value)
    except TypeError:
        return ()


def score_row(row: Mapping[str, Any]) -> float:
    """Score a single row. `row` is dict-like (pandas Series works)."""
    score = 0.5

    rcode = str(row.get("rcode") or "")
    ip_count = int(row.get("response_ip_count") or 0)
    ips = list(_iter_ips(row.get("response_ips")))
    auth_ttl = int(row.get("auth_ttl") or 0)
    ns_trust = str(row.get("rep_ns_trust") or "")

    # --- Strong negatives (cleanup / takedown signature) --------------
    # NOERROR with 0 IPs = NODATA / sinkhole / cleanup.
    if rcode == "NOERROR" and ip_count == 0:
        score -= 0.40
    # NXDOMAIN — could be takedown or genuinely dead. Weaker signal.
    elif rcode == "NXDOMAIN":
        score -= 0.20

    # Any response IP in curated parking/sinkhole CIDRs = cleanup.
    # Using `any` because a parked domain often has 1-2 parking IPs
    # alongside maybe zero or stray IPs.
    if ips and any(ip_in_parking(ip) for ip in ips):
        score -= 0.50

    # --- Positive signals (looks like active malicious) ---------------
    if ip_count >= 1 and not any(ip_in_parking(ip) for ip in ips):
        score += 0.20

    # Fast TTL is weakly correlated with dynamic / fast-flux malicious
    # infra; we only nudge, not dominate.
    if 0 < auth_ttl < 300:
        score += 0.10

    # NS trust hint: 'unknown' / 'new' NS providers over-index for
    # malicious behavior. 'stable' / 'known_provider' is a weak BENIGN
    # signal — but we don't subtract for it because legit-looking NS
    # on compromised subdomains is exactly the attack we want to
    # catch.
    if ns_trust in ("unknown", "new", "registrar_default"):
        score += 0.10

    # Clamp.
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score


# --- Tests -------------------------------------------------------------
# Run with: uv run python -m pytest ml/confidence_active.py -q
# Or as a script: uv run python ml/confidence_active.py


def _test_nodata_scores_low() -> None:
    """NOERROR with 0 IPs → strong cleanup signal, score should drop well
    below 0.5."""
    assert score_row({"rcode": "NOERROR", "response_ip_count": 0, "response_ips": []}) <= 0.2


def _test_parked_ip_scores_very_low() -> None:
    """Response landing on GoDaddy parking → very low score."""
    row = {
        "rcode": "NOERROR",
        "response_ip_count": 1,
        "response_ips": ["76.223.1.2"],
        "auth_ttl": 3600,
    }
    assert score_row(row) <= 0.1


def _test_active_response_scores_high() -> None:
    """Response on a non-parking IP with short TTL and unknown NS →
    score comfortably above neutral."""
    row = {
        "rcode": "NOERROR",
        "response_ip_count": 2,
        "response_ips": ["8.8.8.8", "1.1.1.1"],
        "auth_ttl": 60,
        "rep_ns_trust": "unknown",
    }
    assert score_row(row) >= 0.8


def _test_nxdomain_mild_penalty() -> None:
    """NXDOMAIN penalty is weaker than NODATA+parking."""
    s = score_row({"rcode": "NXDOMAIN", "response_ip_count": 0, "response_ips": []})
    assert 0.25 <= s <= 0.35


if __name__ == "__main__":
    for fn in (
        _test_nodata_scores_low,
        _test_parked_ip_scores_very_low,
        _test_active_response_scores_high,
        _test_nxdomain_mild_penalty,
    ):
        fn()
        print(f"ok  {fn.__name__}")
    print("all confidence_active tests passed")
