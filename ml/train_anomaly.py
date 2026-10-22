"""Isolation Forest baseline — Pillar 2 of zero-second detection.

Pulls per-flow features from ClickHouse (flows + flow_novelty + velocity MV)
joined with PostgreSQL domain_reputation, trains a sklearn IsolationForest,
and reports:

 1. Top-N most anomalous flows (for operator review)
 2. Feature importance via score perturbation
 3. Recall against incident_labels (if any overlap exists)
 4. Optional: write scores to detector_scores for Pillar 3 comparison

Offline only. Non-hot-path. Deterministic with --seed.

Usage (from PG + CH tunnels):
    uv run ml/train_anomaly.py --days 1
    uv run ml/train_anomaly.py --days 7 --write-scores

Tunnels assumed:
    ssh -fN -L 5433:/run/postgresql/.s.PGSQL.5432 root@127.0.0.1
    ssh -fN -L 9000:localhost:9000 root@127.0.0.1
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import clickhouse_connect
import numpy as np
import pandas as pd
import psycopg2
from sklearn.ensemble import IsolationForest

DEFAULT_PG_URL = "dbname=nameserver user=nameserver_admin host=localhost port=5433 sslmode=disable"
DEFAULT_CH_HOST = "localhost"
DEFAULT_CH_PORT = 9000
DEFAULT_CH_DB = "nameserver"

# Continuous + binary features fed to IsolationForest. Order matters — it
# defines the column order in the feature matrix (used by perturbation
# importance below).
FEATURE_COLUMNS: list[str] = [
    "is_first_contact",
    "age_minutes_at_flow",
    "total_ms",
    "response_auth_ttl",
    "dnssec_ds_present",
    "cname_chain_length",
    "resolution_path_depth",
    "response_ip_count",
    "query_count_5m",
    "distinct_profiles_5m",
    "distinct_asns_5m",
    "rep_ns_observation_count",
    "rep_total_flow_count",
    "rep_days_since_first_seen",
    "rep_is_well_known",
    "rep_is_nrd",
]


@dataclass
class Config:
    days: int
    sample_limit: int
    contamination: float
    random_state: int
    write_scores: bool
    detector_name: str
    detector_version: str


def fetch_features(ch_client: Any, cfg: Config) -> pd.DataFrame:
    """Pull per-flow features from ClickHouse, joining flows + flow_novelty +
    domain_velocity_5m. Returns a DataFrame indexed by flow_id."""
    query = f"""
        SELECT
            n.flow_id                                 AS flow_id,
            n.started_at                              AS started_at,
            n.registrable                             AS registrable,
            n.domain                                  AS domain,
            n.is_first_contact                        AS is_first_contact,
            n.age_minutes_at_flow                     AS age_minutes_at_flow,
            f.total_ms                                AS total_ms,
            f.response_auth_ttl                       AS response_auth_ttl,
            f.dnssec_ds_present                       AS dnssec_ds_present,
            length(f.cname_chain)                     AS cname_chain_length,
            length(f.resolution_path.step)            AS resolution_path_depth,
            length(f.response_ips)                    AS response_ip_count,
            coalesce(v.query_count_5m, 0)             AS query_count_5m,
            coalesce(v.distinct_profiles_5m, 0)       AS distinct_profiles_5m,
            coalesce(v.distinct_asns_5m, 0)           AS distinct_asns_5m
        FROM nameserver.flow_novelty n
        INNER JOIN nameserver.flows f ON n.flow_id = f.flow_id
        LEFT JOIN (
            SELECT
                registrable,
                toStartOfFiveMinute(window_start)    AS window_start,
                countMerge(query_count_state)       AS query_count_5m,
                uniqMerge(distinct_profiles_state)  AS distinct_profiles_5m,
                uniqMerge(distinct_asns_state)      AS distinct_asns_5m
            FROM nameserver.domain_velocity_5m
            GROUP BY registrable, window_start
        ) v ON v.registrable = n.registrable
           AND v.window_start = toStartOfFiveMinute(n.started_at)
        WHERE n.started_at >= now() - INTERVAL {cfg.days} DAY
        ORDER BY n.started_at DESC
        LIMIT {cfg.sample_limit}
    """
    result = ch_client.query(query)
    df = pd.DataFrame(result.result_rows, columns=result.column_names)
    print(f"[CH] fetched {len(df):,} flows with novelty features", flush=True)
    return df


def enrich_with_reputation(pg_url: str, df: pd.DataFrame) -> pd.DataFrame:
    """Left-join domain_reputation fields on registrable. Missing rows → NaN."""
    if df.empty:
        for col in ("rep_ns_observation_count", "rep_total_flow_count",
                    "rep_days_since_first_seen", "rep_is_well_known", "rep_is_nrd"):
            df[col] = pd.NA
        return df

    regs = df["registrable"].dropna().unique().tolist()
    if not regs:
        for col in ("rep_ns_observation_count", "rep_total_flow_count",
                    "rep_days_since_first_seen", "rep_is_well_known", "rep_is_nrd"):
            df[col] = pd.NA
        return df

    conn = psycopg2.connect(pg_url)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT registrable_domain,
               ns_observation_count,
               total_flow_count,
               EXTRACT(EPOCH FROM (NOW() - first_seen)) / 86400.0 AS days_since_first_seen,
               is_well_known,
               is_nrd
        FROM domain_reputation
        WHERE registrable_domain = ANY(%s)
        """,
        (regs,),
    )
    rep_rows = cur.fetchall()
    cur.close()
    conn.close()

    rep_df = pd.DataFrame(
        rep_rows,
        columns=[
            "registrable",
            "rep_ns_observation_count",
            "rep_total_flow_count",
            "rep_days_since_first_seen",
            "rep_is_well_known",
            "rep_is_nrd",
        ],
    )
    print(f"[PG] fetched reputation for {len(rep_df):,} registrables", flush=True)
    merged = df.merge(rep_df, on="registrable", how="left")
    return merged


def build_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Select FEATURE_COLUMNS, cast to float, fill missing with column median."""
    X = df[FEATURE_COLUMNS].copy()
    for col in FEATURE_COLUMNS:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    medians = X.median(numeric_only=True)
    X = X.fillna(medians)
    # Final safety net — any feature still entirely NaN → 0
    X = X.fillna(0.0)
    return X.to_numpy(dtype=np.float64)


def train_isolation_forest(
    X: np.ndarray, cfg: Config
) -> tuple[IsolationForest, np.ndarray]:
    model = IsolationForest(
        n_estimators=200,
        contamination=cfg.contamination,
        max_samples="auto",
        random_state=cfg.random_state,
        n_jobs=-1,
    )
    model.fit(X)
    # decision_function: higher = more normal. Invert + normalize to [0, 1]
    # where 1 = most anomalous.
    raw = -model.decision_function(X)
    lo, hi = raw.min(), raw.max()
    scores = (raw - lo) / (hi - lo) if hi > lo else np.zeros_like(raw)
    return model, scores


def feature_importance_by_perturbation(
    model: IsolationForest,
    X: np.ndarray,
    baseline_scores: np.ndarray,
    feature_names: list[str],
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Measure how much each feature changes the anomaly score when permuted."""
    importances: list[tuple[str, float]] = []
    for idx, name in enumerate(feature_names):
        Xp = X.copy()
        rng.shuffle(Xp[:, idx])
        perturbed = -model.decision_function(Xp)
        lo, hi = perturbed.min(), perturbed.max()
        perturbed_norm = (
            (perturbed - lo) / (hi - lo) if hi > lo else np.zeros_like(perturbed)
        )
        importance = float(np.mean(np.abs(baseline_scores - perturbed_norm)))
        importances.append((name, importance))
    out = pd.DataFrame(importances, columns=["feature", "mean_abs_score_delta"])
    return out.sort_values("mean_abs_score_delta", ascending=False).reset_index(drop=True)


def recall_against_labels(
    pg_url: str, df: pd.DataFrame, scores: np.ndarray, threshold: float
) -> dict[str, object]:
    """Recall + detection-latency gap Δt against DNS-layer incident_labels.

    Δt = label.first_seen_at − flow.started_at (both UTC). Positive Δt means
    we scored a flow malicious BEFORE the feed listed the domain — which is
    the zero-second detection north-star. Zero/negative Δt means we're
    rediscovering what the feed already knew.

    Only DNS-layer labels (layer='dns') count toward eval: URL-layer feeds
    flag paths we cannot observe at the DNS layer.
    """
    conn = psycopg2.connect(pg_url)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT domain, first_seen_at
          FROM incident_labels
         WHERE verdict = 'malicious'
           AND layer = 'dns'
        """
    )
    label_first_seen: dict[str, datetime | None] = {
        row[0]: row[1] for row in cur.fetchall()
    }
    cur.close()
    conn.close()

    df = df.copy()
    df["_anomaly"] = scores
    df["_clean_domain"] = df["domain"].str.rstrip(".")
    df["_is_labeled"] = df["_clean_domain"].isin(label_first_seen)
    labeled_rows = df[df["_is_labeled"]].copy()

    total = int(len(labeled_rows))
    if total == 0:
        return {
            "labeled_flows": 0, "recalled": 0, "recall": 0.0,
            "delta_t": None,
        }

    recalled_mask = labeled_rows["_anomaly"] >= threshold
    recalled = int(recalled_mask.sum())
    recall = recalled / total

    # Δt distribution across recalled flows. first_seen_at is naive vs
    # flow started_at (ClickHouse DateTime64) — force both to UTC.
    labeled_rows["_first_seen_at"] = (
        labeled_rows["_clean_domain"].map(label_first_seen)
    )
    recalled_rows = labeled_rows[recalled_mask].dropna(
        subset=["_first_seen_at", "started_at"]
    )
    delta_t_summary: dict[str, float | int] | None = None
    if not recalled_rows.empty:
        fs = pd.to_datetime(recalled_rows["_first_seen_at"], utc=True)
        st = pd.to_datetime(recalled_rows["started_at"], utc=True)
        delta = (fs - st).dt.total_seconds() / 3600.0  # hours
        delta_t_summary = {
            "n": int(len(delta)),
            "p50_hours": round(float(delta.quantile(0.50)), 2),
            "p25_hours": round(float(delta.quantile(0.25)), 2),
            "p75_hours": round(float(delta.quantile(0.75)), 2),
            "min_hours": round(float(delta.min()), 2),
            "max_hours": round(float(delta.max()), 2),
            "beat_feed_pct": round(float((delta > 0).mean() * 100), 1),
        }

    return {
        "labeled_flows": total,
        "recalled": recalled,
        "recall": round(recall, 3),
        "delta_t": delta_t_summary,
    }


def write_detector_scores(
    ch_client: Any, df: pd.DataFrame, scores: np.ndarray, cfg: Config
) -> int:
    """Insert scores into detector_scores so this run shows up in Pillar 3
    comparisons."""
    scored_at = datetime.now(timezone.utc)
    rows = [
        (
            str(df.iloc[i]["flow_id"]),
            df.iloc[i]["started_at"].to_pydatetime() if hasattr(df.iloc[i]["started_at"], "to_pydatetime") else df.iloc[i]["started_at"],
            cfg.detector_name,
            cfg.detector_version,
            float(scores[i]),
            "",
            "",
            scored_at,
            "",
        )
        for i in range(len(df))
    ]
    ch_client.insert(
        "nameserver.detector_scores",
        rows,
        column_names=[
            "flow_id",
            "started_at",
            "detector_name",
            "detector_version",
            "score",
            "verdict",
            "features_fingerprint",
            "scored_at",
            "notes",
        ],
    )
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=1, help="Lookback window in days")
    parser.add_argument("--sample-limit", type=int, default=500_000)
    parser.add_argument("--contamination", type=float, default=0.01,
                        help="Expected fraction of anomalies (default 0.01 = 1 percent)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold", type=float, default=0.7,
                        help="Anomaly score threshold for recall reporting")
    parser.add_argument("--write-scores", action="store_true",
                        help="Persist scores to detector_scores table")
    parser.add_argument("--detector-name", default="isolation_forest_novelty")
    parser.add_argument("--detector-version", default="v1")
    args = parser.parse_args()

    cfg = Config(
        days=args.days,
        sample_limit=args.sample_limit,
        contamination=args.contamination,
        random_state=args.seed,
        write_scores=args.write_scores,
        detector_name=args.detector_name,
        detector_version=args.detector_version,
    )

    pg_url = os.environ.get("PGURL", DEFAULT_PG_URL)
    ch_host = os.environ.get("CH_HOST", DEFAULT_CH_HOST)
    ch_port = int(os.environ.get("CH_PORT", "18123"))
    ch_db = os.environ.get("CH_DB", DEFAULT_CH_DB)

    # clickhouse-connect speaks HTTP (default 18123 via tunnel convention —
    # see ml/backfill_reputation.py). Override with CH_PORT env var.
    ch_client = clickhouse_connect.get_client(
        host=ch_host,
        port=ch_port,
        database=ch_db,
    )

    print(f"Config: days={cfg.days} sample_limit={cfg.sample_limit:,} "
          f"contamination={cfg.contamination} seed={cfg.random_state}", flush=True)

    df = fetch_features(ch_client, cfg)
    if df.empty:
        print("No flows in window. Exiting.", flush=True)
        return 0

    df = enrich_with_reputation(pg_url, df)
    X = build_feature_matrix(df)
    print(f"Feature matrix: shape={X.shape} dtype={X.dtype}", flush=True)

    model, scores = train_isolation_forest(X, cfg)
    print(f"Trained IsolationForest: n_estimators=200 "
          f"contamination={cfg.contamination}", flush=True)

    df_out = df.copy()
    df_out["anomaly_score"] = scores
    top = df_out.sort_values("anomaly_score", ascending=False).head(20)
    print("\nTop 20 anomalies:")
    show_cols = [
        "domain", "registrable", "anomaly_score",
        "is_first_contact", "age_minutes_at_flow",
        "query_count_5m", "distinct_profiles_5m",
    ]
    print(top[show_cols].to_string(index=False), flush=True)

    rng = np.random.default_rng(cfg.random_state)
    importance = feature_importance_by_perturbation(
        model, X, scores, FEATURE_COLUMNS, rng
    )
    print("\nFeature importance (mean |Δ score| under permutation):")
    print(importance.to_string(index=False), flush=True)

    recall_stats = recall_against_labels(pg_url, df, scores, args.threshold)
    print(f"\nRecall @ threshold={args.threshold}: {recall_stats}", flush=True)

    if cfg.write_scores:
        n = write_detector_scores(ch_client, df_out, scores, cfg)
        print(f"\nWrote {n:,} rows to detector_scores as "
              f"'{cfg.detector_name}/{cfg.detector_version}'", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
