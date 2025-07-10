"""
Clean and enrich ServiceNow network‑incident extracts **and** emit
pipeline‑health metrics for operational monitoring.

Key additions (July 2025)
------------------------
* **Metadata logging** – row counts, data‑quality errors, and SLA‑breach rate
  are computed and pushed to a monitoring sink (DB table, CSV, or logger).

Usage
-----
>>> import pandas as pd, sqlalchemy as sa
>>> from network_incident_etl import transform_incident_frame, log_pipeline_metrics
>>> raw = pd.read_csv("IM_Network_EMEA_2025.csv")
>>> tidy = transform_incident_frame(raw)
>>> engine = sa.create_engine("postgresql+psycopg2://svc:*****@dw/ops")
>>> log_pipeline_metrics(raw, tidy, engine)
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

# ──────────────────────────────────────────────────────────
# 0  -- LOGGER CONFIG
# ──────────────────────────────────────────────────────────
logger = logging.getLogger("network_incident_etl")
logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────
# 1  -- CONFIGURATION
# ──────────────────────────────────────────────────────────
IMPLEMENTATION_START = pd.Timestamp("2025-03-25", tz="UTC")

class Sev(Enum):
    CRIT = "1 - Critical"
    HIGH = "2 - High"

BUS_HOURS = pd.offsets.CustomBusinessHour(
    start="08:00", end="17:00", weekmask="Mon Tue Wed Thu Fri"
)

@dataclass(frozen=True)
class PatternSpec:
    name: str
    regexes: Tuple[str, ...]

PATTERN_MAP: List[PatternSpec] = [
    PatternSpec(
        "WiFi_Connection",
        (
            r"\bwap\b",
            r"wi[\s\-]?fi",
            r"\bconnect(?:ion)?\b",
            r"\bap[ s]down\b",
            r"access point",
            r"wireless",
            r"disconnect",
        ),
    ),
    PatternSpec(
        "Performance",
        (
            r"build failing",
            r"\bslow(?:ness)?\b",
            r"clearcase",
            r"performance",
            r"time[ -]?out",
            r"latency",
            r"response time",
            r"hang(?:ing)?",
            r"freeze",
        ),
    ),
    PatternSpec("VPN_Access", (r"\bvpn\b", r"zscaler", r"remote access", r"ipsec")),
    PatternSpec("DNS_DHCP", (r"\bdns\b", r"\bdhcp\b", r"name resolution")),
    PatternSpec(
        "Application_Access",
        (r"\bapp(?:lication)?\b", r"login", r"access denied", r"auth(?:entication)?"),
    ),
    PatternSpec(
        "Network_Infrastructure",
        (r"switch", r"\bport\b", r"\bvlan\b", r"routing", r"\bnetwork\b"),
    ),
]

# Pre‑compile regex patterns once for speed
_COMPILED_PATTERNS: List[Tuple[str, re.Pattern]] = [
    (spec.name, re.compile("|".join(spec.regexes), re.I)) for spec in PATTERN_MAP
]

# ──────────────────────────────────────────────────────────
# 2  -- CORE TRANSFORM HELPERS
# ──────────────────────────────────────────────────────────

def _categorize_series(short_desc: pd.Series, fallback_ci: pd.Series) -> pd.Series:
    """Vectorised incident categorisation."""
    out = pd.Series("Other_Network", index=short_desc.index, dtype="string")
    mask_remaining = short_desc.notna()
    for name, regex in _COMPILED_PATTERNS:
        matched = short_desc.str.contains(regex, na=False) & mask_remaining
        out.loc[matched] = name
        mask_remaining &= ~matched
        if not mask_remaining.any():
            break
    # Fill any still‑uncategorised rows with CI type if available
    out.loc[mask_remaining & fallback_ci.notna()] = fallback_ci
    return out.astype("category")


def _estimate_user_impact(
    category: pd.Series, priority: pd.Series, desc: pd.Series
) -> pd.Series:
    """Vectorised impact estimate (# users) using numpy where cascades."""
    high = priority.isin([Sev.CRIT.value, Sev.HIGH.value])
    return np.select(
        [
            desc.str.contains(r"\b(?:site|all users|entire)\b", na=False, case=False),
            (category == "WiFi_Connection"),
            (category == "Performance") & desc.str.contains("clearcase", na=False, case=False),
            (category == "Performance"),
            (category == "VPN_Access"),
            (category == "Network_Infrastructure"),
            high,
        ],
        [400, 400, 50, 25, 10, np.where(high, 100, 25), 50],
        default=10,
    )


def _business_hours_delta(start: pd.Series, end: pd.Series) -> pd.Series:
    """Business‑hours duration in hours; NaN where end is null."""
    def count_biz_hours(row):
        if pd.isnull(row['openedDate']) or pd.isnull(row['resolvedDate']):
            return np.nan
        rng = pd.date_range(row['openedDate'], row['resolvedDate'], freq=BUS_HOURS)
        return len(rng)
    return pd.DataFrame({'openedDate': start, 'resolvedDate': end}).apply(count_biz_hours, axis=1)


# ──────────────────────────────────────────────────────────
# 3  -- MAIN TRANSFORM
# ──────────────────────────────────────────────────────────

def transform_incident_frame(df_raw: pd.DataFrame) -> pd.DataFrame:
    """
    Clean, enrich and return a dashboard‑ready dataframe.
    Adds `slaTargetHrs` and `slaBreach` fields.
    """
    df = df_raw.copy()

    # ---------- Filtering ----------
    df = df[df["assignment_group"].str.contains("network", case=False, na=False)]

    # ---------- Timestamp parsing ----------
    df["openedDate"] = pd.to_datetime(df["opened"], errors="coerce", utc=True)
    df["resolvedDate"] = pd.to_datetime(df["resolved"], errors="coerce", utc=True)

    # ---------- Sanity checks ----------
    bad_ts = df["resolvedDate"] < df["openedDate"]
    if bad_ts.any():
        logger.warning("%s rows had negative resolution intervals; resolvedDate nulled.", bad_ts.sum())
        df.loc[bad_ts, "resolvedDate"] = pd.NaT

    # ---------- Derived time metrics ----------
    df["resolutionTimeHrs"] = (
        (df["resolvedDate"] - df["openedDate"]).dt.total_seconds() / 3600
    ).clip(lower=0)

    df["resolutionTimeBizHrs"] = _business_hours_delta(
        df["openedDate"], df["resolvedDate"]
    ).round(1)

    # ---------- Week bucket ----------
    df["week"] = (
        (df["openedDate"] - IMPLEMENTATION_START).dt.days // 7 + 12
    ).clip(lower=12)

    # ---------- Categorisation ----------
    df["patternCategory"] = _categorize_series(df["short_description"], df["ci_type"])

    # ---------- Flags ----------
    df["isActive"] = df["incident_state"].isin(["In Progress", "On Hold", "New"])
    df["isHighImpact"] = df["priority"].isin([Sev.CRIT.value, Sev.HIGH.value])

    # ---------- Impact estimation ----------
    df["userImpactEstimate"] = _estimate_user_impact(
        df["patternCategory"], df["priority"], df["short_description"]
    )

    # ---------- SLA breach example ----------
    SLA_TARGET_HRS = {"1 - Critical": 4, "2 - High": 8, "3 - Moderate": 16}
    df["slaTargetHrs"] = df["priority"].map(SLA_TARGET_HRS).fillna(24)
    df["slaBreach"] = (df["resolutionTimeBizHrs"] > df["slaTargetHrs"]) & (
        df["resolvedDate"].notna()
    )

    return df


# ──────────────────────────────────────────────────────────
# 4  -- METADATA / PIPELINE‑HEALTH LOGGING
# ──────────────────────────────────────────────────────────

def _compute_metrics(df_raw: pd.DataFrame, df_clean: pd.DataFrame) -> pd.DataFrame:
    """Return a one‑row dataframe of pipeline metrics."""
    metrics = {
        "run_timestamp_utc": datetime.now(timezone.utc),
        "rows_raw": len(df_raw),
        "rows_filtered": len(df_clean),
        "pct_invalid_timestamps": (
            df_raw["resolved"].isna().mean().round(4) * 100
        ),
        "neg_resolution_intervals": ((pd.to_datetime(df_raw["resolved"], errors="coerce", utc=True)
                                        < pd.to_datetime(df_raw["opened"], errors="coerce", utc=True)).sum()),
        "sla_breach_pct": (df_clean["slaBreach"].mean().round(4) * 100),
    }
    return pd.DataFrame([metrics])


def log_pipeline_metrics(
    df_raw: pd.DataFrame,
    df_clean: pd.DataFrame,
    engine=None,
    table: str = "ops_network_incident_metrics",
    csv_fallback: str | None = None,
):
    """Write pipeline‑health metrics to the specified sink.

    Parameters
    ----------
    df_raw : The pre‑filtered dataframe (original extract).
    df_clean : The dataframe after `transform_incident_frame`.
    engine : SQLAlchemy Engine or None. If provided, metrics are appended to
              `table` in the connected database.
    table : Target table name for DB sink.
    csv_fallback : Optional path; if provided and DB write fails or engine is
                   None, metrics are appended to this CSV as a second‑tier
                   fallback.
    """
    metrics_df = _compute_metrics(df_raw, df_clean)
    try:
        if engine is not None:
            metrics_df.to_sql(table, engine, if_exists="append", index=False)
            logger.info("Metrics written to database table '%s'", table)
            return
    except Exception as exc:  # noqa: BLE001
        logger.error("DB write failed: %s", exc, exc_info=True)

    if csv_fallback:
        metrics_df.to_csv(csv_fallback, mode="a", header=not pd.io.common.file_exists(csv_fallback), index=False)
        logger.info("Metrics appended to CSV fallback '%s'", csv_fallback)
    else:
        logger.warning("Metrics could not be persisted; dumping to log only:\n%s", metrics_df.to_markdown(index=False))


# ──────────────────────────────────────────────────────────
# 5  -- REPEATING‑PATTERN SUMMARY (unchanged)
# ──────────────────────────────────────────────────────────

def pattern_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Return a tidy dataframe summarising repeating patterns (≥3 occurrences)."""
    norm_desc = (
        df["short_description"].fillna("").str.lower().str.replace(r"[^a-z0-9\s]", "", regex=True)
        .str.replace(r"\s+", " ", regex=True).str.strip()
    )

    grp = (
        df.assign(norm_desc=norm_desc)
        .groupby(["patternCategory", "norm_desc"], observed=True)
        .agg(
            totalOccur=("norm_desc", "size"),
            firstSeen=("openedDate", "min"),
            lastSeen=("openedDate", "max"),
            activeIncidents=("isActive", "sum"),
            avgResolutionTime=("resolutionTimeHrs", "mean"),
        )
        .reset_index()
    )

    return grp[grp["totalOccur"] >= 3].sort_values(
        ["patternCategory", "totalOccur"], ascending=[True, False]
    )


if __name__ == "__main__":
    import pandas as pd
    import os
    import glob

    # Find any file in data/raw/
    raw_files = glob.glob(os.path.join("data", "raw", "*"))
    
    if not raw_files:
        print("No files found in data/raw/")
        exit(1)
    
    # Use the first file found (or you could process all files)
    input_path = raw_files[0]
    print(f"Processing file: {input_path}")
    
    # Generate output path based on input filename
    input_filename = os.path.basename(input_path)
    name_without_ext = os.path.splitext(input_filename)[0]
    output_path = os.path.join("data", "processed", f"{name_without_ext}_clean.csv")
    metrics_path = "ops_metrics.csv"

    # Read from data/raw, handling CSV and Excel
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".csv":
        raw_df = pd.read_csv(input_path)
    elif ext in [".xls", ".xlsx"]:
        raw_df = pd.read_excel(input_path)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")

    engine = None  # Or your actual SQLAlchemy engine if you want to test DB logging

    # Process
    tidy_df = transform_incident_frame(raw_df)

    # Save processed file to data/processed
    tidy_df.to_csv(output_path, index=False)
    print(f"Processed file saved to {output_path}")

    # Log metrics
    log_pipeline_metrics(raw_df, tidy_df, engine, csv_fallback=metrics_path)
    print(f"Metrics logged to {metrics_path} (or database if engine is set).")
