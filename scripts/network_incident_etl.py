"""
Clean and enrich ServiceNow network‑incident extracts **and** emit
pipeline‑health metrics for operational monitoring.

Key additions (July 2025)
------------------------
* **Metadata logging** – row counts, data‑quality errors, and SLA‑breach rate
  are computed and pushed to a monitoring sink (DB table, CSV, or logger).
* **SLA Analysis** – detailed breach analysis for operational insights
* **Configuration Management** – externalized settings via config.py

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

# 🆕 Configuration import
from config import IMPLEMENTATION_START, BUSINESS_HOURS, SLA_TARGETS, ALERT_THRESHOLDS

# ──────────────────────────────────────────────────────────
# 0  -- LOGGER CONFIG
# ──────────────────────────────────────────────────────────
logger = logging.getLogger("network_incident_etl")
logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────
# 1  -- CONFIGURATION
# ──────────────────────────────────────────────────────────
# IMPLEMENTATION_START is now imported from config.py

class Sev(Enum):
    CRIT = "1 - Critical"
    HIGH = "2 - High"

# 🆕 Business hours from config
BUS_HOURS = pd.offsets.CustomBusinessHour(
    start=BUSINESS_HOURS["start"], 
    end=BUSINESS_HOURS["end"], 
    weekmask=BUSINESS_HOURS["weekmask"]
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

    # ---------- Column name mapping for different CSV formats ----------
    # Handle different column naming conventions
    opened_col = "opened_at" if "opened_at" in df.columns else "opened"
    resolved_col = "u_resolved" if "u_resolved" in df.columns else "resolved"
    ci_type_col = "u_ci_type" if "u_ci_type" in df.columns else "ci_type"

    # ---------- Filtering ----------
    df = df[df["assignment_group"].str.contains("network", case=False, na=False)]

    # ---------- Timestamp parsing ----------
    df["openedDate"] = pd.to_datetime(df[opened_col], errors="coerce", utc=True)
    df["resolvedDate"] = pd.to_datetime(df[resolved_col], errors="coerce", utc=True)

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
    df["patternCategory"] = _categorize_series(df["short_description"], df[ci_type_col])

    # ---------- Flags ----------
    df["isActive"] = df["incident_state"].isin(["In Progress", "On Hold", "New"])
    df["isHighImpact"] = df["priority"].isin([Sev.CRIT.value, Sev.HIGH.value])

    # ---------- Impact estimation ----------
    df["userImpactEstimate"] = _estimate_user_impact(
        df["patternCategory"], df["priority"], df["short_description"]
    )

    # ---------- SLA breach analysis ----------
    # 🆕 Using SLA targets from config
    df["slaTargetHrs"] = df["priority"].map(SLA_TARGETS).fillna(24)
    df["slaBreach"] = (df["resolutionTimeBizHrs"] > df["slaTargetHrs"]) & (
        df["resolvedDate"].notna()
    )

    return df


# ──────────────────────────────────────────────────────────
# 4  -- SLA ANALYSIS FUNCTIONS
# ──────────────────────────────────────────────────────────

def analyze_sla_breaches(df: pd.DataFrame) -> dict:
    """Generate detailed SLA breach analysis for operational review."""
    breaches = df[df['slaBreach'] == True]
    
    if len(breaches) == 0:
        return {"message": "No SLA breaches found"}
    
    analysis = {
        'total_breaches': len(breaches),
        'breach_rate': len(breaches) / len(df[df['resolvedDate'].notna()]),
        'breach_by_category': breaches['patternCategory'].value_counts().to_dict(),
        'breach_by_priority': breaches['priority'].value_counts().to_dict(),
        'avg_breach_time_hrs': breaches['resolutionTimeBizHrs'].mean(),
        'worst_cases': breaches.nlargest(5, 'resolutionTimeBizHrs')[
            ['id_hash', 'patternCategory', 'priority', 'resolutionTimeBizHrs']
        ].to_dict('records')
    }
    return analysis


def generate_alerts(df: pd.DataFrame) -> List[str]:
    """Generate operational alerts based on thresholds."""
    alerts = []
    
    # SLA breach rate alert
    resolved_incidents = df[df['resolvedDate'].notna()]
    if len(resolved_incidents) > 0:
        breach_rate = df['slaBreach'].sum() / len(resolved_incidents) * 100
        if breach_rate > ALERT_THRESHOLDS["sla_breach_rate_pct"]:
            alerts.append(f"🔴 SLA breach rate: {breach_rate:.1f}% (threshold: {ALERT_THRESHOLDS['sla_breach_rate_pct']}%)")
    
    # High impact active incidents
    active_high_impact = df[(df['isActive'] == True) & (df['isHighImpact'] == True)]
    if len(active_high_impact) > ALERT_THRESHOLDS["active_high_impact_max"]:
        alerts.append(f"⚠️ Active high impact incidents: {len(active_high_impact)} (threshold: {ALERT_THRESHOLDS['active_high_impact_max']})")
    
    # Data freshness
    if len(df) > 0:
        latest_incident = df['openedDate'].max()
        hours_since_latest = (datetime.now(timezone.utc) - latest_incident).total_seconds() / 3600
        if hours_since_latest > ALERT_THRESHOLDS["data_freshness_hrs"]:
            alerts.append(f"📅 Data freshness: {hours_since_latest:.1f} hours old (threshold: {ALERT_THRESHOLDS['data_freshness_hrs']}hrs)")
    
    # Average breach time
    breaches = df[df['slaBreach'] == True]
    if len(breaches) > 0:
        avg_breach_time = breaches['resolutionTimeBizHrs'].mean()
        if avg_breach_time > ALERT_THRESHOLDS["avg_breach_time_hrs"]:
            alerts.append(f"⏱️ Average breach time: {avg_breach_time:.1f}hrs (threshold: {ALERT_THRESHOLDS['avg_breach_time_hrs']}hrs)")
    
    return alerts


# ──────────────────────────────────────────────────────────
# 5  -- METADATA / PIPELINE‑HEALTH LOGGING
# ──────────────────────────────────────────────────────────

def _compute_metrics(df_raw: pd.DataFrame, df_clean: pd.DataFrame) -> pd.DataFrame:
    """Return a one‑row dataframe of pipeline metrics."""
    
    # Get SLA analysis
    sla_analysis = analyze_sla_breaches(df_clean)
    
    metrics = {
        "run_timestamp_utc": datetime.now(timezone.utc),
        "rows_raw": len(df_raw),
        "rows_filtered": len(df_clean),
        "pct_invalid_timestamps": (df_raw["resolved"].isna().mean().round(4) * 100),
        "neg_resolution_intervals": ((pd.to_datetime(df_raw["resolved"], errors="coerce", utc=True)
                                        < pd.to_datetime(df_raw["opened"], errors="coerce", utc=True)).sum()),
        "sla_breach_pct": (df_clean["slaBreach"].mean().round(4) * 100),
        
        # 🆕 Enhanced SLA insights
        "breach_count": sla_analysis.get('total_breaches', 0),
        "top_breach_category": list(sla_analysis.get('breach_by_category', {}).keys())[0] if sla_analysis.get('breach_by_category') else 'None',
        "avg_breach_time_hrs": round(sla_analysis.get('avg_breach_time_hrs', 0), 2),
        
        # 🆕 Operational metrics
        "active_incidents": df_clean['isActive'].sum(),
        "high_impact_incidents": df_clean['isHighImpact'].sum(),
        "data_freshness_hrs": round((datetime.now(timezone.utc) - df_clean['openedDate'].max()).total_seconds() / 3600, 2) if len(df_clean) > 0 else 0,
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
# 6  -- REPEATING‑PATTERN SUMMARY
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


# ──────────────────────────────────────────────────────────
# 7  -- MAIN EXECUTION
# ──────────────────────────────────────────────────────────

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
    output_path = os.path.join("data", "processed", f"{name_without_ext}_analysed.csv")
    
    # Ensure data/report directory exists and set metrics path
    os.makedirs(os.path.join("data", "report"), exist_ok=True)
    metrics_path = os.path.join("data", "report", "ops_metrics.csv")

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

    # 🆕 SLA Analysis with enhanced output
    print("\n" + "="*60)
    print("📊 SLA BREACH ANALYSIS")
    print("="*60)
    
    sla_analysis = analyze_sla_breaches(tidy_df)
    
    if 'message' in sla_analysis:
        print("✅ " + sla_analysis['message'])
    else:
        print(f"Total Incidents Analyzed: {len(tidy_df)}")
        print(f"Resolved Incidents: {len(tidy_df[tidy_df['resolvedDate'].notna()])}")
        print(f"SLA Breaches: {sla_analysis['total_breaches']}")
        print(f"Breach Rate: {sla_analysis['breach_rate']*100:.1f}%")
        print(f"Average Breach Time: {sla_analysis['avg_breach_time_hrs']:.1f} hours")
        
        print(f"\nTop Breach Categories:")
        for category, count in list(sla_analysis['breach_by_category'].items())[:5]:
            print(f"  {category}: {count}")
        
        print(f"\nBreaches by Priority:")
        for priority, count in sla_analysis['breach_by_priority'].items():
            print(f"  {priority}: {count}")

    # 🆕 Generate and display alerts
    alerts = generate_alerts(tidy_df)
    if alerts:
        print(f"\n⚠️ OPERATIONAL ALERTS:")
        for alert in alerts:
            print(f"  {alert}")
    else:
        print(f"\n✅ No operational alerts - system performing within thresholds")

    # Log enhanced metrics
    print(f"\n📊 Logging enhanced metrics to {metrics_path}")
    log_pipeline_metrics(raw_df, tidy_df, engine, csv_fallback=metrics_path)
    print("Processing complete!")
    print("="*60)