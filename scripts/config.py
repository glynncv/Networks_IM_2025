"""
Pipeline configuration - modify thresholds here instead of hardcoding
"""

import pandas as pd

# ──────────────────────────────────────────────────────────
# TIMELINE CONFIGURATION
# ──────────────────────────────────────────────────────────

IMPLEMENTATION_START = pd.Timestamp("2025-03-25", tz="UTC")

# ──────────────────────────────────────────────────────────
# BUSINESS HOURS CONFIGURATION
# ──────────────────────────────────────────────────────────

BUSINESS_HOURS = {
    "start": "08:00",
    "end": "17:00", 
    "weekmask": "Mon Tue Wed Thu Fri"
}

# ──────────────────────────────────────────────────────────
# SLA TARGETS (hours)
# ──────────────────────────────────────────────────────────

SLA_TARGETS = {
    "1 - Critical": 4,
    "2 - High": 8, 
    "3 - Moderate": 16,
    "4 - Low": 24  # You might want to increase this to 72 based on analysis
}

# ──────────────────────────────────────────────────────────
# ALERTING THRESHOLDS
# ──────────────────────────────────────────────────────────

ALERT_THRESHOLDS = {
    "sla_breach_rate_pct": 60,        # Alert if breach rate > 60%
    "invalid_timestamps_pct": 10,     # Alert if >10% invalid timestamps
    "data_freshness_hrs": 24,         # Alert if data >24 hours old
    "active_high_impact_max": 10,     # Alert if >10 active high impact incidents
    "avg_breach_time_hrs": 100        # Alert if avg breach time >100 hours
}

# ──────────────────────────────────────────────────────────
# PIPELINE PROCESSING SETTINGS
# ──────────────────────────────────────────────────────────

PROCESSING = {
    "min_pattern_occurrences": 3,     # Minimum occurrences for pattern analysis
    "week_offset": 12,                # Week number offset for reporting
    "default_sla_hours": 24           # Default SLA for unknown priorities
}