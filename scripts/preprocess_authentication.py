"""
SENTINEL AI — Authentication Log Preprocessor & Aggregator
Extracts behavioral, sequence-level, and sliding-window features from authentication logs.
Performs chronological train/val/test splitting to prevent temporal leakage.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple
import pandas as pd
import numpy as np

from common import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    MANIFESTS_DIR,
    compute_sha256,
    save_manifest,
    logger
)
from generate_auth_events import MALICIOUS_IPS

SENSITIVE_PREFIXES = ("/admin", "/api/v1/keys", "/system")


def extract_auth_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract rolling aggregate security features from chronological authentication events."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Base indicators
    df["is_failure"] = (df["status"] == "failure").astype(int)
    df["is_success"] = (df["status"] == "success").astype(int)
    df["is_blocked"] = (df["status"] == "blocked").astype(int)

    # Sensitive resource indicator
    df["is_sensitive_resource"] = df["resource_requested"].apply(
        lambda r: 1 if any(str(r).startswith(p) for p in SENSITIVE_PREFIXES) else 0
    )

    # Time-based features
    df["hour"] = df["timestamp"].dt.hour
    df["is_off_hours"] = df["hour"].apply(lambda h: 1 if h < 6 or h >= 21 else 0)

    # IP risk indicator
    df["is_known_threat_ip"] = df["source_ip"].isin(MALICIOUS_IPS).astype(int)

    # Sliding window aggregations per Source IP (10 minutes rolling)
    df["window_fail_count_ip"] = 0
    df["window_attempt_count_ip"] = 0
    df["distinct_users_targeted_ip"] = 0
    df["success_after_failure_seq"] = 0

    # Fast rolling computation
    records = df.to_dict("records")
    ten_minutes = pd.Timedelta(minutes=10)

    for i, curr in enumerate(records):
        curr_time = curr["timestamp"]
        curr_ip = curr["source_ip"]
        curr_user = curr["user_id"]

        recent_ip_events = [
            r for r in records[max(0, i - 100):i]
            if r["source_ip"] == curr_ip and (curr_time - r["timestamp"]) <= ten_minutes
        ]

        fails = sum(r["is_failure"] for r in recent_ip_events)
        total_attempts = len(recent_ip_events) + 1
        unique_users = len(set(r["user_id"] for r in recent_ip_events).union({curr_user}))

        curr["window_fail_count_ip"] = fails
        curr["window_attempt_count_ip"] = total_attempts
        curr["distinct_users_targeted_ip"] = unique_users

        # Check success following >= 3 recent failures on same account
        if curr["status"] == "success" and fails >= 3:
            curr["success_after_failure_seq"] = 1
        else:
            curr["success_after_failure_seq"] = 0

    feat_df = pd.DataFrame(records)
    feat_df["fail_ratio_10m"] = (feat_df["window_fail_count_ip"] / feat_df["window_attempt_count_ip"]).round(4)
    feat_df["burst_rate_per_min"] = (feat_df["window_attempt_count_ip"] / 10.0).round(2)

    return feat_df


def preprocess_auth_dataset(raw_csv_path: Path = None) -> Tuple[Path, Path, Path]:
    raw_auth_dir = RAW_DATA_DIR / "authentication"
    raw_auth_dir.mkdir(parents=True, exist_ok=True)

    if raw_csv_path is None or not raw_csv_path.exists():
        raw_csv_path = raw_auth_dir / "auth_events_synthetic.csv"
        if not raw_csv_path.exists():
            from generate_auth_events import generate_and_save_auth_dataset
            generate_and_save_auth_dataset()

    df_raw = pd.read_csv(raw_csv_path)
    logger.info(f"Extracting temporal authentication features from {len(df_raw)} records...")
    df_feat = extract_auth_features(df_raw)

    # Feature columns for modeling
    model_cols = [
        "is_failure", "is_success", "is_blocked", "is_sensitive_resource",
        "is_off_hours", "is_known_threat_ip", "window_fail_count_ip",
        "window_attempt_count_ip", "distinct_users_targeted_ip",
        "success_after_failure_seq", "fail_ratio_10m", "burst_rate_per_min",
        "is_anomaly"
    ]

    clean_df = df_feat[model_cols].copy()

    # Chronological Split (70% train, 15% validation, 15% test)
    n = len(clean_df)
    train_end = int(0.70 * n)
    val_end = int(0.85 * n)

    train_df = clean_df.iloc[:train_end].copy()
    val_df = clean_df.iloc[train_end:val_end].copy()
    test_df = clean_df.iloc[val_end:].copy()

    processed_dir = PROCESSED_DATA_DIR / "authentication"
    processed_dir.mkdir(parents=True, exist_ok=True)

    train_path = processed_dir / "auth_train.csv"
    val_path = processed_dir / "auth_val.csv"
    test_path = processed_dir / "auth_test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    logger.info(f"Auth preprocessing completed: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")
    return train_path, val_path, test_path


if __name__ == "__main__":
    preprocess_auth_dataset()
