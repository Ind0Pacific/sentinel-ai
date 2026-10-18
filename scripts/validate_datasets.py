"""
SENTINEL AI — Dataset Quality Validation Suite
Enforces schema validation, missingness checks, duplicate detection, and leakage checks.
Generates structured quality reports in reports/data_quality/.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

from common import (
    PROCESSED_DATA_DIR,
    QUALITY_REPORTS_DIR,
    logger
)


def validate_dataframe_quality(
    df: pd.DataFrame,
    dataset_name: str,
    required_cols: List[str],
    target_col: str,
    max_missing_ratio: float = 0.05
) -> Dict[str, Any]:
    """Execute quality gates against a dataset split."""
    total_records = len(df)
    issues: List[str] = []

    # 1. Required column check
    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        issues.append(f"Missing required columns: {missing_cols}")

    # 2. Missing values check
    missing_counts = df.isnull().sum()
    missing_ratios = (missing_counts / max(1, total_records)).to_dict()
    high_missing = {k: v for k, v in missing_ratios.items() if v > max_missing_ratio}
    if high_missing:
        issues.append(f"Columns exceeding missing threshold ({max_missing_ratio*100}%): {high_missing}")

    # 3. Duplicate checks
    dup_count = int(df.duplicated().sum())
    if dup_count > 0:
        issues.append(f"Found {dup_count} full duplicate rows.")

    # 4. Target column check
    target_valid = False
    class_balance = {}
    if target_col in df.columns:
        unique_targets = df[target_col].dropna().unique()
        if len(unique_targets) < 2:
            issues.append(f"Target column '{target_col}' has fewer than 2 distinct classes: {unique_targets}")
        else:
            target_valid = True
            class_balance = {str(k): int(v) for k, v in df[target_col].value_counts().items()}
    else:
        issues.append(f"Target column '{target_col}' missing from dataset.")

    # 5. Data leakage check: check if any feature has suspicious 1.0 correlation with target
    leakage_suspects = []
    if target_valid:
        numeric_df = df.select_dtypes(include=["number"])
        if target_col in numeric_df.columns:
            for col in numeric_df.columns:
                if col != target_col:
                    corr = numeric_df[col].corr(numeric_df[target_col])
                    if abs(corr) >= 0.999:
                        leakage_suspects.append(f"{col} (corr={corr:.4f})")
    if leakage_suspects:
        issues.append(f"Potential target leakage detected: {leakage_suspects}")

    quality_passed = len(issues) == 0

    return {
        "dataset_name": dataset_name,
        "validation_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records": total_records,
        "total_columns": len(df.columns),
        "passed_quality_gates": quality_passed,
        "duplicate_rows": dup_count,
        "class_balance": class_balance,
        "issues_flagged": issues,
        "missing_ratios": {k: round(v, 4) for k, v in missing_ratios.items() if v > 0}
    }


def validate_all_processed_datasets() -> Dict[str, Any]:
    QUALITY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    summary: Dict[str, Any] = {}

    # Validate Phishing splits
    phish_train_path = PROCESSED_DATA_DIR / "phishing" / "phishing_train.csv"
    if phish_train_path.exists():
        df_p = pd.read_csv(phish_train_path)
        p_res = validate_dataframe_quality(
            df_p, "phishing_train",
            required_cols=["url_length", "hostname_length", "url_entropy", "label"],
            target_col="label"
        )
        summary["phishing_train"] = p_res

    # Validate Network splits
    net_train_path = PROCESSED_DATA_DIR / "network" / "network_train.csv"
    if net_train_path.exists():
        df_n = pd.read_csv(net_train_path)
        n_res = validate_dataframe_quality(
            df_n, "network_train",
            required_cols=["dur", "spkts", "dpkts", "sbytes", "dbytes", "label"],
            target_col="label"
        )
        summary["network_train"] = n_res

    # Validate Authentication splits
    auth_train_path = PROCESSED_DATA_DIR / "authentication" / "auth_train.csv"
    if auth_train_path.exists():
        df_a = pd.read_csv(auth_train_path)
        a_res = validate_dataframe_quality(
            df_a, "auth_train",
            required_cols=["is_failure", "window_fail_count_ip", "burst_rate_per_min", "is_anomaly"],
            target_col="is_anomaly"
        )
        summary["auth_train"] = a_res

    # Validate Malware splits
    mal_train_path = PROCESSED_DATA_DIR / "malware_features" / "malware_train.csv"
    if mal_train_path.exists():
        df_m = pd.read_csv(mal_train_path)
        m_res = validate_dataframe_quality(
            df_m, "malware_train",
            required_cols=["size_bytes", "byte_entropy", "label"],
            target_col="label"
        )
        summary["malware_train"] = m_res

    report_path = QUALITY_REPORTS_DIR / "data_quality_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info(f"Data quality report saved to {report_path}")
    return summary


if __name__ == "__main__":
    validate_all_processed_datasets()
