"""
SENTINEL AI — Authentication Anomaly Detector & Fallback Engine
Combines an Isolation Forest statistical anomaly detector with calibrated deterministic
heuristics to guarantee resilient detection even when model artifacts are unavailable.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)
from sklearn.preprocessing import StandardScaler

from common import (
    PROCESSED_DATA_DIR,
    MODELS_DIR,
    compute_sha256,
    logger
)

RANDOM_SEED = 42

FEATURE_COLS = [
    "is_failure", "is_success", "is_blocked", "is_sensitive_resource",
    "is_off_hours", "is_known_threat_ip", "window_fail_count_ip",
    "window_attempt_count_ip", "distinct_users_targeted_ip",
    "success_after_failure_seq", "fail_ratio_10m", "burst_rate_per_min"
]


class FallbackRuleEngine:
    """
    Deterministic rule-based anomaly detector serving as a resilient fallback
    when statistical ML models are unavailable or encounter corrupted input.
    """
    @staticmethod
    def evaluate(event_features: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        triggered_rules = []
        score = 0.0

        # Rule 1: High-frequency brute force
        if event_features.get("window_fail_count_ip", 0) >= 10:
            triggered_rules.append("RULE_BRUTE_FORCE_IP_THRESHOLD")
            score = max(score, 0.90)

        # Rule 2: Password Spraying across accounts
        if event_features.get("distinct_users_targeted_ip", 0) >= 4:
            triggered_rules.append("RULE_PASSWORD_SPRAY_SUSPECTED")
            score = max(score, 0.88)

        # Rule 3: Success immediately after repeated failures
        if event_features.get("success_after_failure_seq", 0) == 1:
            triggered_rules.append("RULE_SUCCESS_AFTER_REPEATED_FAILURES")
            score = max(score, 0.95)

        # Rule 4: Known malicious threat intelligence IP
        if event_features.get("is_known_threat_ip", 0) == 1:
            triggered_rules.append("RULE_THREAT_INTEL_MALICIOUS_IP")
            score = max(score, 0.92)

        # Rule 5: Rapid event burst
        if event_features.get("burst_rate_per_min", 0) >= 20.0:
            triggered_rules.append("RULE_RAPID_EVENT_BURST")
            score = max(score, 0.80)

        # Rule 6: Sensitive resource access off hours
        if event_features.get("is_sensitive_resource", 0) == 1 and event_features.get("is_off_hours", 0) == 1:
            triggered_rules.append("RULE_OFF_HOURS_SENSITIVE_RESOURCE")
            score = max(score, 0.75)

        is_anom = len(triggered_rules) > 0
        return is_anom, score, triggered_rules


def train_auth_anomaly_model() -> Dict[str, Any]:
    train_path = PROCESSED_DATA_DIR / "authentication" / "auth_train.csv"
    val_path = PROCESSED_DATA_DIR / "authentication" / "auth_val.csv"
    test_path = PROCESSED_DATA_DIR / "authentication" / "auth_test.csv"

    if not train_path.exists():
        from preprocess_authentication import preprocess_auth_dataset
        preprocess_auth_dataset()

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    X_train = df_train[FEATURE_COLS].fillna(0)
    y_train = df_train["is_anomaly"].astype(int)

    X_test = df_test[FEATURE_COLS].fillna(0)
    y_test = df_test["is_anomaly"].astype(int)

    logger.info(f"Fitting Isolation Forest on {len(X_train)} authentication event vectors...")

    # Fit scaler on normal profiles only
    normal_mask = (y_train == 0)
    scaler = StandardScaler()
    scaler.fit(X_train[normal_mask])

    X_train_norm_scaled = scaler.transform(X_train[normal_mask])

    # Isolation Forest: contamination based on normal set tolerance
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.04,
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    iso_forest.fit(X_train_norm_scaled)

    # Evaluate on test set
    X_test_scaled = scaler.transform(X_test)
    raw_scores = iso_forest.score_samples(X_test_scaled)
    # Convert anomaly score so higher = more anomalous (0 to 1)
    normalized_scores = 1.0 - (raw_scores - raw_scores.min()) / max(1e-6, (raw_scores.max() - raw_scores.min()))

    # Combine statistical model score with fallback rule engine
    hybrid_preds = []
    for idx in range(len(X_test)):
        feat_dict = X_test.iloc[idx].to_dict()
        rule_anom, rule_score, _ = FallbackRuleEngine.evaluate(feat_dict)
        stat_anom = normalized_scores[idx] >= 0.75

        # Alert if either rule matches or statistical score exceeds threshold
        is_flagged = 1 if (rule_anom or stat_anom) else 0
        hybrid_preds.append(is_flagged)

    hybrid_preds = np.array(hybrid_preds)

    tn, fp, fn, tp = confusion_matrix(y_test, hybrid_preds).ravel()
    prec = float(precision_score(y_test, hybrid_preds, zero_division=0))
    rec = float(recall_score(y_test, hybrid_preds, zero_division=0))
    f1 = float(f1_score(y_test, hybrid_preds, zero_division=0))
    fpr = float(fp / max(1, (fp + tn)))

    model_dir = MODELS_DIR / "authentication"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "auth_anomaly_detector_v1.joblib"
    scaler_path = model_dir / "auth_scaler_v1.joblib"
    meta_path = model_dir / "auth_anomaly_detector_v1_meta.json"

    # Persist model and scaler
    joblib.dump(iso_forest, model_path)
    joblib.dump(scaler, scaler_path)

    metadata = {
        "model_name": "sentinel_auth_anomaly_detector",
        "model_version": "v1.0.0",
        "model_file": str(model_path.name),
        "scaler_file": str(scaler_path.name),
        "sha256_checksum": compute_sha256(model_path),
        "algorithm": "IsolationForest + Deterministic Fallback Heuristics",
        "feature_schema_version": "v1.1",
        "features": FEATURE_COLS,
        "score_threshold": 0.75,
        "fallback_rules_available": [
            "RULE_BRUTE_FORCE_IP_THRESHOLD",
            "RULE_PASSWORD_SPRAY_SUSPECTED",
            "RULE_SUCCESS_AFTER_REPEATED_FAILURES",
            "RULE_THREAT_INTEL_MALICIOUS_IP",
            "RULE_RAPID_EVENT_BURST",
            "RULE_OFF_HOURS_SENSITIVE_RESOURCE"
        ],
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "test_precision": round(prec, 4),
            "test_recall": round(rec, 4),
            "test_f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        },
        "training_dataset": "data/processed/authentication/auth_train.csv",
        "manifest_reference": "data/manifests/auth_events_manifest.json",
        "status": "production"
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Authentication model and fallback engine saved (Test F1={f1:.4f}, FPR={fpr:.4f})")
    return metadata


if __name__ == "__main__":
    train_auth_anomaly_model()
