"""
SENTINEL AI — Network Intrusion Detection Model Training
Trains a supervised Random Forest Classifier and an Isolation Forest anomaly detector
on normalized network flow features (UNSW-NB15 schema).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from common import (
    PROCESSED_DATA_DIR,
    MODELS_DIR,
    compute_sha256,
    logger
)

RANDOM_SEED = 42
EXCLUDE_COLS = ["label", "attack_cat"]


def train_network_model() -> Dict[str, Any]:
    train_path = PROCESSED_DATA_DIR / "network" / "network_train.csv"
    val_path = PROCESSED_DATA_DIR / "network" / "network_val.csv"
    test_path = PROCESSED_DATA_DIR / "network" / "network_test.csv"

    if not train_path.exists():
        from preprocess_network import preprocess_network_dataset
        preprocess_network_dataset()

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    feature_cols = [c for c in df_train.columns if c not in EXCLUDE_COLS]

    X_train = df_train[feature_cols].fillna(0)
    y_train = df_train["label"].astype(int)

    X_val = df_val[feature_cols].fillna(0)
    y_val = df_val["label"].astype(int)

    X_test = df_test[feature_cols].fillna(0)
    y_test = df_test["label"].astype(int)

    logger.info(f"Training Network Intrusion Classifier on {len(feature_cols)} flow features...")
    logger.info(f"Dataset sizes: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    classifier = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=100,
            max_depth=14,
            min_samples_split=5,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1
        ))
    ])

    classifier.fit(X_train, y_train)

    # Train Isolation Forest on benign samples for zero-day/novel anomaly detection
    benign_X = X_train[y_train == 0]
    isolation_forest = IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    isolation_forest.fit(benign_X)

    # Test evaluation
    test_probs = classifier.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.50).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, test_preds).ravel()
    prec = float(precision_score(y_test, test_preds, zero_division=0))
    rec = float(recall_score(y_test, test_preds, zero_division=0))
    f1 = float(f1_score(y_test, test_preds, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, test_probs))
    pr_prec, pr_rec, _ = precision_recall_curve(y_test, test_probs)
    pr_auc = float(auc(pr_rec, pr_prec))
    fpr = float(fp / max(1, (fp + tn)))

    # Feature importances
    rf_step = classifier.named_steps["rf"]
    importances = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(zip(feature_cols, rf_step.feature_importances_), key=lambda x: x[1], reverse=True)
    }

    model_dir = MODELS_DIR / "network"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "network_detector_v1.joblib"
    iforest_path = model_dir / "network_isolation_forest_v1.joblib"
    meta_path = model_dir / "network_detector_v1_meta.json"

    # Persist model artifacts
    joblib.dump(classifier, model_path)
    joblib.dump(isolation_forest, iforest_path)

    metadata = {
        "model_name": "sentinel_network_intrusion_detector",
        "model_version": "v1.0.0",
        "model_file": str(model_path.name),
        "anomaly_detector_file": str(iforest_path.name),
        "sha256_checksum": compute_sha256(model_path),
        "algorithm": "RandomForestClassifier + IsolationForest",
        "feature_schema_version": "v1.2",
        "features": feature_cols,
        "top_features": dict(list(importances.items())[:8]),
        "decision_threshold": 0.50,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "test_precision": round(prec, 4),
            "test_recall": round(rec, 4),
            "test_f1": round(f1, 4),
            "test_roc_auc": round(roc_auc, 4),
            "test_pr_auc": round(pr_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        },
        "training_dataset": "data/processed/network/network_train.csv",
        "manifest_reference": "data/manifests/network_unsw_nb15_manifest.json",
        "status": "production"
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Network models saved to {model_dir} (Test F1={f1:.4f}, PR-AUC={pr_auc:.4f})")
    return metadata


if __name__ == "__main__":
    train_network_model()
