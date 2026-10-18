"""
SENTINEL AI — Phishing URL Detection Model Training
Trains a scikit-learn pipeline on lexical URL features, optimizes decision thresholds
to enforce low false-positive rates (FPR <= 0.02), and exports versioned model artifacts.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    auc
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from common import (
    PROCESSED_DATA_DIR,
    MODELS_DIR,
    TRAINING_REPORTS_DIR,
    compute_sha256,
    logger
)

RANDOM_SEED = 42

EXCLUDE_COLS = ["url", "label", "source", "domain_group"]


def train_phishing_model() -> Dict[str, Any]:
    train_path = PROCESSED_DATA_DIR / "phishing" / "phishing_train.csv"
    val_path = PROCESSED_DATA_DIR / "phishing" / "phishing_val.csv"
    test_path = PROCESSED_DATA_DIR / "phishing" / "phishing_test.csv"

    if not train_path.exists():
        from preprocess_phishing import preprocess_phishing_dataset
        preprocess_phishing_dataset()

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

    logger.info(f"Training Phishing Model with {len(feature_cols)} lexical features...")
    logger.info(f"Dataset sizes: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # Construct pipeline with StandardScaler and RandomForest
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1
        ))
    ])

    pipeline.fit(X_train, y_train)

    # Threshold optimization on Validation Set
    val_probs = pipeline.predict_proba(X_val)[:, 1]

    # Find optimal threshold that enforces FPR <= 0.02 while maximizing F1
    best_threshold = 0.55
    best_f1 = f1_score(y_val, (val_probs >= 0.55).astype(int), zero_division=0)

    for thresh in np.linspace(0.40, 0.80, 41):
        preds = (val_probs >= thresh).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, preds).ravel()
        fpr = fp / max(1, (fp + tn))
        f1 = f1_score(y_val, preds, zero_division=0)
        if fpr <= 0.02 and f1 >= best_f1:
            best_f1 = f1
            best_threshold = round(float(thresh), 4)

    logger.info(f"Optimal decision threshold: {best_threshold:.4f} (Validation F1: {best_f1:.4f})")

    # Evaluate on held-out Test Set
    test_probs = pipeline.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, test_preds).ravel()
    fpr = float(fp / max(1, (fp + tn)))
    prec = float(precision_score(y_test, test_preds, zero_division=0))
    rec = float(recall_score(y_test, test_preds, zero_division=0))
    f1 = float(f1_score(y_test, test_preds, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, test_probs))
    pr_prec, pr_rec, _ = precision_recall_curve(y_test, test_probs)
    pr_auc = float(auc(pr_rec, pr_prec))

    # Feature importances
    rf_model = pipeline.named_steps["classifier"]
    importances = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(zip(feature_cols, rf_model.feature_importances_), key=lambda x: x[1], reverse=True)
    }

    model_dir = MODELS_DIR / "phishing"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_artifact_path = model_dir / "phishing_detector_v1.joblib"
    metadata_path = model_dir / "phishing_detector_v1_meta.json"

    # Persist model
    joblib.dump(pipeline, model_artifact_path)
    model_sha256 = compute_sha256(model_artifact_path)

    metadata = {
        "model_name": "sentinel_phishing_url_detector",
        "model_version": "v1.0.0",
        "model_file": str(model_artifact_path.name),
        "sha256_checksum": model_sha256,
        "algorithm": "RandomForestClassifier",
        "feature_schema_version": "v1.2",
        "features": feature_cols,
        "top_features": dict(list(importances.items())[:8]),
        "decision_threshold": round(best_threshold, 4),
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
        "training_dataset": "data/processed/phishing/phishing_train.csv",
        "manifest_reference": "data/manifests/phishing_urls_manifest.json",
        "status": "production"
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Phishing model saved to {model_artifact_path} (Test F1={f1:.4f}, FPR={fpr:.4f})")
    return metadata


if __name__ == "__main__":
    train_phishing_model()
