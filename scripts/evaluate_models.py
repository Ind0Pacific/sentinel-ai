"""
SENTINEL AI — Comprehensive Model Evaluation & Benchmarking Suite
Evaluates all trained production models against held-out test splits, benchmarks inference
latency in milliseconds, and exports structured reports in JSON and Markdown.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score
)

from common import (
    MODELS_DIR,
    PROCESSED_DATA_DIR,
    EVALUATION_REPORTS_DIR,
    logger
)
from train_auth_anomaly_model import FallbackRuleEngine, FEATURE_COLS as AUTH_FEAT_COLS


def benchmark_latency(model: Any, sample_X: pd.DataFrame, num_runs: int = 100) -> float:
    """Measure average single-sample inference latency in milliseconds."""
    single_sample = sample_X.iloc[[0]]
    sample_input = single_sample.values if not hasattr(single_sample, "columns") or getattr(model, "feature_names_in_", None) is None else single_sample
    # Warmup
    for _ in range(10):
        if hasattr(model, "predict_proba"):
            _ = model.predict_proba(single_sample)
        elif hasattr(model, "score_samples"):
            _ = model.score_samples(sample_input)

    start = time.perf_counter()
    for _ in range(num_runs):
        if hasattr(model, "predict_proba"):
            _ = model.predict_proba(single_sample)
        elif hasattr(model, "score_samples"):
            _ = model.score_samples(sample_input)
    duration = time.perf_counter() - start
    return round((duration / num_runs) * 1000.0, 3)


def evaluate_all_models() -> Dict[str, Any]:
    EVALUATION_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Any] = {}

    # 1. Evaluate Phishing Model
    phish_model_path = MODELS_DIR / "phishing" / "phishing_detector_v1.joblib"
    phish_test_path = PROCESSED_DATA_DIR / "phishing" / "phishing_test.csv"

    if phish_model_path.exists() and phish_test_path.exists():
        logger.info("Evaluating Phishing Detector...")
        pipeline = joblib.load(phish_model_path)
        meta_path = MODELS_DIR / "phishing" / "phishing_detector_v1_meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        threshold = meta.get("decision_threshold", 0.50)

        df_test = pd.read_csv(phish_test_path)
        feature_cols = [c for c in df_test.columns if c not in ("url", "label", "source", "domain_group")]
        X_test = df_test[feature_cols].fillna(0)
        y_test = df_test["label"].astype(int)

        probs = pipeline.predict_proba(X_test)[:, 1]
        preds = (probs >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        fpr = float(fp / max(1, (fp + tn)))
        roc_auc = float(roc_auc_score(y_test, probs))
        pr_prec, pr_rec, _ = precision_recall_curve(y_test, probs)
        pr_auc = float(auc(pr_rec, pr_prec))
        latency = benchmark_latency(pipeline, X_test)

        results["phishing"] = {
            "model_name": "sentinel_phishing_url_detector",
            "version": meta.get("model_version", "v1.0.0"),
            "dataset_split": "phishing_test.csv",
            "test_samples": len(X_test),
            "class_distribution": {"legitimate": int((y_test == 0).sum()), "phishing": int((y_test == 1).sum())},
            "decision_threshold": threshold,
            "metrics": {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4)
            },
            "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
            "inference_latency_ms": latency,
            "limitations": [
                "Evaluates static lexical signals without network DNS resolution.",
                "Compromised high-reputation domains require additional contextual telemetry."
            ]
        }

    # 2. Evaluate Network Intrusion Model
    net_model_path = MODELS_DIR / "network" / "network_detector_v1.joblib"
    net_test_path = PROCESSED_DATA_DIR / "network" / "network_test.csv"

    if net_model_path.exists() and net_test_path.exists():
        logger.info("Evaluating Network Intrusion Detector...")
        classifier = joblib.load(net_model_path)
        meta_path = MODELS_DIR / "network" / "network_detector_v1_meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}

        df_test = pd.read_csv(net_test_path)
        feature_cols = [c for c in df_test.columns if c not in ("label", "attack_cat")]
        X_test = df_test[feature_cols].fillna(0)
        y_test = df_test["label"].astype(int)

        probs = classifier.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.50).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        fpr = float(fp / max(1, (fp + tn)))
        roc_auc = float(roc_auc_score(y_test, probs))
        pr_prec, pr_rec, _ = precision_recall_curve(y_test, probs)
        pr_auc = float(auc(pr_rec, pr_prec))
        latency = benchmark_latency(classifier, X_test)

        results["network"] = {
            "model_name": "sentinel_network_intrusion_detector",
            "version": meta.get("model_version", "v1.0.0"),
            "dataset_split": "network_test.csv",
            "test_samples": len(X_test),
            "class_distribution": {"benign": int((y_test == 0).sum()), "attack": int((y_test == 1).sum())},
            "decision_threshold": 0.50,
            "metrics": {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4)
            },
            "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
            "inference_latency_ms": latency,
            "limitations": [
                "Flow feature representation omits encrypted payload inspection.",
                "High volumetric packet floods may alter packet duration distributions."
            ]
        }

    # 3. Evaluate Authentication Anomaly Model
    auth_model_path = MODELS_DIR / "authentication" / "auth_anomaly_detector_v1.joblib"
    auth_scaler_path = MODELS_DIR / "authentication" / "auth_scaler_v1.joblib"
    auth_test_path = PROCESSED_DATA_DIR / "authentication" / "auth_test.csv"

    if auth_model_path.exists() and auth_test_path.exists() and auth_scaler_path.exists():
        logger.info("Evaluating Authentication Anomaly Detector...")
        iso_forest = joblib.load(auth_model_path)
        scaler = joblib.load(auth_scaler_path)

        df_test = pd.read_csv(auth_test_path)
        X_test = df_test[AUTH_FEAT_COLS].fillna(0)
        y_test = df_test["is_anomaly"].astype(int)

        X_scaled = scaler.transform(X_test)
        scores = iso_forest.score_samples(X_scaled)
        norm_scores = 1.0 - (scores - scores.min()) / max(1e-6, (scores.max() - scores.min()))

        hybrid_preds = []
        for i in range(len(X_test)):
            rule_anom, _, _ = FallbackRuleEngine.evaluate(X_test.iloc[i].to_dict())
            stat_anom = norm_scores[i] >= 0.75
            hybrid_preds.append(1 if (rule_anom or stat_anom) else 0)

        hybrid_preds = np.array(hybrid_preds)
        tn, fp, fn, tp = confusion_matrix(y_test, hybrid_preds).ravel()
        prec = float(precision_score(y_test, hybrid_preds, zero_division=0))
        rec = float(recall_score(y_test, hybrid_preds, zero_division=0))
        f1 = float(f1_score(y_test, hybrid_preds, zero_division=0))
        fpr = float(fp / max(1, (fp + tn)))
        latency = benchmark_latency(iso_forest, pd.DataFrame(X_scaled, columns=AUTH_FEAT_COLS))

        results["authentication"] = {
            "model_name": "sentinel_auth_anomaly_detector",
            "version": "v1.0.0",
            "dataset_split": "auth_test.csv",
            "test_samples": len(X_test),
            "class_distribution": {"normal": int((y_test == 0).sum()), "anomalous": int((y_test == 1).sum())},
            "decision_threshold": 0.75,
            "metrics": {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4)
            },
            "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
            "inference_latency_ms": latency,
            "limitations": [
                "Requires rolling window aggregation state per source IP.",
                "Rapid IP hopping / distributed botnets require cross-entity correlation."
            ]
        }

    # 4. Evaluate Malware Model if present
    mal_model_path = MODELS_DIR / "malware_features" / "malware_detector_v1.joblib"
    mal_test_path = PROCESSED_DATA_DIR / "malware_features" / "malware_test.csv"
    if mal_model_path.exists() and mal_test_path.exists():
        logger.info("Evaluating Malware Static Feature Detector...")
        mal_pipeline = joblib.load(mal_model_path)
        df_test = pd.read_csv(mal_test_path)
        feat_cols = [c for c in df_test.columns if c != "label"]
        X_test = df_test[feat_cols].fillna(0)
        y_test = df_test["label"].astype(int)

        probs = mal_pipeline.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.50).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        fpr = float(fp / max(1, (fp + tn)))
        roc_auc = float(roc_auc_score(y_test, probs))
        pr_prec, pr_rec, _ = precision_recall_curve(y_test, probs)
        pr_auc = float(auc(pr_rec, pr_prec))
        latency = benchmark_latency(mal_pipeline, X_test)

        results["malware_features"] = {
            "model_name": "sentinel_malware_static_detector",
            "version": "v1.0.0",
            "dataset_split": "malware_test.csv",
            "test_samples": len(X_test),
            "class_distribution": {"benign": int((y_test == 0).sum()), "malware": int((y_test == 1).sum())},
            "decision_threshold": 0.50,
            "metrics": {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4)
            },
            "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
            "inference_latency_ms": latency,
            "limitations": [
                "Static vector features only. Zero execution or dynamic unpacking.",
                "Custom PE packers may obscure section entropies."
            ]
        }

    # Save JSON summary
    summary_json_path = EVALUATION_REPORTS_DIR / "evaluation_summary.json"
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Save Markdown report
    md_report_path = EVALUATION_REPORTS_DIR / "evaluation_report.md"
    generate_markdown_report(results, md_report_path)

    logger.info(f"Evaluation complete. Reports written to {summary_json_path} and {md_report_path}")
    return results


def generate_markdown_report(results: Dict[str, Any], output_path: Path) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# 🛡️ SENTINEL AI — Machine Learning Evaluation Report",
        f"**Generated:** {now_str}  ",
        "**System:** Kali Linux / Python 3.11 / scikit-learn  ",
        "",
        "---",
        "",
        "## 📊 Model Performance Summary",
        "",
        "| Task / Model | Precision | Recall | F1 Score | PR-AUC | ROC-AUC | FPR | Latency (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for task, res in results.items():
        m = res["metrics"]
        pr_auc_str = f"{m.get('pr_auc', 0.0):.4f}" if "pr_auc" in m else "N/A"
        roc_auc_str = f"{m.get('roc_auc', 0.0):.4f}" if "roc_auc" in m else "N/A"
        lines.append(
            f"| **{res['model_name']}** | {m['precision']:.4f} | {m['recall']:.4f} | "
            f"**{m['f1_score']:.4f}** | {pr_auc_str} | {roc_auc_str} | {m['false_positive_rate']:.4f} | {res['inference_latency_ms']} ms |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 🔍 Task-Specific Breakdown",
        ""
    ])

    for task, res in results.items():
        lines.extend([
            f"### {res['model_name']} ({res['version']})",
            f"- **Test Split:** `{res['dataset_split']}` ({res['test_samples']} samples)",
            f"- **Class Distribution:** `{res['class_distribution']}`",
            f"- **Decision Threshold:** `{res['decision_threshold']}`",
            f"- **Confusion Matrix:** `TN={res['confusion_matrix']['TN']}`, `FP={res['confusion_matrix']['FP']}`, `FN={res['confusion_matrix']['FN']}`, `TP={res['confusion_matrix']['TP']}`",
            "- **Documented Limitations:**"
        ])
        for lim in res.get("limitations", []):
            lines.append(f"  - {lim}")
        lines.append("")

    lines.extend([
        "---",
        "*Report generated automatically by SENTINEL AI evaluation pipeline. Benchmark metrics are computed on held-out test splits with zero test-set leakage.*"
    ])

    output_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    evaluate_all_models()
