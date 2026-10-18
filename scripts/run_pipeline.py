"""
SENTINEL AI — Master Pipeline Orchestrator
Coordinates end-to-end data ingestion, validation, preprocessing, model training,
benchmarking, and model registry registration in both lightweight and full modes.
"""

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from common import logger, REPORTS_DIR
from download_datasets import run_download_pipeline
from validate_datasets import validate_all_processed_datasets
from preprocess_phishing import preprocess_phishing_dataset
from preprocess_network import preprocess_network_dataset
from preprocess_authentication import preprocess_auth_dataset
from preprocess_malware import preprocess_malware_dataset
from train_phishing_model import train_phishing_model
from train_network_model import train_network_model
from train_auth_anomaly_model import train_auth_anomaly_model
from train_malware_model import train_malware_model
from evaluate_models import evaluate_all_models
from register_models import scan_and_register_all_models


def execute_full_pipeline(mode: str = "lightweight") -> Dict[str, Any]:
    start_total = time.perf_counter()
    pipeline_run_id = f"PIPE-{int(time.time())}"
    logger.info(f"=== STARTING SENTINEL AI PIPELINE [{pipeline_run_id}] (Mode: {mode.upper()}) ===")

    stages_report = []

    def record_stage(name: str, func, *args, **kwargs):
        st = time.perf_counter()
        logger.info(f">> Running Stage: {name}...")
        try:
            res = func(*args, **kwargs)
            duration = round(time.perf_counter() - st, 2)
            stages_report.append({"stage": name, "status": "COMPLETED", "duration_seconds": duration})
            logger.info(f">> Stage '{name}' completed in {duration}s")
            return res
        except Exception as e:
            duration = round(time.perf_counter() - st, 2)
            stages_report.append({"stage": name, "status": "FAILED", "error": str(e), "duration_seconds": duration})
            logger.error(f">> Stage '{name}' FAILED in {duration}s: {e}")
            raise e

    # Stage 1: Ingestion & Generation
    is_offline = (mode == "lightweight")
    record_stage("1. Data Ingestion & Synthetic Generation", run_download_pipeline, offline=is_offline, full=(mode == "full"))

    # Stage 2: Preprocessing
    record_stage("2.1 Preprocess Phishing URLs", preprocess_phishing_dataset)
    record_stage("2.2 Preprocess Network Flows", preprocess_network_dataset)
    record_stage("2.3 Preprocess Auth Logs", preprocess_auth_dataset)
    record_stage("2.4 Preprocess Malware Static Vectors", preprocess_malware_dataset)

    # Stage 3: Data Quality Validation
    record_stage("3. Data Quality Validation", validate_all_processed_datasets)

    # Stage 4: Model Training
    record_stage("4.1 Train Phishing Detector", train_phishing_model)
    record_stage("4.2 Train Network Intrusion Detector", train_network_model)
    record_stage("4.3 Train Authentication Anomaly Detector", train_auth_anomaly_model)
    record_stage("4.4 Train Malware Static Detector", train_malware_model)

    # Stage 5: Evaluation & Benchmarking
    eval_results = record_stage("5. Model Evaluation & Latency Benchmarks", evaluate_all_models)

    # Stage 6: Model Registry Registration
    registry_res = record_stage("6. Model Registry Registration", scan_and_register_all_models)

    total_duration = round(time.perf_counter() - start_total, 2)
    logger.info(f"=== SENTINEL AI PIPELINE FINISHED IN {total_duration}s ===")

    run_summary = {
        "pipeline_run_id": pipeline_run_id,
        "mode": mode,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "total_duration_seconds": total_duration,
        "stages": stages_report,
        "active_models_count": len(registry_res.get("models", {})),
        "status": "SUCCESS"
    }

    # Save run summary report
    import json
    report_file = REPORTS_DIR / "training" / f"pipeline_run_{pipeline_run_id}.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(run_summary, f, indent=2)

    return run_summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL AI Pipeline Runner")
    parser.add_argument("--mode", choices=["lightweight", "full"], default="lightweight",
                        help="lightweight (instant offline reproducible) or full (download external)")
    args = parser.parse_args()

    try:
        summary = execute_full_pipeline(mode=args.mode)
        print("\n" + "=" * 50)
        print(f"PIPELINE RUN COMPLETED: {summary['status']} ({summary['total_duration_seconds']}s)")
        print(f"Registered Models: {summary['active_models_count']}")
        for stg in summary["stages"]:
            print(f" - [{stg['status']}] {stg['stage']} ({stg['duration_seconds']}s)")
        print("=" * 50)
    except Exception as err:
        print(f"\nPipeline execution failed: {err}")
        sys.exit(1)
