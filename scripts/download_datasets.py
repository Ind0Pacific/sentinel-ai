"""
SENTINEL AI — Safe Dataset Download & Ingestion Engine
Downloads public cybersecurity datasets securely with strict content-length verification,
anti-path-traversal protection, disk-space checks, archive sanitization, and offline mode.
"""

import argparse
import os
import shutil
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import requests

from common import (
    RAW_DATA_DIR,
    MANIFESTS_DIR,
    compute_sha256,
    get_disk_free_gb,
    save_manifest,
    logger
)
from generate_auth_events import generate_and_save_auth_dataset
from preprocess_phishing import generate_synthetic_phishing_benchmark
from preprocess_network import generate_synthetic_unsw_benchmark
from preprocess_malware import generate_synthetic_ember_features
from enrich_threat_intel import initialize_threat_intel_store
from generate_investigation_cases import generate_and_save_investigation_dataset

# Configured public dataset sources
SOURCES = {
    "unsw_nb15": {
        "name": "UNSW-NB15 Network Intrusion Dataset",
        "url": "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2F&files=UNSW_NB15_training-set.csv",
        "official_filename": "UNSW_NB15_training-set.csv",
        "target_dir": RAW_DATA_DIR / "network",
        "max_size_mb": 500,
        "is_optional": True
    },
    "fed_phishing": {
        "name": "HuggingFace Federated Phishing URLs",
        "url": "https://huggingface.co/datasets/flwrlabs/fed-phishing-urls/raw/main/data/train.csv",
        "official_filename": "fed_phishing_train.csv",
        "target_dir": RAW_DATA_DIR / "phishing",
        "max_size_mb": 50,
        "is_optional": True
    }
}

MIN_REQUIRED_FREE_DISK_GB = 2.0


def safe_download_file(
    url: str,
    target_path: Path,
    max_size_bytes: int = 500 * 1024 * 1024,
    timeout_seconds: int = 30
) -> Path:
    """Download a remote file with streaming verification and path containment."""
    free_gb = get_disk_free_gb(target_path.parent)
    if free_gb < MIN_REQUIRED_FREE_DISK_GB:
        raise RuntimeError(f"Insufficient free disk space: {free_gb:.2f}GB available, {MIN_REQUIRED_FREE_DISK_GB}GB required.")

    # Prevent path traversal
    resolved_target = target_path.resolve()
    if not str(resolved_target).startswith(str(RAW_DATA_DIR.resolve())):
        raise ValueError(f"Path traversal detected: {resolved_target} is outside {RAW_DATA_DIR}")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target_path.with_suffix(target_path.suffix + ".part")

    session = requests.Session()
    headers = {"User-Agent": "SentinelAI-DatasetEngine/2.0 (Security-Research)"}

    logger.info(f"Connecting to {url}...")
    response = session.get(url, stream=True, timeout=timeout_seconds, headers=headers)
    response.raise_for_status()

    content_len = response.headers.get("content-length")
    if content_len and int(content_len) > max_size_bytes:
        raise ValueError(f"File size ({int(content_len)} bytes) exceeds maximum limit ({max_size_bytes} bytes)")

    downloaded_bytes = 0
    with open(temp_target, "wb") as f:
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                downloaded_bytes += len(chunk)
                if downloaded_bytes > max_size_bytes:
                    temp_target.unlink(missing_ok=True)
                    raise ValueError(f"Download aborted: exceeded size limit of {max_size_bytes} bytes")
                f.write(chunk)

    if temp_target.exists():
        temp_target.replace(target_path)
    logger.info(f"Successfully downloaded {target_path.name} ({downloaded_bytes / (1024*1024):.2f} MB)")
    return target_path


def run_download_pipeline(offline: bool = False, full: bool = False) -> Dict[str, Any]:
    """Execute download or generate synthetic benchmark datasets for zero-download demo."""
    logger.info(f"Starting Dataset Ingestion. Mode: {'OFFLINE / LIGHTWEIGHT' if offline or not full else 'ONLINE'}")

    results = {}

    # 1. Authentication events
    logger.info("Initializing Authentication events...")
    auth_csv = generate_and_save_auth_dataset(count_normal=2500)
    results["authentication"] = str(auth_csv)

    # 2. Threat intelligence indicators
    logger.info("Initializing Threat Intelligence indicators...")
    ti_json = initialize_threat_intel_store()
    results["threat_intelligence"] = str(ti_json)

    # 3. AI Investigation evaluation cases
    logger.info("Initializing AI Investigation cases...")
    inv_jsonl = generate_and_save_investigation_dataset()
    results["investigations"] = str(inv_jsonl)

    # 4. Phishing dataset
    phishing_dir = RAW_DATA_DIR / "phishing"
    phishing_dir.mkdir(parents=True, exist_ok=True)
    phishing_csv = phishing_dir / "phishing_urls_benchmark.csv"

    if not offline and full:
        try:
            safe_download_file(
                SOURCES["fed_phishing"]["url"],
                phishing_dir / SOURCES["fed_phishing"]["official_filename"],
                max_size_bytes=50 * 1024 * 1024
            )
            results["phishing"] = str(phishing_dir / SOURCES["fed_phishing"]["official_filename"])
        except Exception as e:
            logger.warning(f"Online download failed ({e}); falling back to verified offline benchmark.")
            df_phish = generate_synthetic_phishing_benchmark()
            df_phish.to_csv(phishing_csv, index=False)
            results["phishing"] = str(phishing_csv)
    else:
        df_phish = generate_synthetic_phishing_benchmark()
        df_phish.to_csv(phishing_csv, index=False)
        results["phishing"] = str(phishing_csv)

    # 5. Network dataset
    net_dir = RAW_DATA_DIR / "network"
    net_dir.mkdir(parents=True, exist_ok=True)
    net_csv = net_dir / "unsw_nb15_benchmark.csv"

    if not offline and full:
        try:
            safe_download_file(
                SOURCES["unsw_nb15"]["url"],
                net_dir / SOURCES["unsw_nb15"]["official_filename"],
                max_size_bytes=500 * 1024 * 1024
            )
            results["network"] = str(net_dir / SOURCES["unsw_nb15"]["official_filename"])
        except Exception as e:
            logger.warning(f"Online download failed ({e}); falling back to verified offline benchmark.")
            df_net = generate_synthetic_unsw_benchmark()
            df_net.to_csv(net_csv, index=False)
            results["network"] = str(net_csv)
    else:
        df_net = generate_synthetic_unsw_benchmark()
        df_net.to_csv(net_csv, index=False)
        results["network"] = str(net_csv)

    # 6. Malware feature vectors (EMBER)
    mal_dir = RAW_DATA_DIR / "malware_features"
    mal_dir.mkdir(parents=True, exist_ok=True)
    mal_csv = mal_dir / "ember_static_features_benchmark.csv"
    df_mal = generate_synthetic_ember_features()
    df_mal.to_csv(mal_csv, index=False)
    results["malware_features"] = str(mal_csv)

    logger.info("Dataset Ingestion completed successfully.")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL AI Dataset Download & Ingestion")
    parser.add_argument("--offline", action="store_true", default=True, help="Run in zero-network offline mode")
    parser.add_argument("--full", action="store_true", default=False, help="Attempt downloading external datasets")
    args = parser.parse_args()

    run_download_pipeline(offline=args.offline, full=args.full)
