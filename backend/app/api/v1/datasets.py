"""
SENTINEL AI — Datasets API Endpoints
Serves dataset manifests, records metadata, data quality results, and provenance.
"""

import json
from pathlib import Path
from typing import List
from fastapi import APIRouter, HTTPException

from app.core.config import MANIFESTS_DIR, REPORTS_DIR
from app.schemas.dataset import DatasetSummary, DatasetDetail

router = APIRouter(prefix="/datasets", tags=["Datasets"])


@router.get("", response_model=List[DatasetSummary])
def list_datasets():
    """List all registered dataset manifests and their provenance metadata."""
    results = []
    if not MANIFESTS_DIR.exists():
        return results

    manifest_files = list(MANIFESTS_DIR.glob("*_manifest.json"))
    for mf in sorted(manifest_files):
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
            dataset_id = mf.stem.replace("_manifest", "")
            results.append(DatasetSummary(
                id=dataset_id,
                dataset_name=data.get("dataset_name", dataset_id),
                source_url=data.get("source_url", "unknown"),
                license=data.get("license", "unknown"),
                record_counts=data.get("record_counts", 0),
                sha256_checksum=data.get("sha256_checksum", ""),
                retrieval_timestamp=data.get("retrieval_timestamp"),
                known_limitations=data.get("known_limitations", [])
            ))
        except Exception:
            continue
    return results


@router.get("/{dataset_id}", response_model=DatasetDetail)
def get_dataset(dataset_id: str):
    """Retrieve full manifest details and data quality metrics for a specific dataset ID."""
    manifest_path = MANIFESTS_DIR / f"{dataset_id}_manifest.json"
    if not manifest_path.exists():
        # Try alternate matching without suffix
        matches = list(MANIFESTS_DIR.glob(f"*{dataset_id}*_manifest.json"))
        if matches:
            manifest_path = matches[0]
        else:
            raise HTTPException(status_code=404, detail=f"Dataset manifest '{dataset_id}' not found.")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Load data quality report if present
    quality_file = REPORTS_DIR / "data_quality" / "data_quality_report.json"
    quality_data = None
    if quality_file.exists():
        try:
            q_all = json.loads(quality_file.read_text(encoding="utf-8"))
            quality_data = q_all.get(f"{dataset_id}_train") or q_all.get(dataset_id)
        except Exception:
            pass

    return DatasetDetail(
        id=dataset_id,
        dataset_name=data.get("dataset_name", dataset_id),
        source_url=data.get("source_url", "unknown"),
        original_filename=data.get("original_filename"),
        file_size_bytes=data.get("file_size_bytes"),
        sha256_checksum=data.get("sha256_checksum", ""),
        license=data.get("license", "unknown"),
        retrieval_timestamp=data.get("retrieval_timestamp"),
        original_schema=data.get("original_schema"),
        preprocessing_version=data.get("preprocessing_version"),
        record_counts=data.get("record_counts"),
        class_distribution=data.get("class_distribution"),
        missing_value_counts=data.get("missing_value_counts"),
        known_limitations=data.get("known_limitations", []),
        data_quality_report=quality_data
    )
