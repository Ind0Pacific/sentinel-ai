"""
SENTINEL AI — Dataset Schemas
Defines request and response models for datasets and manifests.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DatasetSummary(BaseModel):
    id: str
    dataset_name: str
    source_url: str
    license: str
    record_counts: Any
    sha256_checksum: str
    retrieval_timestamp: Optional[str] = None
    known_limitations: List[str] = Field(default_factory=list)


class DatasetDetail(DatasetSummary):
    original_filename: Optional[str] = None
    file_size_bytes: Optional[int] = None
    original_schema: Optional[Dict[str, Any]] = None
    preprocessing_version: Optional[str] = None
    class_distribution: Optional[Dict[str, Any]] = None
    missing_value_counts: Optional[Dict[str, Any]] = None
    data_quality_report: Optional[Dict[str, Any]] = None
