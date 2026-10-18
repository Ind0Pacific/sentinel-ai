"""
SENTINEL AI — Model Schemas
Defines request and response models for registered models and evaluation benchmarks.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfusionMatrix(BaseModel):
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int


class ModelMetrics(BaseModel):
    test_precision: float
    test_recall: float
    test_f1: float
    false_positive_rate: float
    test_roc_auc: Optional[float] = None
    test_pr_auc: Optional[float] = None
    confusion_matrix: Optional[Dict[str, int]] = None
    inference_latency_ms: Optional[float] = None


class ModelSummary(BaseModel):
    id: str
    model_name: str
    model_version: str
    algorithm: str
    supported_task: str
    decision_threshold: float
    status: str
    sha256_checksum: str
    training_timestamp: str


class ModelDetail(ModelSummary):
    features: List[str] = Field(default_factory=list)
    top_features: Optional[Dict[str, float]] = None
    metrics: Optional[ModelMetrics] = None
    training_dataset: Optional[str] = None
    manifest_reference: Optional[str] = None
    file_path: Optional[str] = None
