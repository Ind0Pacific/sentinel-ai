"""
SENTINEL AI — Test Suite: Schemas & Manifests
Validates dataset manifest structures, required metadata, integrity checksums, and licensing.
"""

import json
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = PROJECT_ROOT / "data" / "manifests"


def test_manifest_files_exist():
    assert MANIFESTS_DIR.exists(), "Manifests directory must exist"
    manifests = list(MANIFESTS_DIR.glob("*_manifest.json"))
    assert len(manifests) >= 4, f"Expected at least 4 manifests, found {len(manifests)}"


@pytest.mark.parametrize("manifest_name", [
    "auth_events_manifest.json",
    "phishing_urls_manifest.json",
    "network_unsw_nb15_manifest.json",
    "threat_intel_manifest.json",
    "investigations_manifest.json"
])
def test_manifest_schema_conformance(manifest_name):
    manifest_path = MANIFESTS_DIR / manifest_name
    assert manifest_path.exists(), f"Manifest {manifest_name} should exist"

    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Required fields per Section 4 of Master Prompt
    required_keys = [
        "dataset_name",
        "source_url",
        "original_filename",
        "retrieval_timestamp",
        "file_size_bytes",
        "sha256_checksum",
        "license",
        "citation",
        "known_limitations"
    ]

    for key in required_keys:
        assert key in data, f"Manifest {manifest_name} missing mandatory key: '{key}'"

    assert len(data["sha256_checksum"]) == 64, f"Checksum in {manifest_name} must be 64-character SHA-256 hex string"
    assert len(data["known_limitations"]) >= 1, f"Known limitations in {manifest_name} must be documented"
    assert data["license"], f"License must be explicitly defined in {manifest_name}"
