"""
SENTINEL AI — Test Suite: Preprocessing & Leakage Prevention
Verifies offline lexical feature extraction, temporal and grouped splits, and target leakage absence.
"""

import sys
from pathlib import Path
import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from preprocess_phishing import extract_url_lexical_features
from preprocess_authentication import extract_auth_features


def test_url_lexical_extractor_offline():
    """Verify strictly offline feature extraction with zero HTTP requests."""
    test_url = "http://192.168.1.1:8080/secure/login.php?user=admin&token=123"
    features = extract_url_lexical_features(test_url)

    assert isinstance(features, dict)
    assert features["url_length"] == len(test_url)
    assert features["is_ip_address"] == 1
    assert features["has_non_standard_port"] == 1
    assert features["has_security_keyword"] == 1
    assert features["url_entropy"] > 0.0
    assert features["domain_group"] == "192.168.1.1"


def test_url_extractor_malformed_resilience():
    """Test extractor resilience against blank, corrupt, or malformed strings."""
    malformed_inputs = ["", "   ", "http://", "not_a_valid_url_%#@!", None]
    for inp in malformed_inputs:
        feats = extract_url_lexical_features(inp)
        assert isinstance(feats, dict)
        assert "url_length" in feats
        assert "domain_group" in feats


def test_phishing_domain_split_leakage_absence():
    """Ensure no common domain exists between phishing train and test splits."""
    proc_dir = PROJECT_ROOT / "data" / "processed" / "phishing"
    train_path = proc_dir / "phishing_train.csv"
    test_path = proc_dir / "phishing_test.csv"

    if train_path.exists() and test_path.exists():
        df_train = pd.read_csv(train_path)
        df_test = pd.read_csv(test_path)

        train_domains = set(df_train["domain_group"].dropna().unique())
        test_domains = set(df_test["domain_group"].dropna().unique())

        overlap = train_domains.intersection(test_domains)
        assert len(overlap) == 0, f"Found {len(overlap)} domain overlaps between train and test: {list(overlap)[:3]}"


def test_network_leakage_prevention():
    """Confirm identifier and ground-truth category columns are dropped from network features."""
    proc_dir = PROJECT_ROOT / "data" / "processed" / "network"
    train_path = proc_dir / "network_train.csv"

    if train_path.exists():
        df_train = pd.read_csv(train_path)
        assert "id" not in df_train.columns, "Identifier column 'id' must be dropped to prevent leakage."
        assert "ID" not in df_train.columns
        assert "attack_cat" not in df_train.columns, "Multi-class target 'attack_cat' must not leak into binary features."
        assert "label" in df_train.columns


def test_investigations_dataset_validity():
    """Verify AI investigation dataset JSONL integrity and disallowed conclusions."""
    import json
    inv_file = PROJECT_ROOT / "data" / "processed" / "investigations" / "evaluation_cases.jsonl"
    assert inv_file.exists()

    cases = []
    with open(inv_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    assert len(cases) >= 4
    for c in cases:
        assert "incident_id" in c
        assert "ground_truth_category" in c
        assert "observed_evidence" in c
        assert "expected_investigation_findings" in c
        assert "recommended_defensive_actions" in c
        assert "disallowed_conclusions" in c
        assert len(c["disallowed_conclusions"]) >= 1, "Disallowed conclusions must be explicitly constrained."
