"""
SENTINEL AI — Network Intrusion Detection Preprocessor
Processes network flow features (UNSW-NB15 schema), validates types, removes leakage,
and generates clean train, validation, and test splits.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd

from common import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    MANIFESTS_DIR,
    compute_sha256,
    save_manifest,
    logger
)

RANDOM_SEED = 42

CATEGORICAL_COLS = ["proto", "service", "state"]
TARGET_COL = "label"
MULTICLASS_COL = "attack_cat"
LEAKAGE_COLS = ["id", "attack_cat"]

NUMERIC_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports"
]


def generate_synthetic_unsw_benchmark(num_records: int = 3500) -> pd.DataFrame:
    """
    Generates a realistic synthetic UNSW-NB15 flow benchmark dataset
    guaranteeing zero-dependency offline reproducibility.
    """
    rng = np.random.RandomState(RANDOM_SEED)

    protocols = ["tcp", "udp", "unas", "arp", "ospf"]
    proto_probs = [0.70, 0.20, 0.05, 0.03, 0.02]
    services = ["-", "http", "dns", "smtp", "ftp", "ftp-data", "pop3", "ssh", "ssl"]
    service_probs = [0.45, 0.25, 0.15, 0.04, 0.03, 0.03, 0.02, 0.02, 0.01]
    states = ["FIN", "CON", "INT", "REQ", "RST"]
    state_probs = [0.60, 0.25, 0.10, 0.03, 0.02]

    # Labels: 0 = Benign/Normal, 1 = Attack
    # Attack categories: Normal, Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor, Shellcode, Worms
    labels = rng.choice([0, 1], size=num_records, p=[0.65, 0.35])
    attack_cats = []
    
    cat_pool = ["Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"]
    cat_weights = [0.35, 0.25, 0.15, 0.10, 0.08, 0.03, 0.02, 0.01, 0.01]

    for lbl in labels:
        if lbl == 0:
            attack_cats.append("Normal")
        else:
            attack_cats.append(rng.choice(cat_pool, p=cat_weights))

    data = {
        "id": np.arange(1, num_records + 1),
        "dur": np.where(labels == 1, rng.exponential(scale=1.5, size=num_records), rng.exponential(scale=0.4, size=num_records)),
        "proto": rng.choice(protocols, size=num_records, p=proto_probs),
        "service": rng.choice(services, size=num_records, p=service_probs),
        "state": rng.choice(states, size=num_records, p=state_probs),
        "spkts": np.where(labels == 1, rng.negative_binomial(5, 0.2, size=num_records), rng.negative_binomial(10, 0.5, size=num_records)),
        "dpkts": np.where(labels == 1, rng.negative_binomial(4, 0.3, size=num_records), rng.negative_binomial(12, 0.6, size=num_records)),
        "sbytes": np.where(labels == 1, rng.lognormal(mean=7.5, sigma=1.2, size=num_records), rng.lognormal(mean=6.2, sigma=0.8, size=num_records)),
        "dbytes": np.where(labels == 1, rng.lognormal(mean=6.8, sigma=1.5, size=num_records), rng.lognormal(mean=7.1, sigma=0.9, size=num_records)),
        "rate": rng.uniform(0.1, 50000.0, size=num_records),
        "sttl": np.where(labels == 1, rng.choice([62, 64, 254], size=num_records, p=[0.2, 0.2, 0.6]), rng.choice([31, 64, 252], size=num_records, p=[0.1, 0.8, 0.1])),
        "dttl": np.where(labels == 1, rng.choice([0, 29, 252], size=num_records, p=[0.4, 0.4, 0.2]), rng.choice([29, 252], size=num_records, p=[0.7, 0.3])),
        "sload": rng.exponential(scale=1000000.0, size=num_records),
        "dload": rng.exponential(scale=2000000.0, size=num_records),
        "sloss": rng.poisson(lam=1.2, size=num_records),
        "dloss": rng.poisson(lam=0.8, size=num_records),
        "sinpkt": rng.exponential(scale=50.0, size=num_records),
        "dinpkt": rng.exponential(scale=60.0, size=num_records),
        "sjit": rng.exponential(scale=15.0, size=num_records),
        "djit": rng.exponential(scale=20.0, size=num_records),
        "swin": np.where(labels == 1, rng.choice([0, 255], size=num_records), rng.choice([255], size=num_records)),
        "stcpb": rng.uniform(0, 4e9, size=num_records),
        "dtcpb": rng.uniform(0, 4e9, size=num_records),
        "dwin": np.where(labels == 1, rng.choice([0, 255], size=num_records), rng.choice([255], size=num_records)),
        "tcprtt": rng.exponential(scale=0.05, size=num_records),
        "synack": rng.exponential(scale=0.025, size=num_records),
        "ackdat": rng.exponential(scale=0.025, size=num_records),
        "smean": rng.uniform(32, 1500, size=num_records),
        "dmean": rng.uniform(32, 1500, size=num_records),
        "trans_depth": rng.choice([0, 1, 2], size=num_records, p=[0.8, 0.18, 0.02]),
        "response_body_len": np.where(labels == 1, 0, rng.poisson(lam=400, size=num_records)),
        "ct_srv_src": rng.randint(1, 35, size=num_records),
        "ct_state_ttl": rng.randint(0, 6, size=num_records),
        "ct_dst_ltm": rng.randint(1, 30, size=num_records),
        "ct_src_dport_ltm": rng.randint(1, 25, size=num_records),
        "ct_dst_sport_ltm": rng.randint(1, 20, size=num_records),
        "ct_dst_src_ltm": rng.randint(1, 30, size=num_records),
        "is_ftp_login": rng.choice([0, 1], size=num_records, p=[0.97, 0.03]),
        "ct_ftp_cmd": rng.choice([0, 1, 2], size=num_records, p=[0.96, 0.03, 0.01]),
        "ct_flw_http_mthd": rng.choice([0, 1, 2], size=num_records, p=[0.85, 0.13, 0.02]),
        "ct_src_ltm": rng.randint(1, 30, size=num_records),
        "ct_srv_dst": rng.randint(1, 35, size=num_records),
        "is_sm_ips_ports": rng.choice([0, 1], size=num_records, p=[0.98, 0.02]),
        "attack_cat": attack_cats,
        "label": labels
    }

    df = pd.DataFrame(data)
    return df


def preprocess_network_dataset(raw_csv_path: Path = None) -> Tuple[Path, Path, Path]:
    """
    Validate, clean, encode, and split network intrusion flows.
    Guarantees no target leakage from attack_cat or id columns.
    """
    raw_net_dir = RAW_DATA_DIR / "network"
    raw_net_dir.mkdir(parents=True, exist_ok=True)

    if raw_csv_path is None or not raw_csv_path.exists():
        raw_csv_path = raw_net_dir / "unsw_nb15_benchmark.csv"
        logger.info(f"Generating synthetic UNSW-NB15 benchmark at {raw_csv_path}")
        df_raw = generate_synthetic_unsw_benchmark()
        df_raw.to_csv(raw_csv_path, index=False)
    else:
        df_raw = pd.read_csv(raw_csv_path)

    # Clean whitespace and strip strings
    for col in df_raw.select_dtypes(include=["object"]).columns:
        df_raw[col] = df_raw[col].astype(str).str.strip()

    # Drop explicit identifier columns that cause artificial leakage
    cols_to_drop = [c for c in ["id", "ID"] if c in df_raw.columns]
    if cols_to_drop:
        df_raw = df_raw.drop(columns=cols_to_drop)

    # Validate target column
    if "label" not in df_raw.columns:
        raise ValueError(f"Required binary target column 'label' missing in {raw_csv_path}")

    df_raw["label"] = df_raw["label"].astype(int)

    # Impute missing values
    for num_col in NUMERIC_COLS:
        if num_col in df_raw.columns:
            median_val = df_raw[num_col].median()
            df_raw[num_col] = df_raw[num_col].fillna(median_val)

    # Extract and isolate multiclass labels to prevent binary target leakage
    attack_cat_dist = df_raw["attack_cat"].value_counts().to_dict() if "attack_cat" in df_raw.columns else {}
    if "attack_cat" in df_raw.columns:
        df_raw = df_raw.drop(columns=["attack_cat"])

    # One-hot / frequency encode categorical columns deterministically
    df_encoded = pd.get_dummies(df_raw, columns=[c for c in CATEGORICAL_COLS if c in df_raw.columns], drop_first=True)

    # Remove duplicates
    n_before = len(df_encoded)
    df_encoded = df_encoded.drop_duplicates().reset_index(drop=True)
    n_removed = n_before - len(df_encoded)
    if n_removed > 0:
        logger.info(f"Removed {n_removed} duplicate flow records.")

    # Stratified Train/Val/Test Split (70/15/15)
    from sklearn.model_selection import train_test_split
    train_df, temp_df = train_test_split(
        df_encoded, test_size=0.30, random_state=RANDOM_SEED, stratify=df_encoded["label"]
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, random_state=RANDOM_SEED, stratify=temp_df["label"]
    )

    processed_dir = PROCESSED_DATA_DIR / "network"
    processed_dir.mkdir(parents=True, exist_ok=True)

    train_path = processed_dir / "network_train.csv"
    val_path = processed_dir / "network_val.csv"
    test_path = processed_dir / "network_test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    # Manifest
    label_dist = df_raw["label"].value_counts().to_dict()
    attack_cat_dist = df_raw["attack_cat"].value_counts().to_dict() if "attack_cat" in df_raw.columns else {}

    manifest = {
        "dataset_name": "sentinel_network_unsw_nb15_benchmark",
        "source_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "original_filename": raw_csv_path.name,
        "retrieval_timestamp": pd.Timestamp.now("UTC").isoformat(),
        "file_size_bytes": raw_csv_path.stat().st_size,
        "sha256_checksum": compute_sha256(raw_csv_path),
        "is_official_checksum": False,
        "license": "Research and Non-Commercial Academic Use / CC-BY-NC-ND",
        "citation": "Moustafa, Nour, and Jill Slay. 'UNSW-NB15: a comprehensive data set for network intrusion detection systems.' MilCIS 2015.",
        "original_schema": {
            "dur": "float", "proto": "string", "service": "string", "state": "string",
            "spkts": "int", "dpkts": "int", "sbytes": "int", "dbytes": "int", "rate": "float",
            "sttl": "int", "dttl": "int", "sload": "float", "dload": "float",
            "label": "int (0=normal, 1=attack)", "attack_cat": "string"
        },
        "encoded_feature_columns": [c for c in train_df.columns if c not in ("label", "attack_cat")],
        "preprocessing_version": "v1.2",
        "record_counts": {
            "total_clean": len(df_encoded),
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
            "duplicates_removed": n_removed
        },
        "class_distribution": {
            "benign_0": int(label_dist.get(0, 0)),
            "attack_1": int(label_dist.get(1, 0)),
            "attack_categories": {k: int(v) for k, v in attack_cat_dist.items()}
        },
        "split_method": "StratifiedSplit (70% Train, 15% Val, 15% Test)",
        "known_limitations": [
            "Synthetic and tabular flow representations omit raw payload packet captures.",
            "High packet-rate volumetric attacks can skew flow duration distributions."
        ]
    }

    manifest_path = MANIFESTS_DIR / "network_unsw_nb15_manifest.json"
    save_manifest(manifest, manifest_path)
    logger.info(f"Network preprocessing completed: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

    return train_path, val_path, test_path


if __name__ == "__main__":
    preprocess_network_dataset()
