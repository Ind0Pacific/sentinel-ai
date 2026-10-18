# 🛡️ SENTINEL AI — Machine Learning Evaluation Report
**Generated:** 2026-10-18 16:09:05 UTC  
**System:** Kali Linux / Python 3.11 / scikit-learn  

---

## 📊 Model Performance Summary

| Task / Model | Precision | Recall | F1 Score | PR-AUC | ROC-AUC | FPR | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **sentinel_phishing_url_detector** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 0.0000 | 16.819 ms |
| **sentinel_network_intrusion_detector** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 0.0000 | 17.447 ms |
| **sentinel_auth_anomaly_detector** | 0.9208 | 0.9894 | **0.9538** | N/A | N/A | 0.0270 | 3.721 ms |
| **sentinel_malware_static_detector** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 0.0000 | 17.12 ms |

---

## 🔍 Task-Specific Breakdown

### sentinel_phishing_url_detector (v1.0.0)
- **Test Split:** `phishing_test.csv` (213 samples)
- **Class Distribution:** `{'legitimate': 19, 'phishing': 194}`
- **Decision Threshold:** `0.8`
- **Confusion Matrix:** `TN=19`, `FP=0`, `FN=0`, `TP=194`
- **Documented Limitations:**
  - Evaluates static lexical signals without network DNS resolution.
  - Compromised high-reputation domains require additional contextual telemetry.

### sentinel_network_intrusion_detector (v1.0.0)
- **Test Split:** `network_test.csv` (525 samples)
- **Class Distribution:** `{'benign': 340, 'attack': 185}`
- **Decision Threshold:** `0.5`
- **Confusion Matrix:** `TN=340`, `FP=0`, `FN=0`, `TP=185`
- **Documented Limitations:**
  - Flow feature representation omits encrypted payload inspection.
  - High volumetric packet floods may alter packet duration distributions.

### sentinel_auth_anomaly_detector (v1.0.0)
- **Test Split:** `auth_test.csv` (390 samples)
- **Class Distribution:** `{'normal': 296, 'anomalous': 94}`
- **Decision Threshold:** `0.75`
- **Confusion Matrix:** `TN=288`, `FP=8`, `FN=1`, `TP=93`
- **Documented Limitations:**
  - Requires rolling window aggregation state per source IP.
  - Rapid IP hopping / distributed botnets require cross-entity correlation.

### sentinel_malware_static_detector (v1.0.0)
- **Test Split:** `malware_test.csv` (225 samples)
- **Class Distribution:** `{'benign': 133, 'malware': 92}`
- **Decision Threshold:** `0.5`
- **Confusion Matrix:** `TN=133`, `FP=0`, `FN=0`, `TP=92`
- **Documented Limitations:**
  - Static vector features only. Zero execution or dynamic unpacking.
  - Custom PE packers may obscure section entropies.

---
*Report generated automatically by SENTINEL AI evaluation pipeline. Benchmark metrics are computed on held-out test splits with zero test-set leakage.*