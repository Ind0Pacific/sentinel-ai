#!/usr/bin/env bash
# ==============================================================================
# SENTINEL AI — Kali Linux Setup & Deployment Script
# Configures virtual environment, installs pinned dependencies, checks disk space,
# tests CPU/GPU capabilities, and initializes the cybersecurity dataset pipeline.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "======================================================================"
echo "🛡️  SENTINEL AI: Kali Linux Environment Setup"
echo "======================================================================"

# 1. Verify OS and Python
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo "[+] Found Python ${PY_VER}"
else
    echo "[-] Python 3 is not installed. Please run: sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
    exit 1
fi

# 2. Check Disk Space (minimum 2.0 GB recommended)
FREE_KB=$(df -k "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
FREE_GB=$(awk "BEGIN {print $FREE_KB / 1024 / 1024}")
echo "[+] Available disk space: ${FREE_GB} GB"

if (( $(awk "BEGIN {print ($FREE_GB < 2.0)}") )); then
    echo "[!] WARNING: Less than 2 GB of free disk space available."
    read -p "Do you want to proceed anyway with lightweight mode? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborting setup."
        exit 1
    fi
fi

# 3. CPU & Optional GPU Detection
echo "[+] Detecting hardware acceleration..."
NUM_CPUS=$(nproc || echo 2)
echo "    CPU Cores available: ${NUM_CPUS} (CPU-first baseline enabled)"

if command -v nvidia-smi >/dev/null 2>&1; then
    echo "    NVIDIA GPU detected:"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader || true
else
    echo "    No discrete GPU detected. Using optimized multi-threaded CPU execution."
fi

# 4. Create and Activate Virtual Environment
VENV_PATH="${PROJECT_ROOT}/.venv"
if [ ! -d "$VENV_PATH" ]; then
    echo "[+] Creating Python virtual environment at ${VENV_PATH}..."
    python3 -m venv "$VENV_PATH"
fi

# Activate venv
# shellcheck disable=SC1091
source "${VENV_PATH}/bin/activate"

# 5. Install Dependencies
echo "[+] Upgrading pip and installing requirements..."
pip install --upgrade pip
pip install -r "${PROJECT_ROOT}/requirements.txt"

# 6. Verify Directory Tree
echo "[+] Initializing directory structure..."
python3 -c "
from pathlib import Path
root = Path('${PROJECT_ROOT}')
dirs = [
    root / 'data' / 'raw' / 'network',
    root / 'data' / 'raw' / 'phishing',
    root / 'data' / 'raw' / 'authentication',
    root / 'data' / 'raw' / 'malware_features',
    root / 'data' / 'raw' / 'threat_intelligence',
    root / 'data' / 'interim',
    root / 'data' / 'processed' / 'network',
    root / 'data' / 'processed' / 'phishing',
    root / 'data' / 'processed' / 'authentication',
    root / 'data' / 'processed' / 'malware_features',
    root / 'data' / 'processed' / 'investigations',
    root / 'data' / 'manifests',
    root / 'data' / 'quarantine',
    root / 'models' / 'network',
    root / 'models' / 'phishing',
    root / 'models' / 'authentication',
    root / 'models' / 'malware_features',
    root / 'reports' / 'data_quality',
    root / 'reports' / 'training',
    root / 'reports' / 'evaluation'
]
for d in dirs:
    d.mkdir(parents=True, exist_ok=True)
print('    Directories verified.')
"

# 7. Run Lightweight Pipeline Verification
echo "[+] Running initial lightweight pipeline verification..."
python3 "${PROJECT_ROOT}/scripts/run_pipeline.py" --mode lightweight

echo "======================================================================"
echo "✅ SENTINEL AI Setup Complete on Kali Linux!"
echo "   - To activate the environment: source .venv/bin/activate"
echo "   - To run tests: ./scripts/run_tests.sh"
echo "   - To start backend: uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
echo "======================================================================"
