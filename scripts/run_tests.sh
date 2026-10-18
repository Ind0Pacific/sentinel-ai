#!/usr/bin/env bash
# ==============================================================================
# SENTINEL AI — Test Suite Runner for Kali Linux
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🧪 Running SENTINEL AI Automated Test Suite..."

if [ -f "${PROJECT_ROOT}/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "${PROJECT_ROOT}/.venv/bin/activate"
fi

pytest -c "${PROJECT_ROOT}/pytest.ini" --rootdir="${PROJECT_ROOT}" "${PROJECT_ROOT}/tests" -v

echo "✅ All tests passed successfully."
