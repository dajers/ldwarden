#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
VENV_PY="${LDWARDEN_VENV:-$PROJECT_DIR/venv}/bin/python"
if [ ! -x "$VENV_PY" ]; then
  echo "Сначала запустите ./start.sh — он создаст venv." >&2
  exit 1
fi
"$VENV_PY" -m pip install -r requirements-ai.txt
"$VENV_PY" - <<'PY'
try:
    import llama_cpp
    print("llama-cpp-python:", llama_cpp.__version__)
except Exception as exc:
    print("llama-cpp-python не загрузился:", exc)
    raise SystemExit(1)
PY
