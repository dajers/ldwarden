#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"
source "$PROJECT_DIR/venv/bin/activate"
exec python -m app.main serve --host "${LDWARDEN_HOST:-127.0.0.1}" --port "${LDWARDEN_PORT:-8000}"
