#!/usr/bin/env bash
# LDWarden — запуск в один шаг: venv, зависимости, сервер.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

HOST="${LDWARDEN_HOST:-127.0.0.1}"
PORT="${LDWARDEN_PORT:-8000}"
VENV_DIR="${LDWARDEN_VENV:-$PROJECT_DIR/venv}"
PYTHON_BIN="${LDWARDEN_PYTHON:-python3}"
INSTALL=1
DRY_RUN=0

usage() {
  cat <<'EOF'
Запуск LDWarden.

  ./start.sh [--host 127.0.0.1] [--port 8000] [--no-install] [--reinstall] [--dry-run]

  --no-install   не устанавливать зависимости (быстрый повторный запуск)
  --reinstall    переустановить зависимости
  --dry-run      показать команды, ничего не выполнять
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:?--host требует значение}"; shift 2 ;;
    --port) PORT="${2:?--port требует значение}"; shift 2 ;;
    --no-install) INSTALL=0; shift ;;
    --reinstall) INSTALL=2; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m%s\033[0m\n' "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Не найден $PYTHON_BIN. Установите Python 3.10+ и повторите запуск." >&2
  echo "  macOS: brew install python@3.12   Debian/Ubuntu: sudo apt install python3 python3-venv" >&2
  exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Нужен Python 3.10+, найден $PY_VERSION." >&2
  exit 1
fi

say "LDWarden"
echo "Проект: $PROJECT_DIR"
echo "Python: $PY_VERSION"

if [ -x "$VENV_DIR/bin/python" ]; then
  say "[1/3] Виртуальное окружение уже есть"
else
  say "[1/3] Создаю виртуальное окружение…"
  run "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
VENV_PY="$VENV_DIR/bin/python"

if [ "$DRY_RUN" = 0 ] && [ ! -x "$VENV_PY" ]; then
  echo "Не удалось создать $VENV_DIR. Запустите без --no-install." >&2
  exit 1
fi

if [ "$INSTALL" != 0 ]; then
  say "[2/3] Устанавливаю зависимости…"
  run "$VENV_PY" -m pip install --upgrade pip
  run "$VENV_PY" -m pip install -r requirements.txt
else
  say "[2/3] Пропускаю установку зависимостей"
fi

if [ "$DRY_RUN" = 0 ]; then
  AI_STATUS="$("$VENV_PY" - <<'PY' 2>/dev/null || true
from app.config import load_settings

labels = {
    "local": "локальная модель",
    "ollama": "Ollama",
    "openai": "OpenAI-совместимый API",
    "universal": "универсальный OpenAI-совместимый API",
    "fake": "fallback",
    "none": "fallback (модель не подключена)",
}
try:
    settings = load_settings({"seed_templates": False})
except Exception as exc:  # noqa: BLE001
    print(f"неизвестно ({exc})")
else:
    provider = settings.effective_llm_provider
    label = labels.get(provider, provider)
    detail = ""
    if provider == "local":
        detail = f" · {settings.llm_model_path.name}"
        try:
            import llama_cpp  # noqa: F401
        except Exception:
            detail += " · не установлен llama-cpp-python → ./scripts/setup-ai.sh"
    elif provider in {"ollama", "openai", "universal"} and settings.llm_model:
        detail = f" · {settings.llm_model}"
    print(label + detail)
PY
)"
  echo "AI: ${AI_STATUS:-неизвестно}"
fi

echo
say "[3/3] Сервер: http://$HOST:$PORT"
echo "Остановить — Ctrl+C"
echo

if [ "$DRY_RUN" = 1 ]; then
  echo "+ exec \"$VENV_PY\" -m app.main serve --host \"$HOST\" --port \"$PORT\""
  exit 0
fi

exec "$VENV_PY" -m app.main serve --host "$HOST" --port "$PORT"
