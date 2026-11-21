#!/usr/bin/env bash
# Ставит llama-cpp-python и готовит локальную модель Qwen.
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL="qwen2.5-7b"
MODEL_PATH=""
DRY_RUN=0

usage() {
  cat <<'USAGE'
Использование:
  ./scripts/setup-ai.sh [qwen2.5-7b|qwen3-14b]
  ./scripts/setup-ai.sh --path /путь/к/модели.gguf

  --path <file>  использовать уже скачанный .gguf (симлинк в llms/)
  --dry-run      показать команды, ничего не выполнять
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --path) MODEL_PATH="${2:?--path требует путь}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    qwen2.5-7b|qwen3-14b) MODEL="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage >&2; exit 2 ;;
  esac
done

run() { if [ "$DRY_RUN" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }

if [ ! -x venv/bin/python ]; then
  run python3 -m venv venv
fi

run venv/bin/python -m pip install --upgrade pip
run venv/bin/python -m pip install -r requirements-ai.txt

mkdir -p llms
if [ -n "$MODEL_PATH" ]; then
  SRC="$(cd "$(dirname "$MODEL_PATH")" && pwd)/$(basename "$MODEL_PATH")"
  if [ ! -f "$SRC" ]; then
    echo "Файл не найден: $SRC" >&2
    exit 1
  fi
  DEST="llms/$(basename "$SRC")"
  if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    echo "Уже подключено: $DEST"
  else
    run ln -s "$SRC" "$DEST"
  fi
  FILE="$DEST"
elif [ "$MODEL" = "qwen2.5-7b" ]; then
  run ./scripts/download-model.sh qwen2.5-7b
  FILE="llms/qwen2.5-coder-7b-instruct-q4_k_m.gguf"
else
  run ./scripts/download-model.sh qwen3-14b
  FILE="llms/Qwen3-14B-Q4_K_M.gguf"
fi

echo
echo "Готово. Запуск:"
if [ "$FILE" = "llms/qwen2.5-coder-7b-instruct-q4_k_m.gguf" ]; then
  echo "  ./start.sh"
else
  echo "  LDWARDEN_LLM_PROVIDER=local LDWARDEN_LLM_MODEL_PATH=\"$PWD/$FILE\" ./start.sh"
fi
