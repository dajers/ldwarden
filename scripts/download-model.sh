#!/usr/bin/env bash
# Скачивает GGUF-модель Qwen в llms/.
set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
MODEL="${1:-qwen2.5-7b}"

case "$MODEL" in
  qwen2.5-7b)
    REPO="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
    FILE="qwen2.5-coder-7b-instruct-q4_k_m.gguf"
    ;;
  qwen3-14b)
    REPO="Qwen/Qwen3-14B-GGUF"
    FILE="Qwen3-14B-Q4_K_M.gguf"
    ;;
  *)
    echo "Доступные модели: qwen2.5-7b | qwen3-14b" >&2
    exit 2
    ;;
esac

DEST="llms/$FILE"
URL="https://huggingface.co/$REPO/resolve/main/$FILE?download=true"

mkdir -p llms
if [ -f "$DEST" ]; then
  echo "Уже скачано: $DEST"
  exit 0
fi

echo "Скачиваю $REPO/$FILE → $DEST"
if [ "$DRY_RUN" = 1 ]; then
  echo "+ curl -L --fail -o \"$DEST.part\" \"$URL\""
  exit 0
fi

curl -L --fail --progress-bar -o "$DEST.part" "$URL"
mv "$DEST.part" "$DEST"

SIZE="$(wc -c < "$DEST" | tr -d ' ')"
if [ "$SIZE" -lt 1000000000 ]; then
  echo "Файл подозрительно маленький ($SIZE байт) — возможно, скачалась HTML-страница." >&2
  exit 1
fi

echo
echo "Готово: $DEST ($((SIZE / 1024 / 1024)) МБ)"
if [ "$MODEL" = "qwen2.5-7b" ]; then
  echo "Запуск: ./start.sh"
else
  echo "Запуск: LDWARDEN_LLM_PROVIDER=local LDWARDEN_LLM_MODEL_PATH=\"$DEST\" ./start.sh"
fi
