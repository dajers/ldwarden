#!/bin/bash
# Двойной клик: поднимает сервер, открывает сайт и держит окно открытым.
# Закрыли окно (или нажали Ctrl+C) — сервер останавливается.
cd "$(dirname "$0")" || exit 1

PORT="${LDWARDEN_PORT:-8000}"
export LDWARDEN_PORT="$PORT"
URL="http://127.0.0.1:$PORT"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo
    echo "Останавливаю LDWarden…"
    kill "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 40); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 0' INT TERM HUP

# Если порт уже занят — останавливаем старый экземпляр, чтобы этим сервером управляло это окно.
if curl -s -o /dev/null "$URL/api/health"; then
  OLD_PID=""
  if command -v lsof >/dev/null 2>&1; then
    OLD_PID="$(lsof -ti tcp:"$PORT" 2>/dev/null | head -n 1)"
  fi
  if [ -n "$OLD_PID" ]; then
    echo "На порту $PORT уже работает LDWarden (PID $OLD_PID) — останавливаю его."
    kill "$OLD_PID" 2>/dev/null
    for _ in $(seq 1 40); do
      curl -s -o /dev/null "$URL/api/health" || break
      sleep 0.25
    done
  fi
fi

echo "Запускаю LDWarden на $URL …"
./start.sh &
SERVER_PID=$!

for _ in $(seq 1 300); do
  if curl -s -o /dev/null "$URL/api/health"; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [ "${LDWARDEN_NO_OPEN:-0}" = "1" ]; then
  echo "Браузер не открываю (LDWARDEN_NO_OPEN=1). Адрес: $URL"
elif command -v open >/dev/null 2>&1; then
  open "$URL"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL"
else
  echo "Откройте вручную: $URL"
fi

echo
echo "Сервер работает. Закройте это окно или нажмите Ctrl+C — сервер остановится."
wait "$SERVER_PID"

echo
echo "Сервер остановлен."
read -r -p "Нажмите Enter, чтобы закрыть окно…" _ || true
