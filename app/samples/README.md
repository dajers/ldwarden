# Примеры workflow

Готовые JSON для импорта в UI/React Flow. Формат — как у `POST /api/workflows`:

```json
{"name": "...", "description": "...", "graph": {"nodes": [...], "edges": [...]}}
```

- `full-audit.workflow.json` — ручной запуск, три сканера в независимых ветках, AI, отчёт, уведомление в `local://inbox`.
- `ci-gate.workflow.json` — webhook-триггер, те же сканеры, порог HIGH, отчёт и уведомление.
- `telegram-report.workflow.json` — полный аудит с отправкой отчёта в Telegram; заполните `bot_token` и `chat_id` в ноде `notify.telegram`.

Импорт:

```bash
curl -s -X POST http://127.0.0.1:8000/api/workflows \
  -H 'Content-Type: application/json' \
  --data-binary @samples/full-audit.workflow.json | python -m json.tool
```

Секретов в примерах нет; токены Telegram добавляются в настройках ноды и шифруются backend'ом.
