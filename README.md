# LDWarden

## Требования

- Python 3.10+
- 2 ГБ свободного места без локальной модели
- Для локальной LLM: GGUF-модель и `llama-cpp-python`

## Установка

```bash
git clone git@github.com:dajers/ldwarden.git
cd ldwarden
cp .env.example .env
./start.sh
```

Сервер будет доступен по адресу:

```text
http://127.0.0.1:8000
```

Первый запуск создаёт `venv` и устанавливает зависимости. Повторный запуск:

```bash
./start.sh --no-install
```

## Windows

```bat
start.bat
```

## macOS / Linux без терминала

Дважды кликните `LDWarden.command`.

## Модель

Без модели работает AI fallback. Для локальной модели положите `.gguf` в `llms/`
и укажите относительный путь:

```env
LDWARDEN_LLM_PROVIDER=auto
LDWARDEN_LLM_MODELS_DIR=llms
LDWARDEN_LLM_MODEL_PATH=llms/qwen2.5-coder-7b-instruct-q4_k_m.gguf
```

Для внешнего OpenAI-совместимого API:

```env
LDWARDEN_LLM_PROVIDER=universal
LDWARDEN_LLM_BASE_URL=https://openrouter.ai/api/v1
LDWARDEN_LLM_API_KEY=...
LDWARDEN_LLM_MODEL=...
```

## Порты и пути

```env
LDWARDEN_HOST=127.0.0.1
LDWARDEN_PORT=8000
LDWARDEN_DATA_DIR=data
LDWARDEN_ALLOWED_ROOTS=training-main
```

Все относительные пути считаются от корня проекта.

## Проверка

```bash
./venv/bin/python -m unittest discover -s tests
curl http://127.0.0.1:8000/api/health
```

## Остановка

Нажмите `Ctrl+C` в терминале, где запущен сервер.
