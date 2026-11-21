# LDWarden

Визуальный конструктор проверок безопасности для Kotlin / Spring Boot / Gradle:
собираете сценарий из блоков на холсте, запускаете — получаете находки
SECRET / SCA / SAST, объяснения и рекомендации и готовый отчёт.

## Быстрый старт

Нужен Python 3.10+ (проверено на 3.14).

```bash
./start.sh
```

Первый запуск сам создаст `venv`, поставит зависимости и поднимет сервер на
<http://127.0.0.1:8000>. Повторный запуск — `./start.sh --no-install`.

- **macOS:** можно дважды кликнуть по `LDWarden.command` — откроется Terminal,
  поднимется сервер и сайт в браузере. Пока окно открыто — сервер работает;
  закрыли окно (или Ctrl+C) — сервер остановился.
- **Windows:** `start.bat` делает то же самое.
- Порт: `LDWARDEN_PORT=9000 ./start.sh` или `./LDWarden.command`.

## HTML-отчёт

После прогона в панели результатов есть кнопка **«Отчёт .html»** — скачивается
самодостаточный файл: статистика, находки, объяснения и рекомендации, оформление
под печать (из браузера можно сохранить в PDF).

То же самое доступно без интерфейса:

```bash
# через API (после запуска сценария)
curl -o report.html "http://127.0.0.1:8000/api/runs/<run_id>/report?format=html&download=1"

# из командной строки, без сервера
python -m app.main scan --format html > report.html
```

## Библиотека шаблонов

Готовые сценарии можно публиковать в GitHub-репозиторий и загружать из отдельной
вкладки **«Библиотека»** (поиск, кеш 60 секунд, кнопка «Добавить в пресеты» не
заменяет текущий сценарий). Настройка — в `.env` (пример в `.env.example`):

```env
LDWARDEN_LIBRARY_REPO=owner/ldwarden-presets
LDWARDEN_LIBRARY_BRANCH=main
LDWARDEN_LIBRARY_PATH=presets
LDWARDEN_LIBRARY_TOKEN=github_pat_...
```

Токен нужен для публикации (право **Contents: Read and write**); публичный
репозиторий можно читать без токена. Пресеты хранятся как JSON в каталоге
`LDWARDEN_LIBRARY_PATH`; секреты при публикации маскируются.

## Тесты

```bash
python -m unittest discover -s tests
```

## Структура

```
start.sh / start.bat   запуск: venv, зависимости, сервер
LDWarden.command       запуск двойным кликом (macOS/Linux)

app/analysis/          SECRET, SCA, SAST
app/nodes/             ноды конструктора
app/reports/           Markdown / JSON / SARIF / HTML
app/api/               REST API, SSE, CI, вебхуки
app/frontend/          SPA-конструктор (без сборки, ES-модули)
training-main/         учебный проект и эталон находок
```

## Ограничения

- AI по умолчанию работает в fallback-режиме, если не установлен
  `llama-cpp-python` или не найдена модель. Для локальной Qwen установите
  `./scripts/setup-ai.sh` (или `./venv/bin/pip install -r requirements-ai.txt`);
  после этого проверьте статус `GET /api/health` — `llm.ready` должен быть `true`.
- Локальная 7B на CPU может отвечать 1–3 минуты; по умолчанию AI обрабатывает
  2 находки, остальные объясняет fallback. Если ответ не успел за таймаут,
  в результате AI будет указана причина.
- Инструмент локальный: сканирует любую доступную папку, запускайте в изолированном окружении.
- Правила анализаторов настроены на Kotlin / Spring Boot / Gradle.
