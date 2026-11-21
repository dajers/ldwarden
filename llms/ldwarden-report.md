# Отчёт о проверке безопасности

**Проект:** https://github.com/dajers/ldwarden  
**Дата:** 20 ноября 2026 г. в 23:31  
**Найдено:** 19 — SECRET 14, SCA 0, SAST 5

## Сводка

| Критичность | Количество |
| --- | --- |
| Критично | 1 |
| Высоко | 8 |
| Средне | 8 |
| Низко | 2 |

## Находки

### 1. В репозитории находится приватный ключ (`private-key`) — `app/analysis/secrets/engine.py`. Значение замаскировано: ---…---.

`SECRET` · `CRITICAL` · `app/analysis/secrets/engine.py:518–518`

В репозитории находится приватный ключ (`private-key`) — `app/analysis/secrets/engine.py`.

**Как исправить.** Отзовите и перевыпустите ключ, удалите его из истории Git и храните в секретном хранилище.

```
-----BEGIN PRIVATE KEY----- [содержимое скрыто]
```

### 2. В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt`. Значение замаскировано: cg2…6Qp.

`SECRET` · `HIGH` · `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt:4`

В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt`.

**Как исправить.** Вынесите пароль в переменные окружения или Vault и смените скомпрометированное значение.

```
legacyImportPassword = "cg2…6Qp"
```

### 3. IDOR: GET /api/customer/tickets/{ticketId} читает запись по ID `ticketId` без проверки владельца.

`SAST` · `HIGH` · `training-main/training-project/src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt:10–11`

Маршрут GET /api/customer/tickets/{ticketId} требует входа, но training-main/training-project/src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt:10 выбирает запись по одному ID и не фильтрует по владельцу (customer_id), поэтому клиент может прочитать чужую заявку.

**Как исправить.** Добавьте в запрос условие по owner-полю и передавайте идентификатор из Principal; для чужой и отсутствующей записи возвращайте одинаковый ответ.

```
SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?
```

### 4. SQL-инъекция: в SQL-запрос подставляется `frameTag` (sink `queryForList`).

`SAST` · `HIGH` · `training-main/training-project/src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt:13–14`

Параметр(ы) frameTag попадают в SQL-строку без параметризации в training-main/training-project/src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt:14. Это позволяет изменить логику запроса.

**Как исправить.** Используйте параметризованный запрос с плейсхолдерами `?` и передавайте значения отдельными аргументами JDBC.

```
SELECT ticket_code FROM repair_ticket WHERE frame_tag = '$frameTag'
```

### 5. В конфигурации оставлен токен в открытом виде (`authorization`) — `training-main/training-project/src/main/resources/application.yml`. Значение замаскировано: cg2…6zN.

`SECRET` · `HIGH` · `training-main/training-project/src/main/resources/application.yml:13`

В конфигурации оставлен токен в открытом виде (`authorization`) — `training-main/training-project/src/main/resources/application.yml`.

**Как исправить.** Задайте свойство через переменную окружения без встроенного значения и перевыпустите токен.

```
authorization: "Bea…6zN"
```

### 6. Маршрут GET /api/pickup/export открыт через permitAll без проверки роли.

`SAST` · `HIGH` · `training-main/training-project/src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt:18–18`

Правило `/api/pickup/export` с `permitAll()` открывает GET /api/pickup/export. Обработчик training-main/training-project/src/main/kotlin/lab/repairdesk/pickup/PickupExportController.kt:10 возвращает данные клиентов/выдачи без отдельной проверки роли.

**Как исправить.** Замените permitAll() на hasRole("MECHANIC") (или другую требуемую роль) и проверьте доступ для гостя, клиента и мастера.

```
permitAll: /api/pickup/export (training-main/training-project/src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt:18)
```

### 7. В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `app/frontend/js/fixtures.js`. Значение замаскировано: cg2…•••.

`SECRET` · `HIGH` · `app/frontend/js/fixtures.js:19`

В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `app/frontend/js/fixtures.js`.

**Как исправить.** Вынесите пароль в переменные окружения или Vault и смените скомпрометированное значение.

```
legacyImportPassword = "cg2…•••"
```

### 8. В коде оставлен пароль в открытом виде (`password`) — `tests/test_api.py`. Значение замаскировано: Sup…345.

`SECRET` · `HIGH` · `tests/test_api.py:152`

В коде оставлен пароль в открытом виде (`password`) — `tests/test_api.py`.

**Как исправить.** Вынесите пароль в переменные окружения или Vault и смените скомпрометированное значение.

```
password = "Sup…345"
```

### 9. Строка подключения содержит пароль в открытом виде (`connection-password`) — `app/services/notifications.py`. Значение замаскировано: pas…d").

`SECRET` · `HIGH` · `app/services/notifications.py:186`

Строка подключения содержит пароль в открытом виде (`connection-password`) — `app/services/notifications.py`.

**Как исправить.** Уберите пароль из строки подключения, используйте переменные окружения и ротацию credentials.

```
connection password: pas…d")
```

### 10. В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt`. Значение замаскировано: cg2…J6c.

`SECRET` · `MEDIUM` · `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt:7`

В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt`.

**Как исправить.** Передавайте ключ через настройки окружения или секретное хранилище, не храните его в коде.

```
pricingApiKey = "cg2…J6c"
```

### 11. Токен собирается из строковых литералов в коде и может быть восстановлен (`access`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt`. Значение замаскировано: cg2…mQ9.

`SECRET` · `MEDIUM` · `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt:7–10`

Токен собирается из строковых литералов в коде и может быть восстановлен (`access`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt`.

**Как исправить.** Соберите токен из переменных окружения или секрета, не склеивайте его из литералов в коде.

```
series + grant → auth header; восстановленное значение: cg2…mQ9
```

### 12. CORS разрешает любой origin (`*`) и передачу credentials для `/api/customer/summary`.

`SAST` · `MEDIUM` · `training-main/training-project/src/main/kotlin/lab/repairdesk/config/RepairCors.kt:13–14`

Одновременно включены `allowedOrigins = "*"` и `allowCredentials = true`. Любой сайт может выполнить credentialed-запрос и прочитать приватные данные.

**Как исправить.** Разрешите только доверенный origin клиентского интерфейса или отключите credentialed CORS для приватного маршрута.

```
allowedOrigins=*; allowCredentials=true; route=/api/customer/summary
```

### 13. Верификатор имени хоста принимает любое имя (`HostnameVerifier { _, _ -> true }`).

`SAST` · `MEDIUM` · `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt:13–13`

Верификатор имени хоста принимает любое имя (`HostnameVerifier { _, _ -> true }`). Проверка сертификата/имени хоста ослаблена в training-main/training-project/src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt:13.

**Как исправить.** Используйте штатный HostnameVerifier и стандартный TrustManager; не отключайте проверку сертификатов.

```
HostnameVerifier { _, _ -> true
```

### 14. В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `app/frontend/js/fixtures.js`. Значение замаскировано: cg2…•••.

`SECRET` · `MEDIUM` · `app/frontend/js/fixtures.js:32`

В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `app/frontend/js/fixtures.js`.

**Как исправить.** Передавайте ключ через настройки окружения или секретное хранилище, не храните его в коде.

```
pricingApiKey = "cg2…•••"
```

### 15. В коде оставлен токен в открытом виде (`token`) — `tests/test_notifications.py`. Значение замаскировано: 123…ken.

`SECRET` · `MEDIUM` · `tests/test_notifications.py:62`

В коде оставлен токен в открытом виде (`token`) — `tests/test_notifications.py`.

**Как исправить.** Вынесите токен в секретное хранилище и перевыпустите его.

```
token = "123…ken"
```

### 16. В коде оставлен токен в открытом виде (`token`) — `tests/test_notifications.py`. Значение замаскировано: 123…ken.

`SECRET` · `MEDIUM` · `tests/test_notifications.py:77`

В коде оставлен токен в открытом виде (`token`) — `tests/test_notifications.py`.

**Как исправить.** Вынесите токен в секретное хранилище и перевыпустите его.

```
token = "123…ken"
```

### 17. В коде оставлен токен в открытом виде (`telegram_bot_token`) — `tests/test_api.py`. Значение замаскировано: 123…ken.

`SECRET` · `MEDIUM` · `tests/test_api.py:278`

В коде оставлен токен в открытом виде (`telegram_bot_token`) — `tests/test_api.py`.

**Как исправить.** Вынесите токен в секретное хранилище и перевыпустите его.

```
telegram_bot_token = "123…ken"
```

### 18. Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt`. Значение замаскировано: cg2…2qT.

`SECRET` · `LOW` · `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt:8`

Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `training-main/training-project/src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt`.

**Как исправить.** Удалите fallback-значение: при отсутствии переменной интеграция должна отключаться.

```
access = System.getenv(...) ?: "cg2…2qT"
```

### 19. Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `app/frontend/js/fixtures.js`. Значение замаскировано: cg2…•••.

`SECRET` · `LOW` · `app/frontend/js/fixtures.js:58`

Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `app/frontend/js/fixtures.js`.

**Как исправить.** Удалите fallback-значение: при отсутствии переменной интеграция должна отключаться.

```
access = System.getenv(...) ?: "cg2…•••"
```

## Ограничения проверки

- Анализ статический: уязвимость подтверждена по коду, но не эксплуатировалась.
- Секреты в отчёте замаскированы; исходные значения не выгружаются.
- SCA проверяет только явно объявленные зависимости из `build.gradle.kts` и `gradle.properties`.
