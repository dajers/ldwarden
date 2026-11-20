# Отчёт о проверке безопасности

**Проект:** training-project  
**Дата:** 20 ноября 2026 г. в 19:08  
**Найдено:** 15 — SECRET 5, SCA 5, SAST 5

## Сводка

| Критичность | Количество |
| --- | --- |
| Критично | 1 |
| Высоко | 7 |
| Средне | 6 |
| Низко | 1 |

## Находки

### 1. Уязвимая зависимость org.apache.commons:commons-text:1.9: CVE-2022-42889

`SCA` · `CRITICAL` · `build.gradle.kts:31–31`

Зависимость: `undefined:undefined:undefined` · advisory ``

Зависимость org.apache.commons:commons-text:1.9 попадает в уязвимый диапазон [1.5, 1.10.0) (CVE-2022-42889). Сверено со справочником уязвимостей Maven из учебного набора.

**Как исправить.** Обновить зависимость org.apache.commons:commons-text до исправленной версии 1.10.0.

```
org.apache.commons:commons-text:1.9
```

### 2. В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt`. Значение замаскировано: cg2…6Qp.

`SECRET` · `HIGH` · `src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt:4`

В коде оставлен пароль в открытом виде (`legacyImportPassword`) — `src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt`.

**Как исправить.** Вынесите пароль в переменные окружения или Vault и смените скомпрометированное значение.

```
legacyImportPassword = "cg2…6Qp"
```

### 3. IDOR: GET /api/customer/tickets/{ticketId} читает запись по ID `ticketId` без проверки владельца.

`SAST` · `HIGH` · `src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt:10–11`

Маршрут GET /api/customer/tickets/{ticketId} требует входа, но src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt:10 выбирает запись по одному ID и не фильтрует по владельцу (customer_id), поэтому клиент может прочитать чужую заявку.

**Как исправить.** Добавьте в запрос условие по owner-полю и передавайте идентификатор из Principal; для чужой и отсутствующей записи возвращайте одинаковый ответ.

```
SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?
```

### 4. SQL-инъекция: в SQL-запрос подставляется `frameTag` (sink `queryForList`).

`SAST` · `HIGH` · `src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt:13–14`

Параметр(ы) frameTag попадают в SQL-строку без параметризации в src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt:14. Это позволяет изменить логику запроса.

**Как исправить.** Используйте параметризованный запрос с плейсхолдерами `?` и передавайте значения отдельными аргументами JDBC.

```
SELECT ticket_code FROM repair_ticket WHERE frame_tag = '$frameTag'
```

### 5. В конфигурации оставлен токен в открытом виде (`authorization`) — `src/main/resources/application.yml`. Значение замаскировано: cg2…6zN.

`SECRET` · `HIGH` · `src/main/resources/application.yml:13`

В конфигурации оставлен токен в открытом виде (`authorization`) — `src/main/resources/application.yml`.

**Как исправить.** Задайте свойство через переменную окружения без встроенного значения и перевыпустите токен.

```
authorization: "Bea…6zN"
```

### 6. Маршрут GET /api/pickup/export открыт через permitAll без проверки роли.

`SAST` · `HIGH` · `src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt:18–18`

Правило `/api/pickup/export` с `permitAll()` открывает GET /api/pickup/export. Обработчик src/main/kotlin/lab/repairdesk/pickup/PickupExportController.kt:10 возвращает данные клиентов/выдачи без отдельной проверки роли.

**Как исправить.** Замените permitAll() на hasRole("MECHANIC") (или другую требуемую роль) и проверьте доступ для гостя, клиента и мастера.

```
permitAll: /api/pickup/export (src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt:18)
```

### 7. Уязвимая зависимость org.jsoup:jsoup:1.14.1: CVE-2021-37714

`SCA` · `HIGH` · `build.gradle.kts:32–32`

Зависимость: `undefined:undefined:undefined` · advisory ``

Зависимость org.jsoup:jsoup:1.14.1 попадает в уязвимый диапазон (−∞, 1.14.2) (CVE-2021-37714). Сверено со справочником уязвимостей Maven из учебного набора.

**Как исправить.** Обновить зависимость org.jsoup:jsoup до исправленной версии 1.14.2.

```
org.jsoup:jsoup:1.14.1
```

### 8. Уязвимая зависимость org.json:json:20230227: CVE-2023-5072

`SCA` · `HIGH` · `build.gradle.kts:38–38`

Зависимость: `undefined:undefined:undefined` · advisory ``

Зависимость org.json:json:20230227 попадает в уязвимый диапазон (−∞, 20230618] (CVE-2023-5072). Сверено со справочником уязвимостей Maven из учебного набора.

**Как исправить.** Обновить зависимость org.json:json до исправленной версии 20231013.

```
org.json:json:20230227
```

### 9. В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt`. Значение замаскировано: cg2…J6c.

`SECRET` · `MEDIUM` · `src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt:7`

В коде оставлен API-ключ в открытом виде (`pricingApiKey`) — `src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt`.

**Как исправить.** Передавайте ключ через настройки окружения или секретное хранилище, не храните его в коде.

```
pricingApiKey = "cg2…J6c"
```

### 10. Токен собирается из строковых литералов в коде и может быть восстановлен (`access`) — `src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt`. Значение замаскировано: cg2…mQ9.

`SECRET` · `MEDIUM` · `src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt:7–10`

Токен собирается из строковых литералов в коде и может быть восстановлен (`access`) — `src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt`.

**Как исправить.** Соберите токен из переменных окружения или секрета, не склеивайте его из литералов в коде.

```
series + grant → auth header; восстановленное значение: cg2…mQ9
```

### 11. CORS разрешает любой origin (`*`) и передачу credentials для `/api/customer/summary`.

`SAST` · `MEDIUM` · `src/main/kotlin/lab/repairdesk/config/RepairCors.kt:13–14`

Одновременно включены `allowedOrigins = "*"` и `allowCredentials = true`. Любой сайт может выполнить credentialed-запрос и прочитать приватные данные.

**Как исправить.** Разрешите только доверенный origin клиентского интерфейса или отключите credentialed CORS для приватного маршрута.

```
allowedOrigins=*; allowCredentials=true; route=/api/customer/summary
```

### 12. Верификатор имени хоста принимает любое имя (`HostnameVerifier { _, _ -> true }`).

`SAST` · `MEDIUM` · `src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt:13–13`

Верификатор имени хоста принимает любое имя (`HostnameVerifier { _, _ -> true }`). Проверка сертификата/имени хоста ослаблена в src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt:13.

**Как исправить.** Используйте штатный HostnameVerifier и стандартный TrustManager; не отключайте проверку сертификатов.

```
HostnameVerifier { _, _ -> true
```

### 13. Уязвимая зависимость org.apache.commons:commons-compress:1.25.0: CVE-2024-25710

`SCA` · `MEDIUM` · `build.gradle.kts:33–33`

Зависимость: `undefined:undefined:undefined` · advisory ``

Зависимость org.apache.commons:commons-compress:1.25.0 попадает в уязвимый диапазон [1.3, 1.26.0) (CVE-2024-25710). Сверено со справочником уязвимостей Maven из учебного набора.

**Как исправить.** Обновить зависимость org.apache.commons:commons-compress до исправленной версии 1.26.0.

```
org.apache.commons:commons-compress:1.25.0
```

### 14. Уязвимая зависимость commons-net:commons-net:3.8.0: CVE-2021-37533

`SCA` · `MEDIUM` · `build.gradle.kts:36–36`

Зависимость: `undefined:undefined:undefined` · advisory ``

Зависимость commons-net:commons-net:3.8.0 попадает в уязвимый диапазон (−∞, 3.9.0) (CVE-2021-37533). Сверено со справочником уязвимостей Maven из учебного набора.

**Как исправить.** Обновить зависимость commons-net:commons-net до исправленной версии 3.9.0.

```
commons-net:commons-net:3.8.0
```

### 15. Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt`. Значение замаскировано: cg2…2qT.

`SECRET` · `LOW` · `src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt:8`

Для секрета задано встроенное значение по умолчанию (fallback) (`access`) — `src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt`.

**Как исправить.** Удалите fallback-значение: при отсутствии переменной интеграция должна отключаться.

```
access = System.getenv(...) ?: "cg2…2qT"
```

## Ограничения проверки

- Анализ статический: уязвимость подтверждена по коду, но не эксплуатировалась.
- Секреты в отчёте замаскированы; исходные значения не выгружаются.
- SCA проверяет только явно объявленные зависимости из `build.gradle.kts` и `gradle.properties`.
