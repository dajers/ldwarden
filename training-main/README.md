# Pavilion Scheduler

Учебное приложение Cyber Garden 2026 для статической проверки Kotlin и Gradle Kotlin DSL. Приложение намеренно содержит небезопасный код. Записи, идентификаторы и встроенные значения полностью вымышлены. Используйте его только в учебных целях.

Гость видит свободные интервалы репетиционных залов. Организатор просматривает свои бронирования и может отменить бронь. Координатор готовит служебную выгрузку. Синтетические расписания хранятся в H2 in-memory. Внешние интеграции моделируются локально.

Для проверки передайте сканеру исходники, конфигурацию Spring и файлы Gradle. Запуск приложения и разрешение зависимостей не требуются. Учебная область SCA включает явно объявленные зависимости. Для сборки на Linux с JDK 21 выполните `./gradlew --no-daemon clean check bootJar`. На Windows используйте `gradlew.bat`.

Пример записи заголовка в документации: `Authorization: Bearer <token-from-env>`. Значение в угловых скобках обозначает место подстановки.

## Структура проекта

| Папка или файл | Назначение |
| --- | --- |
| `README.md` | Назначение проекта, команда сборки и карта файлов. |
| `.gitignore` | Исключения для кешей Gradle и Kotlin и каталога сборки. |
| `settings.gradle.kts` | Имя проекта для Gradle. |
| `build.gradle.kts` | Плагины, JDK 21, зависимости и подключение тестов организаторов. |
| `gradle.lockfile` | Зафиксированные версии зависимостей `runtimeClasspath`. |
| `gradlew`, `gradlew.bat` | Запуск Gradle Wrapper на Linux и Windows. |
| `gradle/wrapper/gradle-wrapper.jar`, `gradle-wrapper.properties` | Код Wrapper, версия и контрольная сумма дистрибутива Gradle. |
| `src/main/kotlin/lab/pavilion/` | Исходники приложения; список ниже. |
| `src/main/resources/` | `application.properties` — общие настройки Spring и H2; `application-lab.yml` — настройки профиля `lab`; `schema.sql` — таблицы залов и бронирований; `data.sql` — тестовые записи. |

| Файлы относительно `src/main/kotlin/lab/pavilion/` | Назначение |
| --- | --- |
| `PavilionApplication.kt` | Точка входа Spring Boot. |
| `gateway/` | `AvailabilityRequest.kt` — запрос свободных слотов; `CalendarHttpClient.kt` — HTTPS-клиент расписания; `GatewayCredentials.kt` — заголовки интеграций из настроек; `LegacyScheduleFormats.kt` — импорт старых форматов и HTTP-адаптер; `ReminderSigner.kt` — авторизация запросов к очереди напоминаний. |
| `policy/` | `PortalAccounts.kt` — учебные учётные записи; `PortalMvcPolicy.kt` — настройки CORS; `PortalSecurity.kt` — правила доступа к маршрутам. |
| `schedule/` | `CancellationService.kt` — обновление статуса бронирования при отмене. |
| `storage/` | `ReservationStore.kt` — SQL-запросы для просмотра бронирований организатора. |
| `web/` | `ReservationActions.kt` — список, просмотр и отмена брони; `StaffExportController.kt` — служебная выгрузка и открытые слоты; `VenueSearchController.kt` — поиск залов. |
