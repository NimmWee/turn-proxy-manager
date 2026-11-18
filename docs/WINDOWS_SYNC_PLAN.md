# Windows: привязка сеанса и фоновая проверка подписки

17.11.2026. Продолжение согласованного managed workflow после 0.14. Реальное подключение и обновление установленных служб оставлены пользователю.

## Решение

- Разделить идентификатор сохранённого профиля службы и идентификатор конфигурации, действительно прочитанной работающим tunnel process. SHA-256 с отдельным контекстом от полного trimmed native URI, без передачи URI/ключей в status. Runtime identity публиковать только при свежем runtime, совпадении SCM PID, attempt id и защищённых options. Старые службы/старый runtime не подходят для фоновой синхронизации.
- Узкий `disconnect-if-current`: ожидаемые identity + attempt id обязательны; проверка и остановка под существующим broker mutex. Несовпадение ничего не останавливает. Обычная ручная остановка сохраняется.
- Опциональная настройка фоновой проверки, выключенная по умолчанию. Только зарегистрированный managed профиль, совпавший с подтверждённым runtime (`connected`, handshake/egress), независимо от выбранной строки каталога. Один запрос, первая проверка через 15 секунд, затем 30 минут; ошибки с bounded backoff и учётом Retry-After. Окно должно работать; фоновой службы подписок пока нет.
- HTTPS остаётся внутренним 10.77.43.1:443 с проверкой origin/TLS, без proxy/redirect/public fallback. Перед HTTP и перед сохранением проверять актуальность сеанса; отменять при отключении, операции пользователя, выключении настройки и закрытии приложения. Ответ от старого сеанса не меняет каталог.
- 200 сохраняет проверенный candidate, 304 подтверждает cache, 202 ждёт. Никакого auto-apply, UAC или reconnect. 401/403 блокирует профиль в каталоге и запрашивает остановку только соответствующего runtime через conditional IPC; ключи сохраняются. Неудача остановки видима в журнале, не называется успешной.

## Проверки существенных рисков

Синтетические Go/C# проверки: совпадение digest между языками; stale/PID/attempt/profile mismatch; IPC guard до любых SCM изменений; отмена и смена сеанса во время HTTP без записи; single-flight, расписание/backoff/Retry-After; revoked профиль не может остановить другое соединение; DPAPI/backup сохранение настройки. Затем сборка, существующие managed/enrollment bridge проверки и offline smoke без маршрутов/служб.

## Следующие независимые gates

Traffic-proven LKG/automatic rollback и Direct↔Relay ещё отдельная работа. Простое сохранение candidate или локальный previous profile не объявлять LKG. Реальные TLS/revoke/VPN/sleep/leak E2E — NOT RUN до проверки пользователем.

Результаты выполнения дописываются после фактических проверок.

## Фактический результат0.15

Код решения реализован. Настройка находится в «Настройки → Приложение». Пока открыта вложенная страница, новые background jobs не запускаются; вход на страницу/foreground action отменяет прежний job. Частый status poll при выключенной настройке/старой службе не читает каталог. При устойчивом owned runtime каталог не расшифровывается повторно до следующей проверки; перед HTTP и перед commit он перечитывается и runtime перепроверяется. Ошибка чтения каталога откладывает sync, сохраняя честное отображение состояния VPN.

- Go `test -tags with_gvisor ./...`, `vet`, release build PASS. Digest-вектор совпал с независимым SHA-256 и C#. Stale/future/PID/attempt/options/profile mismatch отвергаются. Invalid conditional IPC отвергается до SCM; valid conditional request при отсутствии private runtime возвращает CONNECTION_CHANGED (только SCM query, остановка не выполняется).
- C# catalog suite PASS: cancelled200/304/403 не меняют DPAPI; отмена после builder не записывает candidate; stale403 не сохраняет отказ; schedule/single-flight/reconnect/backoff/Retry-After bound, opt-out, backup roundtrip/explicit preference restore и lease-target/no false stop-success проверены синтетически. Actual C#→Go managed builder и enrollment key/manifest bridges PASS; настоящий TLS/VPN этим не подтверждён.
- Python server-contract→Go manifest/Unicode ETag/share/key/CID/tamper interop PASS. API/schema/root DB/vendor не менялись.
- WPF publish PASS, финальный native single-window/nested/busy/close/WebView check PASS с ServicesUsed=false/NetworkChanged=false. Compact settings render осмотрен. Offline checker: StateDigestUnchanged=true; preflight честно OTHER_VPN_OR_NONPHYSICAL_UPLINK. Другой VPN не отключался.
- Baseline23 SHA и vendor package verifier PASS. Полный серверный Linux suite повторно не запускался: этот блок меняет только Windows и документы.
- Архив `clients/windows/artifacts/FreeTurn-Windows-0.15.0-preview-win-x64.zip`: 86.13MiB,16 entries/15 payload SHA/171 source files/81 notices. SHA256 `2a7e7396b0c2eb8454d2a2ee55580c82891ee521c787510960b2af29904df605`; payload hashes/source correspondence PASS,0.14 неизменён.

Самопроверка выполнена без субагентов по указанию пользователя. Реальные managed HTTPS/revoke/SCM stop/VPN/leak/sleep E2E — **NOT RUN**. Установленные службы, VPS, рабочие ключи/профили и GitHub не менялись. LKG/автоматический откат не объявлены реализованными.
