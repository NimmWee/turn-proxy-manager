# Windows Direct ↔ VK Relay,0.17

Продолжение согласованного ТЗ17.11.2026. Без субагентов, реальных подключений, установки служб/VPS и GitHub. Применяю проектирование/планирование; автоматические проверки только для существенных рисков ключей, прав, данных и сетевого lifecycle.

## Решение

Закреплённый core `mobile.Restart(config,0)` останавливает proxy session и запускает новую, сохраняя SetProtect/event sink и не владея внешним Windows WGNT/TUN. Выбран transport-only restart. Альтернативы: остановка всей службы перестраивает маршруты; подмена portable URI ломает manifest/ETag identity. Ни один вариант здесь не нужен.

- Opt-in «Автоматически выбирать Direct / Relay», default off, DPAPI/backup. Только WireGuard-профиль с валидной VK-ссылкой, тем же FreeTurn peer/OBF/CID/WG: Direct означает DTLS/OBF к FreeTurn, не публичный51830. API/portable URI/managed manifest не меняются. Core renderer меняет только provider/число direct streams/VK-specific flags, ключи и WG не трогает.
- UI controller начинает работу только после accepted manual Connect receipt, не восстанавливает intent после UI startup/backup. Первый путь Direct, при неподтверждённом трафике30с — Relay; Relay получает60с. Стабильный working path сохраняется. После деградации можно переключиться обратно; максимум2 switches за attempt, затем понятное сообщение/manual action. CAPTCHA/sleep пауза, auth/rate-limit/cancel/foreign attempt отказ; старый reconnect не должен сбрасывать budget.
- Новый `switch-path-if-current` owner IPC под broker mutex проверяет canonical profile/attempt/path epoch/fresh runtime/PID/options, unhealthy/no CAPTCHA и budget. Пишет только фиксированный SYSTEM DPAPI journal с target path и monotonic epoch≤2. Это не stop/start service, не firewall/routes mutation. Повтор pending request/старый epoch отклоняется.
- Tunnel worker принимает журнал только своего attempt/profile, повторно проверяет cancellation и вызывает `mobile.Restart(...,0)`. WG adapter/routes/DNS/WFP остаются на месте. Перед restart журнал уже durable; после crash повторный запуск не обнуляет budget. Отдельный worker/writer lifecycle должен завершаться до финального mobile.Stop.
- Status публикует actual path/epoch/pending и отделяет canonical identity от фактического транспорта. Смена epoch сбрасывает broker egress proof; старый результат probe не подтверждает новый путь. Для system report egress timestamp должен быть позднее path start +8с (probe timeout7с). Никакого успеха по одному core connected/handshake.
- RuntimeLease и conditional stop/recovery включают path epoch. Pending switch/смена path отменяет запоздавший subscription commit. LKG сохраняет доказанный path; config recovery использует его с Auto выключенным. Managed trial ждёт transport budget и не конкурирует с переключением.

## План

- [x] Целевые failing checks: path renderer/key equality, IPC attempt/epoch/pending/budget/healthy guards; controller timing/CAPTCHA/sleep/cancel и stale proof.
- [x] Go path schema/journal/renderer, guarded IPC и runtime worker; receipt/status/probe scope.
- [x] C# settings/backup/lease/controller, MainWindow и LKG/sync coordination, понятные состояния.
- [x] Build0.17, Go test/vet, C# targeted/actual bridge, Python contract, native/offline и package/source hashes;0.16 сохранить.
- [x] ТЗ/PROGRESS/REMAINING с отличием mock/local/real и зафиксированными исключениями Windows scope.

Реальные Direct/Relay/DTLS/WG traffic, switches/leaks/SCM/crash/sleep E2E — NOT RUN. Сохранение adapter/routes кодом не заменяет реальную проверку утечек. Ошибки до accepted Connect не запускают автоматику.

## Фактический результат0.17

Реализованы transport renderer/journal/worker, guarded IPC и actual path status, C# TransportPolicy/Manager, lease/backup/LKG coordination и настройка «Приложение → Транспорт». По умолчанию выключена. Только accepted manual Connect создаёт intent; обычный retry не включает Auto и не сбрасывает budget. Path switch не меняет canonical share/manifest/signature/revision, WG private key/PSK/server key/CID/OBF/peer и не вызывает SCM stop/start. Direct — прежний FreeTurn DTLS/OBF peer, без открытия WG backend51830.

- Go tests сначала показали отсутствие новых guards/types; после реализации test/vet/build PASS. Actual core renderer/validation сохраняет identity/WG-related core fields; wrong path/attempt/epoch/healthy/CAPTCHA/pending/budget и чужие IPC fields отвергаются. Real local DPAPI journal + synthetic Restart callback проверили ack, restart resume без reset budget и отменённую попытку без callback. Настоящий mobile.Restart не запускался.
- Probe scope: broker generation сбрасывается при request/actual epoch. System reporter передаёт captured epoch и completion timestamp; прежний/in-flight result не подтверждает новый путь. Дополнительный8с барьер больше fixed7с HTTPS probe timeout. Proof window/leases включают epoch, pending не считается connected. Это локальная проверка логики; трафик и leaks не подтверждены.
- C# catalog/transport policy/async flow PASS:30/60с, terminal error после5с, max2, healthy/no flapping, CAPTCHA pause, sleep gap, auth/stale/unknown runtime refusal, single pending request, cancel while status awaits, recovered path без switch. Старый path403 не изменяет managed access flag. DPAPI/backup сохраняют preference и proven LKG path; обычный merge не меняет настройку без explicit preferences restore.
- Managed trial приостанавливается, пока действует transport intent; после exhaustion использует актуальный epoch для conditional return. LKG proof сохраняет path, recovery стартует proven path с Auto выключенным. Нельзя делать вывод о server acceptance старой конфигурации по одному сохранённому snapshot.
- Actual C#→Go managed builder/enrollment/LKG key checks, Python server-contract/Unicode ETag/share interop PASS. API/schema/root DB/vendor не менялись. Полный серверный Linux suite повторно не запускался.
- WPF publish0 warnings/errors, final native single-window/nested/busy/close/WebView PASS, compact settings render осмотрен. Offline StateDigestUnchanged=true; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK. Другой VPN не отключался. Baseline23 SHA/vendor verifier PASS.
- Архив `clients/windows/artifacts/FreeTurn-Windows-0.17.0-preview-win-x64.zip`: 86.18MiB/16 entries/15 payload SHA/183 source files/81 notices. SHA256 `3463b04d639050151d000222c0ea15ce13de54670b1f9f242970327c35c6b4bf`; payload/source correspondence PASS,0.16 неизменён.

## Границы приёмки

Real Direct/Relay/DTLS/WG traffic/mobile.Restart/switch/DNS/IPv6 leaks/SCM/crash/sleep/network-change E2E — **NOT RUN**. Пользователь оставил подключение себе; installed services и сеть не менялись. Worker использует выбранный при Connect protector; автоматическая смена physical uplink не реализована. Повреждённый journal запрещает автоматическое переключение; manual disconnect сохраняется. Ошибки до accepted Connect требуют ручного действия. Пока UI не работает, новых switch requests нет; уже принятый request может завершаться runtime worker. Broker budget предотвращает повторный обход лимита в рамках того же attempt. Самопроверка выполнена без субагентов; publication/GitHub/VPS/рабочие ключи не затрагивались.
