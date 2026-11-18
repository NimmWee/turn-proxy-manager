# Windows managed LKG и однократный автоматический возврат

17.11.2026. Продолжение согласованного ТЗ после0.15, без субагентов. Изменения только Windows/документы; installed services, реальное VPN и VPS не трогать, GitHub не публиковать.

## Дизайн

Выбран сохранённый в CurrentUser DPAPI last-known-good snapshot плюс in-memory intent конкретной попытки. Альтернативы: считать любой previous profile рабочим (нет доказательства трафика) либо всегда откатываться по таймеру (ломает CAPTCHA/другие соединения). Эти варианты не подходят.

- LKG хранит точный share, optional applied manifest и время подтверждения; token/private key не пересоздаются. Два подтверждённых service status одного runtime с handshake/egress/Rx/Tx за минимум5 секунд дают основание promotion. Перед записью повторно проверить ключ/manifest локальным Go builder и свежий authenticated status. Повторный poll не переписывает каталог.
- После ручного выбора обновления новый manual Connect может создать trial, только если есть отличающийся LKG, registered/not denied managed identity и receipt службы с exact configuration digest/attempt. Intent не восстанавливается из backup/после запуска приложения.
- Trial: максимум120 секунд наблюдаемого ожидания; CAPTCHA приостанавливает отсчёт, sleep/длинный gap не засчитываются. Auth/rate limit/CAPTCHA errors не вызывают откат. Ручное действие, смена попытки/профиля, отказ доступа и закрытие отменяют intent. Один automatic return, без повторяющегося failover/UAC; Direct↔Relay — следующий отдельный блок.
- Новый `recover-if-current` owner IPC выполняется под broker mutex. До остановки/записи проверить expected digest+attempt, отсутствие connected/CAPTCHA, fallback profile и совпадение private WG key. Running runtime требует fresh PID/options identity; stopped требует exact last attempted profile/options. Нельзя использовать общий import+connect с гонкой между командами. Повтор recovery старой попытки отвергается.
- Перед IPC локально атомарно вернуть LKG с сохранением rejected candidate/seen revision/token; revalidate catalog/session после async checks. Ошибка IPC оставляет честное сообщение и сохранённые обе конфигурации; другой сеанс не останавливается. Многокомпонентный service write failure не объявлять успешным: subsequent runtime сверяет WG/profile/options и откажет при рассогласовании.
- LKG является историческим доказательством прежней работоспособности, не гарантией, что сервер всё ещё принимает старую конфигурацию. AccessDenied запрещает recovery. Импорт backup не запускает VPN; сохранённый LKG повторно проверяется перед использованием.

## План реализации

- [x] Целевые failing checks: runtime recovery match/mismatch, healthy/CAPTCHA refusal, key preservation; C# LKG/trial/cancellation/backup/revision guards.
- [x] Go: last-attempt receipt/status, restricted recovery request и общий guarded connect helper; fixed capability.
- [x] C#: LKG schema/catalog methods, proof/trial monitor и recovery orchestration с injectable service/validator для synthetic checks.
- [x] Связать с MainWindow manual intent/status/close; показать LKG/return в managed page и безопасном журнале.
- [x] Сборка0.16, Go test/vet, C# targeted+bridge, Python contract, native UI и offline unchanged-state checks; source/hash verification, сохранить0.15.
- [x] Обновить ТЗ/прогресс/остаток с различием local/fake/real. Реальные TLS/VPN/rollback/SCM stop/leak/sleep — NOT RUN.

## Результат0.16

- Реализованы `ManagedKnownGood`, catalog proof/return methods, `ManagedProofWindow`/`ManagedTrial`, отдельный monitor и MainWindow binding. KnownGood не равен произвольному PreviousShare: его записывает только proof path. Если LKG ещё нет, автоматический возврат не создаётся. Контекст intended attempt не хранится в backup.
- `recover-if-current` и connect используют один helper под broker mutex. Проверяются profile/options/attempt/runtime/PID/freshness, отсутствие connected/CAPTCHA и same private WG key. Некорректный fallback отбрасывается до остановки; SOCKS закрывается перед заменой туннеля. Непосредственно перед изменением служба повторно проверяет health/attempt, а после остановки перечитывает sticky FakeDNSRequired, чтобы не потерять более новое требование DNS privacy старого runtime. Ошибка underlay/SCM/disk не объявляется успешным подключением.
- Manual/revoke disconnect немедленно запрещает recovery в памяти broker и, если возможно, сохраняет options.cancelled. Отсутствующий/нечитаемый/незаписываемый state disk не блокирует сам stop. При невозможности сохранить marker memory gate живёт до рестарта broker; UI intent не восстанавливается после рестарта приложения. Это ограничение не выдаётся за проверенный disk-fault E2E.
- Целевые Go/C# проверки сначала показали отсутствие новых guards/types; после реализации Go full test/vet/build PASS, C# catalog+LKG storage/policy/async flow PASS. Проверены wrong key/attempt/profile, healthy/CAPTCHA refusal, proof window, pause/sleep, revoked/changed catalog/cancelled validator, сохранение rejected candidate/token/seen revision и отсутствие повторного recovery. SCM start/stop в этих сценариях не исполнялись; valid conditional request при пустом private runtime отказал после read-only SCM query.
- Actual C#→Go LKG key verification, managed builder и enrollment key/manifest bridges PASS; Python server-contract/Unicode ETag/share interop PASS. HTTP/status/recovery callbacks синтетические; это не live TLS/VPN evidence.
- WPF publish0 warnings/errors, native single-window/nested/busy/close/WebView PASS с ServicesUsed=false/NetworkChanged=false. Dark/light managed420×740 top/bottom renders осмотрены. Offline StateDigestUnchanged=true, preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK; другой VPN не отключался. Baseline23 SHA/vendor package PASS.
- Архив `clients/windows/artifacts/FreeTurn-Windows-0.16.0-preview-win-x64.zip`: 86.14MiB/16 entries/15 payload SHA/177 source files/81 notices; SHA256 `e6b50c7b58714171c4f283747101d6fdd21621305cccc2793b29a0157c39952b`. Payload/source correspondence PASS,0.15 не изменён.

## Оставшиеся ограничения

Реальные managed HTTPS/VPN/LKG recovery/revocation/SCM stop/leak/sleep/disk-fault проверки — **NOT RUN**. Старую конфигурацию сервер должен продолжать принимать; snapshot прежней работоспособности этого не гарантирует. Ошибка подготовки/SCM Start до принятого Connect не создаёт trial, пользователь повторяет действие вручную. Частичная ошибка service config write остаётся fail-closed через profile/options/WG consistency check, без обещания transactional rollback всех SYSTEM файлов. Долгая CAPTCHA не вызывает recovery. Перезапуск UI не включает VPN и не продолжает прежний trial. Отдельная фоновая служба подписок/автоматический Direct↔Relay не реализованы этим блоком.

Самопроверка без субагентов. Полный серверный Linux suite не повторялся, серверный код/API/SQLite/schema/vendor не менялись. Installed services, VPS, реальные ключи/профили и GitHub не тронуты.
