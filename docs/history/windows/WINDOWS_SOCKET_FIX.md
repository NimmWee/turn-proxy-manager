# Windows 0.7.1: отказ защиты неподключённых сокетов

16.11.2026. Проверка по сообщению пользователя о повторном отказе подключения. Подключение пользователь запускает сам; агент не включал FreeTurn и не отключал Amnezia.

## Что показали настоящие журналы

- Установленный broker уже 0.7.0, профиль есть. На момент чтения tunnel stopped/1077: после последней загрузки Windows запусков этой службы не было. Это не опровергает предыдущие попытки пользователя.
- Защищённый WireGuard ring log прочитан только для чтения. В сохранённых попытках адаптер создавался, firewall и конфигурация применялись, `Startup complete` достигался. Затем повторялись отправка handshake и timeout, ответного handshake в распознанных записях нет.
- Сохранённый SYSTEM DPAPI runtime последней попытки: 15.11.2026 19:06:55–19:08:12 UTC, `connecting`, этап `vk_auth`, `NETWORK_TIMEOUT`, **0/6 потоков**, активной CAPTCHA нет. Успешного TURN-канала этот snapshot не подтверждает.
- SCM также содержал ошибку broker «не найден путь». В callback завершения broker найден `return false, 3`: приложение само передавало Win32 ERROR_PATH_NOT_FOUND при любой ошибке остановки. Эту строку журнала нельзя считать доказательством отсутствующего пути.

Чтение runtime выполнено отдельной одноразовой задачей SYSTEM без расписания. Она запускала только фиксированный reader, затем была удалена в finally. Службы VPN не запускались/останавливались, маршруты и ACL профилей не менялись. Временный вывод содержит только allowlisted состояния, коды, timestamps, счётчики и metadata файлов. Сырые логи/содержимое профиля/ключи/CAPTCHA URL не выводились. Вариант с заимствованием token broker не получил доступа и удалён из кода; итоговый reader не использует impersonation или SeDebugPrivilege.

## Воспроизведённая причина в коде

`protector.Protect` определял IPv4/IPv6 через `getsockname`. Go вызывает socket Control **до bind/connect**, а Winsock на таком сокете возвращает WSAEINVAL (10022). В результате Protect возвращал false и stock mobile/netctl отклонял создаваемые сокеты. Ошибка затрагивала DNS/VK/TURN до появления рабочего канала. Это воспроизведённый блокирующий дефект Windows-порта, согласующийся с сохранённым timeout; отсутствие других последующих проблем ещё не доказано.

Целевой native regression создал настоящие неподключённые TCP4/UDP4/TCP6/UDP6 sockets, без отправки пакетов. На исходном коде **все четыре проверки FAIL**: getsockname invalid argument, protect rejected. Исправление получает AddressFamily через `getsockopt(SO_PROTOCOL_INFOW)`, которому не нужен bind, затем задаёт прежний IP_UNICAST_IF/IPV6_UNICAST_IF. Все четыре проверки **PASS**, назначенный interface index прочитан обратно из Winsock. Неизвестный/недействительный socket и отсутствующий underlay остаются fail closed. Тест использует loopback index и не меняет маршруты.

Первичные источники: [Microsoft getsockname / WSAEINVAL](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname), [SO_PROTOCOL_INFOW](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options), [IP_UNICAST_IF и byte order](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options).

## Дополнительные исправления диагностики

SCM exit codes теперь читаются отдельно: `svc.Run` возвращает ошибку dispatcher, но callback Execute WireGuard сообщает свою ошибку через SCM. Broker передаёт фиксированный safe code/stage и числовые Win32/service-specific codes; UI объясняет configuration/driver/adapter/firewall/network/start-timeout. 1077 и успешная остановка не превращаются в ошибку. Native regression PASS. Ошибка остановки broker теперь service-specific 3, а не Win32 path-not-found.

## Проверки и выдача

- Go test/vet и Release publish PASS. Целевой socket regression — реальный Winsock, не mock; полноценный VPN-трафик не проверяет.
- Catalog/DPAPI/AES-GCM/backup/key-isolation сценарии PASS.
- Published offline import/routing/foreground guards PASS, digest маршрутов/адаптеров/служб unchanged. Нынешний preflight видит другой активный VPN; это не объяснение старых попыток, для которых пользователь подтвердил отключённую Amnezia.
- Read-only IPC существующего SYSTEM broker PASS: stopped, HasProfile=true.
- Baseline23 SHA и vendor package PASS; baseline не изменён.
- Архив `clients/windows/artifacts/FreeTurn-Windows-0.7.1-preview-win-x64.zip`: 77.35MiB, 14 entries, 13 payload SHA256 и 85 corresponding source files проверены; 61 dependency notices. SHA256 `8ac95940193b0286b286c07fabaf1240cb2bab9a49ea9e36024fba68d3ebc5aa`.

**NOT RUN:** VPN/TURN/WG/egress после исправления, новая CAPTCHA, фактический upgrade/rollback 0.7.1 и аппаратные leak/sleep/network-switch сценарии. Установленная служба остаётся 0.7.0; пакет сам её не заменяет. VPS/профили/ключи не изменялись; GitHub push и субагенты не использовались.

Пользователю: распаковать весь 0.7.1 архив, закрыть старое окно, запустить новый FreeTurn.Windows.exe. При остановленном FreeTurn открыть Настройки → Продвинутые → Обновить службы, подтвердить UAC. Затем самостоятельно повторить подключение без другого VPN с прежним Windows-профилем. Одной замены EXE интерфейса недостаточно: исправление находится в системном engine.
