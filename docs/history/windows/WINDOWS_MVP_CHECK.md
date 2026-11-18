# Windows MVP: фактическое состояние

15.11.2026. Без субагентов. Пользователь выбрал сначала Windows с обычным профилем и затем **самостоятельную установку/проверку**. Это предварительная сборка, не закрытие Windows E2E или всего ТЗ.

## Реализовано

`clients/windows/engine`: Go facade поверх неизменённых FreeTurn v4.1.5/mobile и WireGuard Windows v1.1.1/tunnel, локальный protocol v1, DPAPI, Windows DACL/ownership, фиксированные SCM-службы и пути, защита внешних сокетов через IP_UNICAST_IF. Импорт ограничен текущим VK/UDP/TURN-TCP/rtpopus3/WG профилем; команды/hooks, произвольный WG endpoint, неизвестные поля и дубликаты JSON отвергаются. UI не получает ключи обратно. При установке владельцем privileged файлов становится Administrators; одного удаления user ACE недостаточно для защиты от последующей смены DACL владельцем.

`clients/windows/ui`: WPF/.NET 8, русское окно, файл/текст `freeturn://`, установка собственных служб через UAC, Connect/Disconnect, раздельные состояния SCM/transport/handshake/egress. WebView2 использует штатный локальный CAPTCHA proxy, InPrivate и запрет downloads/host objects. Флажок автоматической CAPTCHA меняет только `mcap` импортируемой копии; обещания полного отсутствия CAPTCHA нет. Existing Android/iPhone profiles не меняются.

Готовая сборка: `clients/windows/artifacts/FreeTurn-Windows-0.1.0-preview-win-x64.zip`, 10 явно перечисленных файлов. EXE не подписаны; WireGuardNT имеет действительную подпись WireGuard LLC. В архив включены license/notice тексты зависимостей и SHA256SUMS. Приватный профиль в архив не включён.

## Проверено на настоящем Windows, без установки VPN

| Проверка | Результат |
| --- | --- |
| Совместная Go сборка FreeTurn mobile + официальный WireGuard tunnel | PASS |
| Go test: 5 целевых проверок импорта/ключей/DPAPI/ACL/IPC | PASS |
| DPAPI encrypt/decrypt, неверное purpose, атомарная замена | PASS под текущим Windows-пользователем; не SYSTEM E2E |
| User pipe ACE без FILE_CREATE_PIPE_INSTANCE, отказ kernel create и положительный контроль с полным ACE | PASS непривилегированным токеном |
| Реальный named pipe framing | PASS с current-user server; это не UI↔SYSTEM |
| Go vet | PASS |
| WPF self-contained win-x64 publish | PASS, 0 ошибок/предупреждений |
| Настоящее WPF окно: ввод синтетического профиля → «Проверить профиль», безопасный отказ на неверный ввод | PASS; установка/Connect не нажимались |
| Собранный CLI: no default action, foreground --broker/--tunnel отказали до применения | PASS |
| Снимки routes/adapters/собственных services/storage до/после offline verifier | PASS: digest одинаков |
| Пакет ZIP | PASS: 10 ожидаемых файлов, все 9 payload SHA256 совпали |
| Actual private Windows profile через stdin --check-profile | PASS, содержимое не печаталось |
| Windows preflight | BLOCKED: уже активный другой WireGuard preferred default route; ничего не отключалось |
| Existing Python regression | PASS:125 tests,15 skipped на Windows |
| Baseline SHA256/package verification | PASS:23 сохранённых файла, binary/bootstrap/runtime checksums |

`build.ps1` выполняет pinned downloads/hash/Authenticode, go test/vet/build, locked NuGet publish и сборку архива. `verify_offline.ps1` воспроизводит безопасные CLI-сценарии и сравнение состояния. Результат: ignored `artifacts/offline-check.json`. Скриншот и работа с окном — проверка UI, не свидетельство работающего VPN.

## Выдача отдельного Windows peer на тестовом VPS

Создан постоянный `Windows PC`, device `0cf9e8f7-b3fd-468a-b295-a1949a677ba3`, VPN IPv4 `10.77.43.25`. Использован существующий Store + фиксированный root agent под lifecycle flock; новый WG public key/PSK/CID независимы от Android/iPhone. Legacy state и все прежние device key/PSK/CID/IP hashes совпали; старые kernel peer параметры сохранены. Серверные VPN/control/SSH PIDs и restart counters не менялись. Metadata18, active kernel peers3.

Plain share, без bootstrap expiry, сохранён root0600 в `/root/ftm-windows-2026-11-15/Windows-FreeTurn.txt`; private копия — `C:/Users/admin/Downloads/FreeTurn-Windows-2026-11-15/Windows-FreeTurn.txt`. Новая ссылка использует штатную автоматическую CAPTCHA (`mcap=false`). Ключи/ссылка/PSK в этот документ, репозиторий и диагностический вывод не включались.

До и после операции созданы combined encrypted checkpoints в root-only каталоге выдачи. SHA256 post checkpoint: `fd7485eae7f2a5042cb0780f708fe5967dfbd2309a105d19661d55c0e45ab69f`. Offsite ciphertext сохранён в private Downloads как `manager-after-windows.vpnbackup`; реальный WSL decode/stage **PASS**: version2,18 devices,3 owned peers, `live_system_changed=false`. Live restore/reboot не выполнялись.

## Осталось

- Установка служб выполнена пользователем; работающий SYSTEM broker и его конфигурация подтверждены. Native client↔SYSTEM IPC и сохранение/чтение профиля под SYSTEM после исправления0.1.1 — PASS (см. ниже). Автоматизация UAC/удаление — NOT RUN.
- Драйвер, наружные защищённые сокеты вместе с WFP kill switch, live CAPTCHA WebView2 — NOT RUN.
- Windows↔тестовый VPS: handshake, egress, DNS/IPv6 policy, отключение/cleanup, сбои и повторное соединение — NOT RUN, пользователь проверяет самостоятельно. Сам факт active peer на сервере не подтверждает клиентское подключение.
- Роуминг, виртуальный uplink, обновление, подписки/bootstrap/QR, routing presets и plain-domain editor — следующие итерации; интерфейс их не изображает готовыми.
- Android/iPhone новые E2E и три одновременных настоящих клиента — NOT RUN. Ранее подтверждённый iPhone профиль сохранён.

## Исправление импорта в UI0.1.1

Пользователь сообщил о невозможности импорта после самостоятельной установки. Реальная служба `FreeTurnManager` работала под LocalSystem, туннель stopped; окно показывало «Служба недоступна». Вызов исходного ServiceClient под обычным пользователем воспроизвёл `UNTRUSTED_PIPE`; уточнённая безопасная диагностика локализовала `OpenProcess(0x1000)` → Win32 error5. Наличие прав SERVICE_QUERY_STATUS не даёт права читать SYSTEM process — предположение первой версии оказалось неверным.

Исправление сохраняет проверку подлинности до отправки профиля: pipe PID совпадает с running SCM service PID, pipe server session0, SCM account LocalSystem, type OWN_PROCESS, бинарник в фиксированном защищённом Program Files и единственный аргумент `--broker`. Читаются только SERVICE_QUERY_STATUS/QUERY_CONFIG. Проверка процесса не выполняется; DACL/права и режим запуска UI не ослаблялись.

Реальный `verify_service.ps1`: `Elevated=false, VerifiedService=true, State=stopped` PASS. WPF publish0.1.1 и пакет собраны без предупреждений. Копия пользователя `C:/Users/admin/Desktop/FTP/FreeTurn.Windows.exe` заменена проверенным EXE; старый сохранён рядом как `FreeTurn.Windows.0.1.0.before-ipc-fix.exe`. Новое настоящее окно показало «VPN отключён» и активную кнопку импорта. Пользователь затем закрыл окно во время восстановления ввода; дальнейшие UI inputs прекращены. Сохранённый ввод сравнен с private issued file в памяти без вывода содержимого — совпал. Этот профиль импортирован через исправленный ServiceClient в существующий broker; ответ `HasProfile=true, State=stopped`, повторный status/decrypt/parse под SYSTEM PASS. Полный повторный GUI-click import не объявляется выполненным.

Новая сборка: `FreeTurn-Windows-0.1.1-preview-win-x64.zip`. На ПК не запускались FTМ tunnel/новый VPN и не останавливался другой VPN; сервер в этом исправлении не затрагивался. Связь со службой/импорт исправлены, handshake/интернет остаются проверкой пользователя.
