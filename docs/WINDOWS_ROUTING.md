# Windows0.6: доменные правила SOCKS5

16.11.2026, Asia/Tomsk. Продолжение Windows-переноса по поручению пользователя, без субагентов, установки/обновления служб, реального VPN, VPS и GitHub. Это законченный первый блок доменного маршрутизатора для существующего SOCKS5, **не общесистемная маршрутизация Windows и не завершение T29–T31**.

## Реализованный путь

`SOCKS5 auth → hostname → BLOCK / VPN / DIRECT → resolver выбранного интерфейса → public IPv4 TCP`. Без совпадения — VPN. BLOCK проверяется до DNS и выше любых совпавших разрешений; среди разрешений выигрывает наиболее специфичный exact/suffix rule, exact выигрывает при равном имени. Совпадение только по границе DNS label: `example.com` не совпадает с `notexample.com`. Кириллица/IDNA и конечная точка нормализуются, дубликаты объединяются, конфликт одинакового domain+mode отклоняется. До300 правил, bounded IPC/CLI input; URL/порт/credentials/regex/wildcard/IP/public-suffix-only entries запрещены. PSL и IDNA — существующий pinned `golang.org/x/net v0.60.0`, без online list fetch.

У SOCKS5 появился отдельный русский редактор: домен, действие «Напрямую / Через VPN / Блокировать», поддомены, поиск/изменить/удалить, локальная проверка решения. Редактор и сохранение доступны без службы/подключения. Применение — при новом запуске SOCKS5; работающий listener использует неизменяемый snapshot. Запуск с правилами требует capability `socks-domain-routing-v1`, то есть службу0.6+. Старой службе правила не отправляются как будто они поддерживаются. Обычный proxy без правил сохраняет прежнюю совместимость.

Политика хранится внутри CurrentUser DPAPI proxy settings и общего encrypted backup; merge с восстановлением preferences возвращает её. Профили, WG/PSK/CID и portable URI/managed-v1 не изменены. В приложении пользователь указывает remote DNS через SOCKS5 (`socks5h`); если программа передала уже готовый IP, домен неизвестен и применяется VPN default. Постоянной истории сайтов/DNS и raw exceptions нет.

## Сеть и граница прав

VPN TCP/DNS привязаны к WG source IPv4+LUID. DIRECT TCP/DNS — к physical source IPv4+LUID и DNS этого интерфейса, выбранного до туннеля. Перед каждым новым сокетом проверяются LUID/index, наличие source и состояние Up. DNS-запросы абсолютные, без подстановки системного DNS search suffix. Resolver failure не включает другой resolver/интерфейс; VPN failure не вызывает DIRECT fallback. Private/LAN/metadata/special IPv4 и IPv6 назначения запрещены на обоих путях. CIDR/AllowedIPs/firewall для доменов не переписываются; shared CDN IP не становится глобальным исключением.

При анализе pinned WireGuard Windows1.1.1 найдено, что `permitWireGuardService` проверяет и EXE, и **SID конкретной tunnel service**. Поэтому DIRECT не исполняется из broker и не получает нового широкого WFP-исключения. Узкий внутренний pipe `FreeTurnManager.Direct.v1` передаёт bounded hostname:port из broker в tunnel process, где создаётся физический сокет. Только SYSTEM/admin ACL, обе стороны проверяют session0/PID/SCM Running/fixed binary/LocalSystem до передачи домена/создания сокета. Anonymous impersonation, нет shell/произвольных путей/правил firewall. При отсутствии relay/physical DNS DIRECT отказывает, полный прежний VPN может продолжать работать. Pipe message-mode сохраняет TCP half-close. Лимит32 relay clients и idle timeout2минуты.

При утрате подтверждённого VPN прежний broker watchdog останавливает весь SOCKS, включая DIRECT; tunnel shutdown закрывает relay. Отдельный SOCKS-stop закрывает broker-side clients; остаточный half-closed direct stream ограничен idle timeout и закрывается при shutdown. Точность firewall/egress/cleanup на настоящем подключении остаётся к проверке.

Primary references: [Microsoft IP_UNICAST_IF](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options), [Go IDNA](https://pkg.go.dev/golang.org/x/net/idna), [Go PSL](https://pkg.go.dev/golang.org/x/net/publicsuffix). Реально прочитан также pinned local module `wireguard/windows@v1.1.1/tunnel/firewall/rules.go` и `helpers.go`; module checksum закреплён. Зависимости не обновлялись автоматически.

## Проверки

- Targeted Go tests/vet: PASS. IDNA/границы/precedence/conflicts/limits, BLOCK до dial, отсутствие route fallback, strict JSON/unknown fields, настоящий spoofed named pipe отказал до передачи домена, bounded relay frame, синтетический stream. Отдельный реальный local message pipe + loopback TCP подтвердил ответ после upload EOF (half-close).
- Native DPAPI/catalog/backup: PASS, новые rules переживают encrypted roundtrip/preferences restore, исходные shares/keys не меняются; прежние AES-GCM/tamper/merge/corruption проверки сохранены.
- Published engine `--check-routing`: PASS для шести synthetic decisions, IDNA и трёх invalid policies. Команда не читает private profile и не выполняет DNS/сеть.
- Read-only SYSTEM broker authentication/status непривилегированным пользователем: PASS; прежняя служба0.1.1 stopped, HasProfile=true. Службы не обновлялись.
- Offline synthetic import/foreground guards и route+adapter+service digest: PASS, неизменён. Preflight отказал из-за другого VPN/nonphysical uplink; чужой VPN не трогался.
- WPF Release build/publish: PASS,0 warnings/errors; dark/light/420/520 routing и SOCKS renders просмотрены. Native editor workflow до итогового отчёта отдельно отмечается ниже; snapshot не является сетевым E2E.
- Native `--preview-routing`: Add/decision preview PASS. В настоящее окно введён `ПРИМЕР.РФ.`, «Добавить» вызвал packaged engine и вернул нормализованное правило; проверка `sub.blocked.example.com` показала BLOCK без DNS. После нажатия «Сохранить» итоговое закрытие окна не подтверждено: пользователь остановил Computer Use физическим Escape при следующем наблюдении; дальнейшего UI-ввода не выполнялось. Callback сохранения synthetic, не реальный каталог. Реальная DPAPI/backup запись отдельно проверена catalog-check. Скролл, читаемость dark switch и постоянно видимые footer actions подтверждены.

Новые interface-bound DIRECT/DNS и authenticated SYSTEM↔SYSTEM runtime, реальный SOCKS/WG egress, leak tests, VPN/CAPTCHA/sleep/resume/clean uninstall: **NOT RUN**. Код и локальные synthetic tests не подтверждают их прохождение. Настоящие Android/iPhone E2E новой версии: **NOT RUN**.

## Оставшийся объём

Общесистемный TUN/netstack или WFP flow backend для доменов и Windows-программ; RU/LAN/YouTube/push/connectivity presets, GeoIP, системный split DNS и BitTorrent enforcement. Текущие custom SOCKS rules — пригодный отдельный слой classifier/DNS intent, не подмена этих требований. Затем AWG, managed enrollment/bootstrap/subscriptions и Direct↔Relay recovery, server installer/access lifecycle, hotspot/UDP/IPv6/preferences/updater. QR на Windows исключён пользователем.

Новая сборка `clients/windows/artifacts/FreeTurn-Windows-0.6.0-preview-win-x64.zip`:77.30MiB,14 entries/13 проверенных payload SHA256;76 исходных файлов побайтово соответствуют workspace, без preview PNG/QR codec/ZXing/private artifacts. SHA256 `8e192455845bec0fc2b1fdfdbf72f98c1aba871a57131fee31274cab1b335c8a`.61 dependency notices; font/driver hashes и официальная подпись WireGuardNT PASS. Собственные EXE пока unsigned. Baseline23 SHA/vendor package и git diff whitespace check PASS. Установленное приложение/службы/рабочие профили не заменялись.
