# Общесистемная маршрутизация Windows

## Checkpoint0.22 — app path rules,17.11.2026

EXE full-path DIRECT/VPN/BLOCK + Windows IPv4 owner table/held process handle/tuple validation встроены в source-aware TCP/UDP dial. Unknown owner блокируется только при наличии правил; DNS общий; BLOCK/protected management сохраняются. UI/editor/settings/backup/capability/aggregate status реализованы. Local native TCP/UDP loopback + synthetic policy/owner/gVisor/WG/C#/UI/offline checks PASS. Actual app→TUN owner matching, UDP throughput/PPL/helper/transfer/reuse/WFP/leak E2E NOT RUN. Это путь/creator PID, не binary sandbox. [Результат0.22](WINDOWS_APP_RULES_PLAN.md). Ниже — история.

## Checkpoint0.21 — .local A resolver,17.11.2026

DNS-маршрутизатор получил одноразовый legacy mDNS для private on-link IPv4/local имён: interface/index/source/mask/packet-info pin, ограниченные concurrency/timeout/packets, no fallback/no durable names. Socket только внутри opt-in runtime; readonly preview/status не делает multicast. Go/C#/native/Windows loopback/offline checks PASS. Реальная multicast/LAN/Windows resolver/native5353/Bonjour/TUN/WFP/leak приёмка NOT RUN; DNS-SD browser/PTR/SRV не реализованы. Новых WFP exemptions, listener5353 или multicast membership нет. [Результат0.21](WINDOWS_MDNS_PLAN.md). Ниже — история.

## Checkpoint0.20 — GeoIP,17.11.2026

IP fallback использует DB-IP Lite2026-11 (12902 RU IPv4 prefixes) вместо IPverse/RIR. Original source, CC BY4.0/атрибуция, compressed/raw SHA и reproducible compilation закреплены; runtime проверяет каталог/provenance/protected ranges. UI показывает базу пакета. Local Go/Python/actual C#→Go/build/native/offline/hash checks PASS; real GeoIP/TUN/WFP/VPN/leak E2E NOT RUN. Без runtime downloads. [Результат0.20](WINDOWS_GEOIP_PLAN.md). Ниже — исторические checkpoints; local unicast DNS уже реализован в0.11, mDNS остаётся отдельной задачей.

## Актуальный checkpoint0.11 — 17.11.2026

Готов отдельный `clients/windows/artifacts/FreeTurn-Windows-0.11.0-preview-win-x64.zip`,86.01MiB/16 entries/15 payload SHA/141 source files/81 notices. SHA256 `3a72169c12b781af8c225c65f839b3f6b5a6cc769b9fa30e0114afdd57344f16`; hashes и source correspondence PASS.0.9/0.10 заморожены неизменными. Для новых проверок выбирать0.11: исправлена избыточная encrypted hostname history0.10 — теперь durable keyed HMAC→IP без имён; v1 мигрирует атомарно с сохранением ключа/IP/head. Добавлен private on-link unicast DNS без публичного fallback; TCP opaque recovery через bounded SNI/HTTP Host, до dial. ECH/unknown UDP/server-first могут требовать нового DNS/перезапуска приложения. Private A остаётся настоящим LAN IPv4, mDNS не обещается.

Go test/vet, DPAPI/AES migration/identity/leak/refusal, C# build/catalog/interop, synthetic single-window и component renders PASS; offline network digest неизменён. Новые службы/реальное VPN/TUN/WFP/LAN E2E **NOT RUN**. [Полное решение, проверенный объём и границы](WINDOWS_LAN_DNS_PLAN.md). Записи0.10 ниже — история; дальнейший managed/failover блок новой версией.

## Проверенный checkpoint0.10 — 17.11.2026

Собран локальный `clients/windows/artifacts/FreeTurn-Windows-0.10.0-preview-win-x64.zip`: **85.92MiB,16 entries/15 payload hashes,137 source files,81 notices**. SHA256 `08b22960e732846aa18672d4e59838a39fca4ca1e74c3ecd05019011a1bf9107`. Все payload hashes и каждый source-файл сопоставлены checkout.0.9 ZIP неизменён. Службы не обновлялись, настоящий VPN не запускался.0.10 сохранить как замороженный checkpoint; следующие изменения — отдельной версией.

Выполнены opt-in `connect.systemRouting`, strict SYSTEM DPAPI options, service branch, numeric WG/egress health, раздельные setup stages,7 presets/domain editor/direct DNS UI и CurrentUser backup/restore. Обычный WGNT default сохранён. SCM Running означает готовность принимать Stop, а не VPN Connected; async startup отменяется с ожиданием rollback. Connected требует handshake и fresh VPN-bound HTTPS proof. Broker не читает отсутствующий WGNT adapter и не получает WFP bypass. UI различает сохранённую preference и actual active. Сохранение само не меняет сеть.

Persistent fake-IP history: root-owned AES-256-GCM append journal + durable encrypted high-water mark, key в SYSTEM DPAPI; fsync до DNS-ответа. Marker сохраняется также в обычном WGNT Connect. Пул131066 имён/64MiB; no reuse/reset. Между профилями переносятся только identities, не decisions/real IP. User backup историю не переносит/не очищает; обычный WGNT её не открывает. Коррупция/потеря/ошибка записи — отказ с безопасным кодом; pool/write ошибки видны в status/journal без hostname. При смене режима приложению с собственным fake DNS cache может понадобиться перезапуск.

**Фактические проверки:** Go49 top-level+8 subtests PASS/0 skips, vet; C# build/publish0 warnings; C#→Go inactive preview и crypto/catalog/preferences/key preservation PASS. Temp CurrentUser DPAPI/AES tests: reversed DNS order/reopen, fresh resolution, tamper/missing/write failure и committed boundary truncation PASS. SYSTEM deployment журнала NOT RUN. Native single-window/nested/close/WebView scenario с новой страницей PASS, synthetic/no services/network. Dark/light420×740 и lower component render просмотрены; DNS textbox clipping исправлен. Offline import/previews/foreground guards PASS, route/adapter/service digest до/после одинаков. Новый normal-user client прочитал прежнюю SYSTEM-службу (stopped/HasProfile=true); это не new-runtime activation. Baseline23 SHA/package verifier PASS. Реальные0.10 TUN/WFP/VPN/DNS/IPv6 leaks/crash/sleep/скорость **NOT RUN**.

Self-review выполнен самостоятельно по ограничению пользователя без субагентов: исправлены cross-session fake-IP alias, точный TCP443 management fence (UDP443 запрещён), SCM cancellation и clipping DNS поля. Полный redesign не выполнялся.

16–17.11.2026. Продолжение по поручению пользователя; редизайн отложен. Без субагентов, VPS, GitHub и изменения маршрутов текущего компьютера. Применяются brainstorming/writing-plans и verification-before-completion; требования семи presets/custom domains уже согласованы в ТЗ. Обычный подтверждённый WGNT/FreeTurn path сохраняется. Текущее ночное окно заканчивается **17.11.2026 в07:00 Asia/Tomsk (00:00 UTC)**.

## Выбор реализации

Записи21:00 UTC ниже — история промежуточного WIP; их предсборочный статус закрыт проверенным checkpoint в шапке.

**Ночное продолжение, 21:00 UTC16.11 (04:00 Томск17.11): WIP0.10.** Opt-in IPC/strict SYSTEM DPAPI options, новый service branch, numeric health/egress report, SCM-controllable async startup/cancel и C# settings/backup/editor уже написаны. Go46 top-level+8 subtests, vet, C# build/catalog crypto/preferences и C#→Go inactive preview PASS. Component render dark/light420×740 просмотрен; без native окна/службы.0.9 ZIP не менялся;0.10 ещё не упакован/не установлен.

**Исправлено до выдачи:** stale app DNS cache больше не получает чужой hostname после reconnect. Реализован root-owned append-only AES-256-GCM journal с DPAPI-wrapped key, отдельным durable encrypted high-water mark и fsync до DNS-ответа. Identity mapping сохраняется; route decisions/реальные IP не переносятся между профилями. Пул131066 имён/64MiB, адреса не переиспользуются. Marker в SYSTEM connection options сохраняется также при обычном WGNT connect; утрата/порча истории, boundary truncation и невозможность записи дают отказ, не reset. История не включена в user backup; обычный WGNT её не открывает. Реальные DPAPI/AES reopen/reverse order/current-path refresh/tamper/write-failure/truncation checks PASS. Никаких настоящих TUN/WFP/VPN запусков. Source0.10 ещё требует финального rebuild/проверки пакета после последнего protocol-fence исправления: management разрешён только TCP443, UDP443 запрещён.0.9 ZIP неизменён.

Рассмотрены три варианта: раздавать IP routes по результатам DNS (не различает shared CDN и конфликтующие домены, отклонено); собственный WFP callout driver (отдельная подпись/драйвер/разработка, не первый этап); TUN с per-flow обработчиком и согласованным DNS (выбрано). Полный sing-box содержит много ненужных этому проекту протоколов и зависимостей; используем узкую sing-tun library и существующую WG crypto реализацию. Официальный WG firewall можно применить к новому TUN LUID внутри того же tunnel-service process, не расширяя права UI/broker.

Источник: pinned WG Windows firewall запрещает физический bypass приложений при /0. Поэтому новый режим не может быть просто набором AllowedIPs или правилами существующего SOCKS. Документация: https://git.zx2c4.com/wireguard-windows/about/docs/netquirk.md ; https://sing-box.sagernet.org/configuration/inbound/tun/ . Локально проверен API sing-tun v0.9.6, commit ddaa4ca25e3bcb776d6ce81f4477b3becb5426de. New() создаёт адаптер/настраивает сеть: его нельзя вызывать из validation/preview.

**Уточнение после проверки исходников:** sing-tun system stack в `Start()` автоматически добавляет persistent inbound allow для EXE на всех профилях firewall. Этот backend отклонён. Используется только **gVisor stack**, build tag `with_gvisor`; без него mutating entry point возвращает `SYSTEM_ROUTING_BUILD_REQUIRED` до любых изменений. Компиляция и реальная передача пакетов gVisor→handler→userspace WG→loopback peer проверены. Полный sing-box не используется.

## Границы и порядок

1. Отдельная strict versioned policy, default VPN, BLOCK выше разрешений, protected VPN management выше LAN/RU bypass, YouTube/push выше RU. Явно различать поддержанные и ещё отсутствующие возможности. Не обещать распознавание torrent через произвольное шифрование/нестандартный протокол; реальные границы блокировки документировать.
2. DNS policy и fake-IP lease mapping сохраняют hostname для TCP/UDP на shared IP. Ни один BLOCK не делает DNS/dial; нет VPN→DIRECT fallback. A/AAAA/CNAME/TTL, cache bounds и pinned flow decisions — существенные проверки. IPv6 до подтверждения серверного IPv6 egress блокируется, а не уходит физически.
3. Реальные TCP/UDP dispatchers, strict interface binding для DIRECT, VPN через userspace WG netstack с прежними ключами и loopback FreeTurn endpoint. Проверка synthetic packets/loopback без создания системного VPN.
4. Отдельный opt-in Windows TUN adapter и lifecycle: firewall до публикации default route; только собственные адреса/routes/DNS; cleanup/rollback; driver hash/signature. Обычный WGNT режим сохраняется, при ошибке новый режим не переключается молча на unfiltered DIRECT.
5. Отдельные DPAPI settings/IPC capability и честное состояние requested/validated/active. UI не должен показывать «применено» после одной проверки схемы. Текущая рабочая portable share URI и ключи не меняются.
6. Реальная проверка пользователем: custom direct/VPN/block на shared IP, LAN, split DNS, protected management, IPv6 refusal/leaks, UDP/QUIC и rollback. Без этой проверки новый backend не считается принятым системным маршрутизатором.

## Задачи текущей разработки

- [x] Чистое policy/DNS ядро, immutable compiled matchers/IPSet и strict inactive preview.
- [x] Stateful DNS/flow layer, bounded leases и TCP/UDP packet dispatch без OS changes.
- [x] Userspace WG/loopback spike и полный in-memory packet proof: TCP/UDP/DNS.
- [x] Root-only TUN lifecycle: external configuration, WFP до routes, owned routes/DNS и rollback; opt-in service branch связан. Реальный TUN/WFP запуск NOT RUN.
- [x] Opt-in IPC/DPAPI, service lifecycle/health, UI settings/backup; WGNT default сохранён.
- [x] Пакет0.10/локальные проверки; OS routes/VPN E2E — NOT RUN до пользовательского запуска.

## Фундамент до интеграции — история проверок

`system_*_windows.go` содержит policy, fake DNS/journal, TCP/UDP dispatchers, numeric physical binding, memory WG, read-only collision/capture preflight, service branch и mutating backend. Preview `--check-system-routing` всегда `active:false/networkChanged:false`; `runtimeIntegrated:true` при with_gvisor означает наличие кода, не подтверждённую OS-приёмку. Preview не создаёт адаптер, не вызывает DNS/preflight и не обращается к SYSTEM DPAPI.

Закреплены sing-tun v0.9.6 и транзитивные модули; stock AmneziaWG netstack совместим с Go1.27.3. Wintun0.14.1 amd64 из module cache совпал с официальным архивом и имеет Valid Authenticode/WireGuard LLC. Полная лицензия prebuilt binary сохранена отдельно. Build helpers проверяют версии/hash/signature и включают data/source/license artifacts; текущий готовый0.9 ZIP не перезаписан.

Data snapshot: V2Fly category-ru с recursive includes и .ru/.su/.рф —1923 suffix+236 exact; YouTube/GoogleFCM/connectivity + узкие Apple APNs domains. IPverse RU —8676 IPv4 prefixes, **RIR allocation hint, не точный GeoIP**. Источники/компиляция/лицензии закреплены в `clients/windows/routing-data.lock.json`; `sources.zip` содержит89 использованных исходных файлов. Runtime ничего не скачивает.

DNS: bounded non-recycled fake IP, separate hostname identity даже на shared IP, CNAME BLOCK/loop/depth checks, повторное разрешение при CNAME DIRECT→VPN, NODATA для AAAA/HTTPS/SVCB, отсутствие межмаршрутного fallback. TTL учитывает A/CNAME и ограничен60с; просроченный fake-IP flow повторно разрешает имя через bounded DNS handler до dial, отказ resolver не использует stale адрес. TTL0 передаётся как0, только доставленному ответу даётся1с на немедленное подключение. Если splitDNS выключен — DNS только через VPN. Country-IP fallback первоначально разрешается VPN DNS; неизвестные/mixed pools не получают неявный direct DNS. TCP retry для усечённого UDP DNS остаётся на том же path/server.

Проверки17.11: Go **42 top-level +8 subtests PASS**,0 skips/failures; vet и dev engine build PASS. In-memory packet test создаёт приложение/netstack, fake TUN endpoint, реальный gVisor forwarding, DNS и два зашифрованных WG peer; TCP/UDP echo и DNS завершились без системного адаптера/маршрутов. Handler cancel, plaintext BitTorrent refusal, no-fallback, CNAME path change, shared IP, metadata/management, capture route collision и injected route/DNS/flush rollback PASS. Manager Windows unittest **125 tests, OK,15 skips**. Baseline23 SHA и исходный package verifier PASS. Реальный TUN/WFP/DNS/leak/cleanup E2E — **NOT RUN**.

## Выполненная интеграция (история плана)

1. Связать runtime с ограниченным IPC/connection options и SYSTEM DPAPI; optional mode off по умолчанию. Не запускать его из check/status/preview. Strict validation до SCM Start; reject unsupported profiles заранее.
2. Внутри tunnel service передавать userspace WG handshake/rx/tx и собственный VPN-bound egress probe. Broker не должен пытаться читать отсутствующий WGNT adapter или получать расширенный WFP bypass. `memoryWG.Health()` уже выдаёт только числовой snapshot, без содержимого IpcGet.
3. Добавить настройки семи presets и domain editor с честными requested/validated/active, backup/migration, отдельной capability и версией. Обновление служб/реальное Connect остаются пользователю.
4. Закончить частные ограничения ниже, собрать отдельную новую версию и зафиксировать дальнейшие NOT RUN. До дедлайна продолжать доступные задачи; после00:00 UTC новых изменений не начинать.

## Ещё не завершено

Следующий ночной блок: не повторять0.10/spike. До07:00 Томск продолжать доступный технический объём новой версией: LAN/private DNS compatibility (сначала исследовать Windows mDNS/WFP, без broad allow/public leakage) либо Windows managed/Connection Manager по локальным контрактам. Решение записать до кода. Недоступные E2E/внешние данные отмечать NOT RUN и идти к независимой задаче. Не выполнять VPS/deploy, GitHub, обновление служб или реальный Connect. После00:00 UTC реализацию прекратить и оставить итог.

Always-on OS network lock при crash/boot не реализован; WFP действует при живой службе. Отдельный SOCKS в новом режиме недоступен. Actual new-runtime acceptance T29–T31 остаётся открытой.

App-process matching, private LAN-name resolver/mDNS, проверенный GeoIP вместо RIR hint, auto-update списков и managed panel policy delivery отсутствуют. Private names сейчас отвергаются и не отправляются публичному DNS. Новый runtime пока ограничен baseline subnet10.77.43.0/24 с public IPv4 WG DNS; другие сети/private DNS требуют явного защищённого management/DNS context и сейчас получают отказ. Ни один из этих scopes не должен стать фиктивной галочкой.

BitTorrent: распознаются plaintext handshake и известные DHT signatures; произвольный encrypted/obfuscated torrent не обещается. ECH/own DoH/DoT/IP literals могут скрывать домен: тогда применяется IP policy/RU fallback, остальные неизвестные IP остаются VPN; приоритет доменных YouTube/push исключений без имени не гарантирован. TLS interception нет, DNSSEC validation поверх синтетических A не обещается. IPv6 блокируется до отдельной приёмки. DIRECT сейчас IPv4 и фиксированный physical interface/source; смена сети требует reconnect, бесшовное восстановление ещё не подтверждено. Native lifecycle существует только как подготовленный код: actual service activation, WFP capture, DNS switching, LAN overlap, crash/stop/sleep recovery и реальная скорость **NOT RUN**.
