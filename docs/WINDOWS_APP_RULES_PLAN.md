# Windows0.22: правила по пути приложения

Продолжение согласованного ТЗ,17.11.2026 Asia/Tomsk. Без субагентов, реального VPN/SCM/маршрутов/VPS/GitHub. Скорость отложена. Package-0.22 отдельно, предыдущие releases сохраняются.

## Дизайн до кода

Правило: canonical local drive full EXE path + direct/vpn/block,≤64 entries,≤1024 UTF-8 bytes/path. Никаких basename/wildcard/parent-process inheritance/UNC/device/ADS/env expansion. Это маршрут по executable path, не проверка подписи/содержимого бинарника и не sandbox. Версионированный путь/другой helper EXE требует отдельного правила.

Выбран IP Helper owner lookup (Microsoft GetExtendedTcpTable/GetExtendedUdpTable + QueryFullProcessImageName) внутри текущего SYSTEM proxy. Native WFP ALE redirect/callout потребовал бы другой lifecycle/driver; basename matching ненадёжен. Новые firewall bypass для приложений не добавлять. TCP exact4tuple, UDP local endpoint: все wildcard/specific candidates должны иметь один PID, иначе unknown. Hold query-limited+synchronize process handle, live/process-creation identity и повторный tuple→PID до/после upstream dial. UDP повторно проверяет endpoint owner перед каждым send/delivery; неоднозначность/выход/ошибка закрывает flow. Это ограничивает reuse race, но snapshot APIs не дают атомарной kernel attribution; передача socket handles между процессами не определяется как новый executable-владелец. Нагрузку такого lookup требуется измерить при живой приёмке, не обещать ускорения.

- Если правил нет, owner lookup не выполняется, прежнее поведение сохраняется. Если правила есть и owner unknown/ambiguous, data flow блокируется (не пропускается через VPN в обход BLOCK). Неизвестный count агрегировать без PID/path/history.
- Приоритет: base BLOCK/BitTorrent/reserved/private protections; app BLOCK; protected management остаётся VPN при app DIRECT; затем app direct/vpn; затем обычные domain/preset defaults. App action выше обычных доменных исключений/пресетов, но не защитных ограничений. DNS53 обслуживается общей DNS policy: Windows может делегировать DNS сервису, поэтому отдельный DNS на приложение не обещается.
- Apps — optional appRules в systemPolicy v1; empty omitted. Settings/DPAPI/encrypted backup сохраняют правила. Старый backup без поля читается; старые версии с strict schema должны отказаться от новых непустых правил вместо молчаливого их удаления. В ordinary WGNT правила не работают; UI явно требует opt-in раздельного режима/нового Connect.
- Immutable compiled path map, bounded read-only owner snapshots≤4MiB/65536 rows/3 attempts; concurrency bound8. Нет paths/PID/команд в логах и status. Native owner reader только в flow, никогда из preview/parse/plan. Pure preview допускает supplied executable path и явно не подтверждает текущий процесс.
- UI: вложенный редактор в том же окне, EXE file picker/ручной путь/action/list/remove; доступно сохранить draft и parent Save. No live reconnect. Product help: scope TCP/UDP/DNS/helper paths/unknown block.

## Шаги

- [x] Targeted failing path/rule/priority/no-owner/ambiguous/stale/no-dial checks; native TCP/UDP loopback owner proof без VPN.
- [x] Policy + bounded owner reader + source-aware dial/connection lifetime; preserve DNS/protected paths and keys.
- [x] Settings/backup/pure preview and in-app editor; capability/status aggregate only.
- [x] Go/C#/native/build/offline/package hashes/old release preservation; реальные app/TUN/WFP/UDP/performance E2E NOT RUN.

## Источники

[Microsoft TCP owner table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable), [UDP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable), [image path](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew). UDP table не содержит remote endpoint; ambiguous bindings не угадывать.

## Результат17.11.2026

- На старом коде regression не компилировался (нет appRules/appAction/path validation); после реализации targeted checks PASS. Go policy имеет optional appRules/immutable compiled path map. Без включённого системного режима приложения не переопределяют маршрут, пустые appRules опускаются. Ordinary WGNT и Share/WG/CID/token не меняются.
- Реализованы bounded AF_INET owner tables (4MiB/65536 rows/3 resize attempts/8 concurrent snapshots), TCP exact tuple и UDP unique PID по local/wildcard endpoint. Query-limited+synchronize process handle удерживается до Close; creation/liveness/tuple recheck до/после dial, UDP до send/после recv до delivery. Snapshot attribution не атомарна; transferred handles сохраняют context-bind PID, это не sandbox/бинарная идентичность. UDP lookup cost и PPL/сложные Windows-приложения требуют реальных измерений.
- Четыре targeted Go checks PASS: paths/disabled mode, ambiguous UDP, настоящий TCP/UDP Windows loopback owner+image lookup, synthetic app DIRECT/VPN/BLOCK/no-rules/no-owner/no-dial/handle release, protected management/domain BLOCK, stale-after-dial и UDP send/delivery refusal. In-memory gVisor→настоящая encrypted WG pair packet fixture тоже использует app rules и проверяет original source tuple; app owner в ней synthetic. Ни loopback, ни этот fixture не подтверждают TUN attribution живого приложения.
- C# DPAPI/encrypted backup/app selector/redaction/empty legacy shape checks PASS. Actual packaged Go preview подтвердил app DIRECT/BLOCK/protected management и отсутствие active/networkChanged. Paths не попадают в ToString/log/status; preview stdout содержит только переданную caller policy, это private child pipe. В status только rules count/unknown blocked count. Старые strict readers с непустыми новыми правилами могут отказаться от backup; downgrade — после удаления правил в новой UI/сохранения либо с прежним backup.
- Добавлен embedded editor с EXE picker/полным путём/action/list/remove. Native working scenario: invalid relative path refused→add full path/direct→visible row label→Done/callback сохранён, fake validator/no service. Исправлено WPF Display binding: public [JsonIgnore] computed label, чтобы текст строк отображался, не становясь полем protocol/backup. Parent отдельно сохраняет draft; при выключенном раздельном режиме явное сообщение о необходимости его включить. Single-window/nested/busy/editor/browser checks PASS, верх/низ app rules render осмотрены.
- Go full test/vet/build, WPF publish0 warnings/errors, C# crypto/catalog/managed checks и Python→Go managed contract PASS. Offline route/adapter/service digest unchanged; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK, другой VPN не отключался. Baseline23/vendor package verifier PASS. Службы/реальные профили/ключи/VPS/GitHub не менялись.
- Package0.22: 90.38MiB/16 entries/15 payload SHA/200 corresponding sources/81 notices; SHA256 `044365c8ca31e97ec0d7608cd1f31d82cd2aa9ca19a53c7f3c9decee441d4e3e`. Payload/source correspondence PASS; ZIP0.21 и payloads0.19.1/0.20/0.21 сохранены побайтно.

**Открыто:** реальный application→TUN tuple mapping, Windows helpers/PPL/socket transfer/UDP reuse/load/owner-table contention, WFP/DNS/leaks/stop/sleep и live policy selection — NOT RUN. DNS53 общий, BLOCK приложения его не блокирует. Нет hot apply/parent inheritance/file signature/hash identity; отдельный helper EXE/версионированный путь требует правила. Полноценный installer/updater/policy delivery/always-on остаются впереди, скорость отложена.
