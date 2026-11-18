# План реализации FreeTurn Manager

**18.11, панель.** Выполнено локально. Control сохраняет минутные агрегаты в закрытой SQLite. Список подписок показывает метаданные, использует существующий экспорт и отзывает ссылку после проверки версии, HTTPS-сессии, CSRF и пароля администратора. Страницы VPN и настроек показывают состояние, а таблица устройств выводит handshake и счётчики WireGuard. Изолированная БД, HTTP-границы, сборка и рабочий сценарий в браузере проверены. Приёмка на VPS открыта.

**18.11, updater Windows.** HTTPS-загрузка реализована и проверена на локальном стенде. Библиотека запрашивает манифест доверенного канала и подписанный адрес пакета, проверяет сертификат и размер, отклоняет редиректы и удаляет временный файл при отказе или закрытии. Запуск Setup, хранилище доверия и интеграция в интерфейс открыты. [Протокол](WINDOWS_UPDATE_PROTOCOL.md).

**Последний ночной checkpoint18.11,Windows0.27:** bounded AWG1–3 расширение0.26 и installer/owner/partial-uninstall hardening0.27 реализованы и собраны локально, ZIP/Setup/source/hash/offline checks PASS. Retained SYSTEM data не меняют Windows owner при reinstall. Offline Ed25519 verifier есть отдельно; real AWG/TUN/FreeTurn/VK/install/upgrade/uninstall/UAC/VM, production feed/trust/downloader/UI integration открыты. Installed0.24/сеть/ключи/телефоны/VPS не менялись. [AWG](WINDOWS_AWG_26.md), [hardening](WINDOWS_SETUP_HARDENING_27.md), [ночь](OVERNIGHT_2026_11_18.md).

**Ночь18.11,поставка Windows:** отдельный русский Setup0.25/guarded uninstall wrapper с preserved frozen payload, source/hash/Go/Inno/query-only checks PASS; actual install/upgrade/uninstall/UAC NOT RUN. Offline Ed25519 metadata/artifact verifier и interop scenario реализованы; production trust/feed/downloader/UI/fence integration остаются открытыми. Установленная0.24/сеть/профили не менялись. [Installer](WINDOWS_INSTALLER_PLAN.md), [update protocol](WINDOWS_UPDATE_PROTOCOL.md), [ночная передача](OVERNIGHT_2026_11_18.md).

**Ночь18.11,0.25:** реализованы воспроизводимые loopback core transport/CPU/alloc замеры и временный Pion single-copy A/B; стабильное ускорение интернета не заявляется. Bounded AWG1 импорт/userspace backend, explicit routing gate, protocol/recovery/UI/DPAPI/encrypted backup — локально проверены и собраны0.25. AWG2/3 и реальные AWG/TUN/VK/E2E остаются открытыми; installed0.24/сеть не менялись. [Замеры](CORE_LOCAL_BENCHMARKS.md), [AWG](WINDOWS_AWG_PLAN.md), [ночная передача](OVERNIGHT_2026_11_18.md).

**Актуально18.11,0.24:** по прямому решению пользователя полностью удалена отдельная постоянная «Блокировка сети»: UI, capability/status, enable/disable IPC, legacy unlock CLI и код установки persistent WFP rules. Connect больше не зависит от obsolete provider lookup. Для перехода с0.23 остаётся только delete-only cleanup собственных fixed GUIDs в elevated setup/uninstall. На текущем компьютере provider отсутствовал; штатный elevated upgrade ядра до0.24 выполнен PASS, encrypted data/routes/adapters сохранены, tunnel stopped. Authenticated IPC подтверждает0.24 и отказ старым enable/disable командам. Сборка/Go/C#/native/offline/hash проверки PASS; реальный Connect не запускался. Policy delivery/network recovery сохранены; постоянную блокировку не возвращать в остаток ТЗ. [Результат0.24](WINDOWS_LOCK_REMOVAL_PLAN.md). Ниже — история.

**Актуально18.11,0.23:** реализованы выбранные пользователем пункты1–3: root-owned публикация маршрутизации через IPC/русскую панель и отдельный bearer routing API; Windows проверка/staging/DPAPI/next-connect delivery и bounded gzip/hash/provenance/revision guards; opt-in persistent WFP lock с отдельным снятием; UI-owned recovery после смены сети/сна/обрыва по exact profile/attempt/epoch. Сборка/Go/C#/Python/HTTP/native/offline проверки выполнены локально. Live WFP/lock/crash/reboot, Wi-Fi/sleep/VPN и доставка с реального сервера **NOT RUN**; сервер/установленные службы/сеть не менялись. Pre-BFE boot protection не заявлена. Далее обсуждение с пользователем; AWG/installer/редизайн/скорость этим поручением не начинались. [Результат0.23](WINDOWS_POLICY_LOCK_NETWORK_PLAN.md). Ранние шапки — история.

**Актуально17.11,0.22:** app path rules DIRECT/VPN/BLOCK реализованы для opt-in system routing; Windows TCP/UDP owner lookup/strict unknown/priority guards, settings/DPAPI/backup и embedded editor. Local Go/native loopback/C#/actual preview/in-memory WG/UI/build/offline checks PASS; real app/TUN/WFP/helpers/UDP performance/leak E2E NOT RUN. DNS общий; путь/creator PID не является sandbox/подписью файла. GeoIP0.20 и.local DNS0.21 уже реализованы локально. Далее списки/panel policy delivery/always-on/смена сети/AWG/installer и реальная приёмка; скорость отложена. [Результат0.22](WINDOWS_APP_RULES_PLAN.md). Ранние шапки — история.

**Актуально17.11,0.21:** A-resolution.local через DNS-маршрутизатор реализован bounded legacy mDNS с physical interface/private subnet/packet-info/ID/TTL checks, no public fallback и mode status/UI. Go/real Windows loopback/C#/build/native/offline/hash checks PASS; реальные LAN/Windows resolver/native5353/Bonjour/TUN/WFP/leaks NOT RUN. Не считать это полным DNS-SD discovery. GeoIP уже в0.20; дальше app rules/policy delivery/always-on/смена сети/AWG/installer и приёмка. Оптимизация скорости отложена. [Результат0.21](WINDOWS_MDNS_PLAN.md). Ранние шапки — история.

**Актуально17.11,0.20:** GeoIP IP fallback реализован на DB-IP Lite2026-11 вместо RIR allocation:12902 RU IPv4 prefixes, pinned original source/license, strict compiler/runtime provenance и приоритеты, UI источника/даты пакета. Python/Go/actual C# bridge/build/native/offline/hash checks PASS; real VPN/TUN/WFP/GeoIP/leak E2E NOT RUN. Геолокация приблизительная; автообновление списков/policy delivery не реализованы. Дальше mDNS/app rules/policy/always-on, AWG, смена физической сети, installer/updater и приёмка; оптимизация скорости остаётся отложенной. [Результат0.20](WINDOWS_GEOIP_PLAN.md). Более ранние шапки — история.

**Актуально17.11,0.19.1:** устранён аварийный composition/D3DImage путь CAPTCHA, зафиксированный Windows в пользовательском crash0.18. Standard WebView2 в том же окне, explicit hidden auto/manual, guarded initialization/close. Native local12-cycle GC/cancel/single-window/build/offline checks PASS; исходный crash не воспроизведён коротким baseline, live VK/VPN soak NOT RUN. Остаток технического ТЗ прежний. [Разбор0.19.1](WINDOWS_WEBVIEW_CRASH_PLAN.md). Более ранние шапки — история.

**Актуально17.11,0.19:** реализовано ручное восстановление потерянного bootstrap claim через сохранённый device token после expiry nonce, с key/origin/session/catalog guards и без повторного устройства. Local C#/actual Go/crypto/server logic/build/native/offline checks PASS;4 HTTP wrapper checks SKIPPED (web dependencies), live HTTPS/VPN recovery NOT RUN.0.18 package сохранён для пользовательского теста, новый build изолирован. Далее routing/mDNS/GeoIP/app/policy/always-on, AWG, installer/updater и реальная приёмка. [Результат0.19](WINDOWS_CLAIM_RECOVERY_PLAN.md). Более ранние шапки — история.

**Актуально17.11,0.18:** по сообщению пользователя исправлена цепочка editor→catalog→Connect, сохранение active selection, stale edit guard, global manual CAPTCHA и safe effective settings. Local native Save/crypto/backup/actual renderer/build/offline PASS; live settings/VPN/CAPTCHA E2E NOT RUN. Остальные системные этапы остаются открытыми, исключённые Windows extras не возвращаются. [Результат0.18](WINDOWS_SETTINGS_PLAN.md).

**Актуально17.11,0.17:** opt-in Windows Direct↔Relay manager, fixed IPC/path journal, proxy-only restart и epoch-bound proof/managed coordination реализованы. Локальные Go/C#/DPAPI/interop/UI/offline проверки PASS; live transports/switch/leak/sleep/crash E2E NOT RUN. Следующие доступные блоки — оставшиеся routing/AWG/installer/bootstrap claim recovery, с сохранением сокращённого пользователем Windows scope. [Результат0.17](WINDOWS_TRANSPORT_PLAN.md).

**Актуально17.11,0.16:** Windows managed KnownGood/backup, sustained service proof и однократный conditional automatic return после принятого manual Connect реализованы; private key/token/candidate/seen revision сохраняются. Go/C# crypto/interop/synthetic lifecycle/UI/offline checks PASS, live LKG/VPN/recovery/leak/sleep E2E NOT RUN. Следующий блок — Direct↔Relay. [Проверенный результат0.16](WINDOWS_LKG_PLAN.md). Исключённые пользователем Windows-функции ниже не возвращаются в scope.

**Решение пользователя17.11.2026 о Windows scope:** не переносить hotspot/LAN sharing, UDP/IPv6 для SOCKS, latency meter, дополнительные языки и полный набор дополнительных Android-настроек. Администрирование VPS и выдача/отзыв доступов остаются в веб-dashboard; Windows server management не разрабатывать. Существующий функционал сохраняется. Основной VPN, маршрутизация/DNS/защита, managed workflow, установщик и updater Windows остаются обязательными. Уточнение приоритетнее прежнего требования полного паритета Android; [актуальный остаток](REMAINING_WORK.md).

**Дата:** 10.11.2026. **Источник требований:** [ТЗ](FreeTurn_Manager_TZ.md).

**Актуально17.11,0.15:** Windows runtime identity/attempt guard, условная остановка и opt-in periodic managed sync реализованы. Локальные build/crypto/backup/cancellation/interop/UI/offline проверки PASS; реальные TLS/revoke/VPN E2E NOT RUN. Следующие блоки — traffic-proven LKG/automatic rollback и Direct↔Relay. Серверный API не менялся, установленные службы не обновлялись. [Результат0.15](WINDOWS_SYNC_PLAN.md). Ниже история прежних checkpoints.

**Актуально17.11,0.14:** Windows user enrollment JSON/local URI, stable DPAPI pending keys/UUID/CID/token, lost-response recovery и first managed profile реализованы. Криптография/contract/backup/UI/offline checks PASS; HTTP сценарии синтетические, live enrollment/new CID/VPN E2E NOT RUN. Серверный API не менялся. Следующий блок — periodic sync/runtime identity/LKG/Connection Manager. [Проверенный результат0.14](WINDOWS_ENROLLMENT_PLAN.md). Ниже история0.13 и ранних этапов.

**Актуализация17.11,0.13 — новое дневное поручение:** выполнены manual managed refresh/ETag validation, DPAPI staging/next-connect apply/local return, key/token/revision/refusal guards и сохранение backup. Python↔Go контракт, C# actual builder+synthetic HTTP, build/UI/offline проверки PASS. Live TLS/VPN/revoke/LKG NOT RUN; initial enrollment, periodic sync и Connection Manager впереди. [План и проверенный результат](WINDOWS_MANAGED_REFRESH_PLAN.md). Новое поручение разрешает продолжение после завершённого ночного окна; текущие ограничения real VPN/VPS/service upgrade/GitHub сохраняются.

**Актуализация17.11,0.11:** готов отдельный локальный Windows пакет с opaque HMAC fake-IP cache/без durable hostname и private on-link unicast DNS/no public fallback. Ключи/IP/head мигрируют без reset; SNI/Host TCP recovery, privacy/crypto/build/UI/unchanged-digest проверки PASS. Live SYSTEM/TUN/WFP/LAN/VPN E2E NOT RUN.0.9/0.10 сохранены; следующая доступная задача — Windows managed/Connection Manager с локальными контрактами. [Проверки и ограничения](WINDOWS_LAN_DNS_PLAN.md). Шапка0.10 ниже историческая.

**Актуальный checkpoint17.11:** собран0.10 с opt-in system routing, IPC/SYSTEM options, service health/egress,7 presets/domain editor/DNS и encrypted preference restore. Stable DNS identities предотвращают alias при reconnect. Code/build/local packet/crypto/interop/UI/readonly IPC проверки PASS; настоящий0.10 VPN/leak/crash E2E NOT RUN. WGNT default сохранён, установленные службы не обновлялись. [Текущий результат и остаток](WINDOWS_SYSTEM_ROUTING_PLAN.md). Записи о неподключённом runtime ниже — история до этой интеграции.

**Техническое продолжение17.11.2026:** редизайн отложен пользователем. Новое системное policy/fake DNS/gVisor/WG ядро и packet-level DNS/TCP/UDP proof PASS; root-only TUN/WFP lifecycle подготовлен, но ещё не связан с рабочей службой/IPC/UI. Следующий блок — opt-in DPAPI/IPC, userspace WG health/egress и честное состояние, затем settings/backup и отдельный пакет. [План, проверки и остаток](WINDOWS_SYSTEM_ROUTING_PLAN.md). Установленные службы/маршруты/VPS и0.9 ZIP не менялись; actual system routing E2E NOT RUN.

**Актуализация16.11.2026 после user-confirmed Windows VPN0.8:** подготовлен0.9 с безопасным core journal, обработкой закрытия, отзывчивостью и иконкой. [Отчёт](WINDOWS_POLISH.md). Полный редизайн разрешён без ограничения прежней навигацией; ожидаются пользовательские примеры. Следующий основной backend-блок — общесистемный routing/DNS, затем managed Connection Manager. Исторические ссылки и ограничения ниже относятся к указанным датам.

**Продолжение16.11.2026:** первый routing block — custom domains для SOCKS5 с реальными VPN/DIRECT/BLOCK dial paths, отдельным resolver/interface binding, безопасным внутренним relay и encrypted preferences. [План](WINDOWS_ROUTING_PLAN.md), [фактические проверки/NOT RUN](WINDOWS_ROUTING.md). Общесистемный маршрутизатор и семь presets ещё впереди; установленная служба не обновляется автоматически.

**Уточнение16.11.2026:** QR/камера на Windows исключены пользователем; текстовый импорт/экспорт и backup сохраняются. UI0.5 переносит композицию Android5.3.4 с portrait/bottom navigation. [План визуального переноса](history/windows/WINDOWS_DESIGN_PARITY_PLAN.md), [фактический результат и оставшийся scope](history/windows/WINDOWS_DESIGN_PARITY.md). Это уточнение имеет приоритет над историческими пунктами Windows QR ниже. Реальное подключение/установку служб пользователь оставил себе.

**Последнее уточнение пользователя15.11.2026:** цель Windows теперь — полный перенос функционала исходного Android FreeTurn, не продолжение урезанного MVP. Зафиксирована [матрица полного переноса Android5.3.4](WINDOWS_FULL_PORT_PLAN.md). Прежний минимальный этап ниже — выполненный промежуточный шаг; UI0.1.1/engine и сохранённые профили сохраняются как основа. Полный паритет пока не реализован.

**Текущий приоритет от 15.11.2026:** сначала минимальный Windows-клиент для обычного `freeturn://` профиля, затем остальной native/managed scope. [Исполняемый Windows-план](history/windows/WINDOWS_MVP_PLAN.md), [фактические проверки](history/windows/WINDOWS_MVP_CHECK.md). Первая сборка и офлайн-сценарий выполнены; пользователь оставил установку и подключение на ПК себе. Для его проверки выдан отдельный Windows peer, существующие телефонные ключи сохранены. Native VPN E2E остаётся NOT RUN до результата пользователя.

> Для выполнения: superpowers:executing-plans; изменения проверяются через superpowers:test-driven-development. Локальные безопасные работы разрешены пользователем. Развёртывание на действующем VPS требует отдельного согласованного доступа.

**Цель первого шага:** сохранить проверяемую копию Vps, зафиксировать исходные версии и добавить безопасный, исполняемый фундамент установки Manager.

**Архитектура:** неизменяемый `vendor/vps/` содержит исходную серверную установку с лицензиями и закреплёнными артефактами. Отдельный пакет `ftm/` выполняет только анализ и формирование плана. На этапе 1 Manager не меняет службы, firewall, WireGuard или состояние Vps. Установка Manager завершится явной ошибкой до реализации apply/rollback.

**Стек этапа 1:** Python 3.10+ (на Ubuntu 24.04 — 3.12), стандартная библиотека, Bash, unittest. Внешних Python-зависимостей пока нет. Контейнеры не используются.

## Этап 1: baseline и безопасный skeleton

### 1. Зафиксировать исходники

- [x] Изучить все шесть репозиториев, записать commit SHA, лицензии и ограничения в `docs/BASELINE.md`, `upstreams.lock.json`; зафиксировать CLI, форматы профилей и системные службы.
- [x] Скопировать отслеживаемые файлы Vps без изменения содержимого в `vendor/vps/`; сохранить README, LICENSE, NOTICE, исходники, тесты, manifest, готовые бинарники и архив.
- [x] Добавить `scripts/verify_baseline.py`: проверка SHA256 каждого сохранённого файла, транспортных бинарников и архива; отказ при отсутствии, подмене или небезопасном пути. Файлы берутся по allowlist из lock, без исполнения скачанного кода.
- [x] Проверить исходные 8 тестов: `python3 -m unittest discover -s vendor/vps/tests -v` и исходный verifier `python3 vendor/vps/scripts/verify-package.py`.

### 2. Добавить проверяемый анализ установки

Файлы: `ftm/installer.py`, `ftm/cli.py`, `ftm/__main__.py`, `install.sh`, `tests/test_installer.py`, `tests/test_cli.py`.

Дополнительно: `ftm/preflight.py`, `tests/test_preflight.py` — чтение ОС/root/systemd, CPU/RAM/диска, TCP/UDP-портов и наличия инструментов; DNS/TLS/firewall/службы не объявлять проверенными.

- [x] Сначала написать тесты валидации конфигурации: домен/IP, TLS policy, типы, отсутствие неизвестных полей, subnet/port separation; выполнить и зафиксировать падение из-за отсутствующей реализации.
- [x] Реализовать строгий JSON config (как содержимое файла `--config`, без shell source/eval), ограничение размера, запрет symlink и требование режима 0600 на POSIX.
- [x] Реализовать чистую функцию плана `build_plan(config, existing_state=None)`: существующая установка требует migration, сохраняет endpoint VPN, порты и subnet, не содержит секретов. Проверять legacy state исходным валидатором, не изменять его.
- [x] Добавить интерактивный мастер без обязательного `--domain`: домен/IP, режим, TLS/access, подтверждение; при EOF/SIGINT — отмена без записи и изменения системы.
- [x] CLI `python -m ftm install --dry-run`, `--non-interactive --config FILE --dry-run`, `python -m ftm inspect --state FILE` и Bash entrypoint с необязательным совместимым `--manager`. Диагностика выводит только allowlist полей, не исходное состояние/исключения с секретами.
- [x] Без `--dry-run` возвращать ненулевой код и понятное объяснение, что apply не реализован. Не вызывать apt/systemctl/wg/iptables и не объявлять установку успешной.
- [x] Проверить команды на Windows и Ubuntu WSL, включая subprocess CLI, неверный конфиг, отказ без dry-run и неизменность входного state.

### 3. Автономный smoke и проверка поставки

Файлы: `scripts/smoke_baseline.py`, `tests/test_baseline.py`, `.github/workflows/verify.yml`.

- [x] Linux amd64 smoke: проверить binary SHA, версию по startup log (флага `-version` нет), `-h`, команды `clients add/list/remove` на временном файле, не поднимая VPN и не меняя системных файлов. Проверить формат и независимость сгенерированных профилей на синтетических ключах.
- [x] Описать границы: smoke не доказывает передачу VPN-трафика, wire-совместимость Android 5.3.2 и сервера 4.1.2, прохождение VK/CAPTCHA и подключение Anton48.
- [x] CI Ubuntu 24.04: baseline verifier, обе группы unittest, bash syntax, binary smoke. Не запускать установку и не требовать секреты.
- [x] Обновить README, `docs/DECISIONS.md`, `docs/PROGRESS.md`: команды, PASS/FAIL/NOT RUN, rollback и следующий шаг.

**Gate этапа 1:** локальные unit/CLI/smoke должны проходить. Полная приёмка требует Ubuntu VPS 1 vCPU/1 GiB, реальных клиентов, `vps-vk status/profiles`, VK-трафика и восстановления. Первоначальный запрет перехода до всех клиентских проверок уточнён текущим поручением пользователя: после подтверждённого iPhone и recovery/rollback разрешены доступные серверные работы этапа 2. Android и одновременные реальные устройства остаются открытыми gates и не объявляются проверенными.

**Контракт миграции:** до любых системных изменений — зашифрованный бэкап вне VPS и подтверждённое восстановление. Сохраняются WG private/public/PSK, CID, VK link, obf key, профили iPhone/Android, endpoint/порты/subnet, firewall, Fail2ban и SSH. Незнакомые peers и чужие службы не удаляются. Отчёт плана не содержит значений секретов. Это требования будущего apply, а не уже выполненная миграция.

**Обновление 10.11.2026:** пользователь предоставил отдельный VPS и VK link и разрешил базовую установку. Добавлен `ftm.baseline_deploy --apply`, заменяющий только obsolete Fail2ban hook без изменения baseline. Первая/повторная установка, status/profiles/QR и offsite encrypted backup round-trip подтверждены. Профиль iPhone подготовлен; пользовательская проверка ожидается, Android для текущего сервера NOT RUN, чистое системное restore ещё NOT RUN. Общий Manager installer остаётся dry-run.

**Следующее обновление:** iPhone подтверждён пользователем и handshake/rx/tx; restore при отсутствующем state на том же VPS и rollback после инъекции ошибки PASS. Начат этап 2: SQLite, metadata CLI, защищённый root reconcile и реальный hot add/revoke синтетического peer. [План](STAGE2_PLAN.md), [результат и оставшиеся gates](STAGE2_PROGRESS.md).

## Последующие этапы

2. SQLite WAL, версия схемы, импорт старых устройств без изменения ключей, транзакционное выделение IP/CID, ограниченный agent и reconciler. Тесты конкуренции/идемпотентности/отзыва; сохранение неизвестных peers. E2E: три одновременных устройства.
3. FastAPI и статический React/Tailwind, Caddy, защищённая сессия, RU UI и настоящие метрики. Сборка вне production. Тесты доступа, CSRF, маршрутов, TLS и памяти.
4. Подписка и device credential, revocation/rotation, revision/ETag, bootstrap→managed через VPN с проверкой TLS. JSON Schema и round-trip из реальных парсеров. Контрактный клиент явно помечается mock.
5. Android: выделенный GPL-совместимый fork, импорт/обновления, Connection Manager, защищённое хранилище, миграция подписи. APK и испытания на устройствах.
6. Windows: spike реального системного туннеля, выбор драйвера/лицензии, service/IPC ACL, UI, reconnect, installer/uninstaller, sleep и leak tests.
7. Матрица нагрузки и скорости, сбои, backup/restore/rollback, DNS/IPv6, совместимость Anton48, реальные сети. CPUQuota менять только по измерениям.
8. Закреплённые release artifacts, интерактивный install/upgrade/repair/migrate/restore/uninstall, финальная проверка T01–T31 на чистых системах и реальных клиентах.

Уточнение14.11.2026 для будущих этапов5/6: переиспользовать существующую автоматическую обработку CAPTCHA FreeTurn, сохранить ручной fallback, cache/cancel/backoff и устранение дублей (§5.1/T28). Обязательный перенос solver из чужого проекта исключён; прежнее Calls-first решение из [исследования](VK_AUTH_RESEARCH.md) теперь только кандидат к проработке при подтверждённой необходимости. Реализацию по этому уточнению не начинать; незакоммиченные изменения VPNN не считаются включёнными в FTM.

Перед каждым следующим этапом план уточняется по результатам предыдущего. Выполненные unit/mocks не заменяют E2E.

Уточнение10.11.2026: [domain routing/split DNS/BitTorrent](ROUTING_POLICY_RESEARCH.md), ТЗ§6.1/T29–T31. На этапе3 — admin plain-domain editor/policy revisions; этапе4 — versioned delivery/capabilities/rollback; этапах5/6 — native per-flow execution и DNS; этапе7 — actual egress/leak/BitTorrent/resource проверки. Сейчас только исследование и запись требований; не менять клиенты, VPS/DNS/firewall или рабочий iPhone-profile в рамках этого поручения.


## К проработке: восстановление на единственном VPS (14.11.2026)

Источник — ТЗ §11.1; это очередь исследования/оценки, не утверждённый исполняемый план и не поручение применять изменения сейчас. Второй VPS, резервный сервер и кластер исключены; текущий временный второй VPS не является зависимостью продукта.

- Этап4: версия managed manifest для согласованных кандидатов одного VPS, capabilities/миграция, безопасный LKG/atomic apply и работа при недоступном API без обхода revoke/expiry. Actual v1 с одним peer пока не меняется.
- Этапы5/6: диагностика по стадиям, ограниченные повторы и sticky failover, реальные probes через туннель, защита сокетов/маршрутов и reuse штатной CAPTCHA. Значения тайм-аутов сначала измерить.
- Этап7: лёгкое серверное наблюдение/ограниченные repairs, матрица совместимости, fault injection и проверка ресурсов; односерверные альтернативные порты/экземпляры оценить отдельно. Не вводить Docker/тяжёлый мониторинг, не нарушать Anton48 и SSH.
- Этап8: постепенный выпуск и rollback, автозапуск после reboot, offsite backup/restore. Полный отказ единственного VPS или всех путей к нему обозначать явно; автоматическую доступность при этом не обещать.

Перед реализацией согласовать конкретные действия, пределы ресурсов, offline-политику, показатели восстановления и проверяемую приёмку. В рамках записи этих требований код, VPS и runtime E2E не меняются.
