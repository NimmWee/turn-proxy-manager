# FreeTurn Manager — техническое задание для Codex

**Решение пользователя18.11.2026, Windows0.24:** самостоятельная постоянная «Блокировка сети» / always-on kill switch полностью исключена из продукта и ТЗ. Удаляются UI, capability/status и команды управления/установки persistent правил. После отключения VPN приложение не оставляет отдельный запрет обычного интернета. При переходе с0.23 разрешена только односторонняя очистка fixed owned legacy provider/filter GUIDs в elevated setup/uninstall; никаких общих firewall reset. Временные правила изоляции работающего VPN, domain BLOCK и DNS/IPv6 защиты остаются частью активной маршрутизации. Постоянную блокировку не возвращать без нового прямого поручения. [Удаление0.24](WINDOWS_LOCK_REMOVAL_PLAN.md).


**История реализации18.11 — Windows0.23; её постоянная блокировка удалена0.24:** доставка маршрутизации выделена в `/api/client/v1/routing` с device bearer и `X-FreeTurn-Capability: routing-bundle-v1`, без изменения strict managed manifest v1. Авторизация active device/root registry предшествует выдаче. Администратор публикует presets/domain rules/directDNS с optimistic revision; списки импортируются root-only offline из проверенной сборки, не по произвольному URL. SHA256 — контроль целостности, доверие к издателю даёт HTTPS identity согласованного сервера; отдельной подписью хеш не является. Windows проверяет декодирование/размер/формат/источник/месяц/ревизию, сохраняет предыдущую принятую версию и применяет новую при следующем Connect только в явно включённом системном режиме. Same-revision substitution/понижение bundle/месяца отклоняются. EXE-правила/локальное включение остаются локальными; server domains/presets/DNS имеют приоритет над соответствующими локальными значениями. Applied revision/catalog digest возвращает служба. Старый сервер404 сохраняет локальные настройки.

Исторический вариант0.23 (не действующее требование): постоянный kill switch — отдельный opt-in OS lock, не импортируется из backup. WFP persistent deny + узкие loopback/DHCPv4/installed tunnel SID+path allowances; TUN allowance dynamic в том же sublayer. Disconnect/выход не снимают lock, отдельные команды владельца/elevated recovery/uninstall снимают только собственные объекты. Сохраняется после падения UI/службы; фактические WFP/crash/reboot gates открыты, pre-BFE boot protection не заявлена. Network recovery работает после ручного Connect, при включённом AutoReconnect и открытом UI: debounce, physical IPv4/DNS fingerprint, suspend/resume, максимум5 попыток, exact attempt/epoch IPC, прежние ключи/settings/path. После network restart Direct/Relay фиксирован до следующего ручного Connect, новый transport budget не выдаётся. CAPTCHA/другой сеанс/ручной stop/отзыв запрещают прежнюю попытку; другой VPN не отключается. Без OS lock отсутствие утечки в restart gap не заявляется. Локальные проверки не заменяют реальную сетевую приёмку. [Проверки и передача](WINDOWS_POLICY_LOCK_NETWORK_PLAN.md).


**Версия ТЗ:** 1.0 · **Дата:** 09.11.2026 · **Уточнение:** 14.11.2026 · **Язык продукта:** русский

> Цель: разработать лёгкую, удобную и отказоустойчивую систему семейного VPN на **одном** VPS, опираясь на уже работающий проект `NimmWee/Vps`. Документ — спецификация для реализации, **не утверждение, что функциональность уже существует**. Не ломать текущие рабочие подключения. Работать последовательно по этапам, проверяя результат каждого.

## 0. Референсы и приоритеты

Проверить код, историю, лицензии и конкретные версии зависимостей перед изменениями:

1. Основной исходный серверный проект: https://github.com/NimmWee/Vps — `install.sh`, `src/vps_vk.py`, `scripts/`, `tests/`, `docs/`, `artifacts/manifest.json`, `NOTICE.md`. Это основа, не удалять её без миграционного плана.
2. FreeTurn Android (актуальная ветка): https://github.com/hackdiaz-dev/turn-proxy-android — существующий GUI, интегрированный WG/AWG, Relay/Direct, раздельное туннелирование. Лицензия GPL-3.0.
3. Ядро/сервер FreeTurn: https://github.com/hackdiaz-dev/free-turn-proxy — режимы, протоколы, клиентские CID и документ `docs/sub.md`. Уточнить лицензию ядра.
4. Экспериментальный Windows-порт FreeTurn: https://github.com/l1ch666/turn-proxy-android — каталог `desktop/`, проверить текущую поддержку полноценного WG/AWG, не предполагать готовность без тестов. GPL-3.0.
5. iPhone — только совместимость с установленным сторонним приложением https://github.com/anton48/vk-turn-proxy-ios. **Не разрабатывать, не подписывать и не собирать iOS-приложение.**
6. Вдохновение только для маршрутизации сайта: https://github.com/itsnotkubrick/3X-UI_KIT, `scripts/3x-ui.sh`: генерирует случайный путь панели, отдельный путь подписки, `location /` обслуживает статическую страницу-заглушку через Nginx. **Не копировать Xray, nginx-stream, REALITY, 3X-UI, протоколы или чужую серверную панель.** У нас будет Caddy.

### Жёстко зафиксированные требования

- **Один VPS** на Ubuntu Server 24.04 (главная тестируемая платформа): **1 vCPU, 1 GiB RAM**, рекламируемый канал **1 Гбит/с**; всё серверное ПО на одной машине. **Подтверждено 14.11.2026: резервные/дополнительные VPS и кластер исключены; временный второй VPS не считать постоянной инфраструктурой.** Копия бэкапа вне VPS допустима и не является запасным VPN-сервером.
- **Не больше 20 членов семьи**; несколько устройств у каждого; ожидаемый ориентир — до 60 зарегистрированных устройств, но не устанавливать искусственный лимит по названию устройства или платформе. Проверить ограничения адресного пула и нагрузки.
- **Android и Windows используют FreeTurn** (Android — модифицированный FreeTurn, Windows — FreeTurn Desktop с подобным интерфейсом/возможностями).
- **iPhone пользуется Anton48 VK TURN Proxy iOS** с индивидуальным импортируемым профилем; отдельная iOS-разработка вне scope.
- Поддержка **WireGuard сейчас**. **AmneziaWG** как требуемая цель после отдельной проверки совместимости реального backend, клиентских ключей, transports и ресурсов; не называть AWG готовым до подтверждённого E2E.
- **VK TURN Relay остаётся рабочим**, плюс Direct к существующей серверной части FreeTurn, где поддержано. TURN использует стороннюю инфраструктуру VK; **свой TURN-сервер не поднимать**.
- **Один пользователь — одна постоянная ссылка-подписка — несколько независимых устройств**. Для каждого устройства отдельные WireGuard/AWG-пиры, VPN-IP, Client ID и ключи. Параллельные подключения не конфликтуют.
- Android и Windows: **автоматический Direct ↔ Relay** с проверкой реального трафика, без зацикливания и постоянной смены маршрутов.
- При блокировке прямого HTTPS к VPS: первоначальный **Bootstrap-профиль**, затем после успешного VPN-подключения автоматический переход к **управляемой подписке**, без повторного ручного импорта. iPhone использует ручной профиль, как сейчас.
- **SQLite, не PostgreSQL**. **FastAPI + статический React/Vite/Tailwind + Caddy + systemd**, без Docker, постоянно работающего Node.js, тяжёлого мониторинга и дополнительных VPS.
- Красивый адаптивный веб-интерфейс на русском, с конкретной статистикой без выдуманных цифр.
- На домене `/` — нейтральный сайт «Сайт находится в разработке»; админка — на длинном случайном пути + полноценная авторизация; отдельные защищённые API маршруты; HTTPS.
- **Однокомандная установка запускает ИНТЕРАКТИВНЫЙ мастер как у 3X-UI_KIT**: выбор своего домена либо публичного IP, DNS/TLS проверка, режим доступа к панели, заглушка, учётная запись и подтверждение. **Не требовать обязательный `--domain` в команде.** Также поддержать неинтерактивный CI-режим; идемпотентность, миграция и rollback.
- **Главный приоритет — сохранить работоспособность существующего `NimmWee/Vps`, совместимость с Anton48, скорость и низкую нагрузку.**

## 1. Подтверждённая исходная точка (не переизобретать)

По README и коду `NimmWee/Vps` на 09.11.2026:

- Установщик: `bash <(curl -fsSL https://raw.githubusercontent.com/NimmWee/Vps/main/install.sh)`; выпускной пакет фиксирован/хеширован.
- Один `vps-vk.service` (сервер FreeTurn) и `vps-vk-network.service`; FreeTurn `4.1.2-vps1` в распространяемом пакете; ядро WireGuard в Linux.
- Транспорт: `56001/udp` (вход из VK), backend WG `51830/udp` (внешний доступ закрыт), интерфейс `vkvpn0`, подсеть `10.77.43.0/24`.
- Текущий профиль `SRTP-WRAP-S`, `rtpopus3`, индивидуальные Client ID; `clients.json`; `iphone` и `android` жёстко заданы в состоянии / профилях и проверках.
- Существуют root-only ссылки `vkturnproxy://` (Anton48) и `freeturn://` (Android); секреты не публиковать в Git.
- Systemd для FreeTurn: примерно `MemoryHigh=64M`, `MemoryMax=96M`, `GOMEMLIMIT=48MiB`, `GOMAXPROCS=1`, `CPUQuota=50%`. Не считать это оптимумом скорости; измерить, прежде чем менять лимиты.
- Вход от VPN клиентов к VPS в настоящий момент ограничен firewall (по умолчанию REJECT); для HTTPS-подписок по внутреннему адресу понадобится узкое разрешающее правило.
- Fail2ban, отдельный системный пользователь и шифрованный бэкап уже существуют. Сохранять гарантию SSH-доступа и чужие правила сети, не делать `iptables -F`/`ufw reset`.
- Ядро FreeTurn (`docs/modes.md`) подтверждает ручной Direct/Relay; `docs/sub.md` подтверждает текстовые подписки для CLI, **но не полноценную систему регистрации устройств**. Нужен отдельный клиентский Subscription Manager.
- **Важно:** Direct FreeTurn — передача DTLS/OBF непосредственно к FreeTurn peer, а не обязательно публичный WG UDP/51830. Нельзя открывать backend 51830 для реализации Direct по умолчанию.

Начать с механической фиксации версии исходников, форматов профилей, CLI, сервисов и тестов. На действующей установке перед изменениями — зашифрованный бэкап вне VPS и проверка восстановления.

## 2. Целевая архитектура

```text
                         Интернет
                             |
            https://vpn.example.org:443 [Caddy]
           /                 |                   \
     GET / → сайт        /a/<random>/          /sub/<token>
     «в разработке»       Admin React             enrollment/updates
                               |                         |
                      FastAPI (127.0.0.1) <------------|
                         |         \
                    SQLite         privileged agent (локальный UNIX socket)
                                        |
                           wg peers / CID / systemd / firewall

Android FreeTurn ─┐
Windows FreeTurn ─┼─ (Direct FreeTurn или VK TURN Relay) → FreeTurn Server:56001
Anton48 iOS ─────┘                                       |
                                             kernel WireGuard / AWG* backend
                                                    vkvpn0 / NAT
                                                     Интернет

* AWG — только после отдельной проверенной реализации.

Актуализация18.11,Windows0.27: bounded AWG1–3 импорт/userspace backend с explicit routing gate, сохранением протокола/ключей и encrypted TCP/UDP/MTU-sized loopback/wrong-header-key refusal реализован и проверен локально. Это не real AWG E2E: TUN+FreeTurn Direct/VK/сервер/leaks/long timers/телефоны остаются открытыми; не все upstream поля входят в bounded subset. Managed v1 пока WG. Отдельный русский Setup/guarded uninstall и retained Windows owner protection собраны, реальная clean VM приёмка NOT RUN. Offline Ed25519 update verifier есть отдельно; production trust/feed/downloader/UI пока отсутствуют. [AWG](WINDOWS_AWG_26.md), [поставка/owner](WINDOWS_SETUP_HARDENING_27.md), [update protocol](WINDOWS_UPDATE_PROTOCOL.md). Локальные performance измерения не доказали интернет-ускорение; поставляемый pinned core не менялся. [Замеры](CORE_LOCAL_BENCHMARKS.md).

**Две независимые плоскости:**
- Data plane: туннель VPN и TURN; не зависит от работоспособности React, FastAPI или SQLite после подключения уже зарегистрированного устройства, насколько это допускают TTL/credential и текущие серверные процессы.
- Control plane: регистрация устройств, управление пользователями, выпуск конфигов, обновления, аудит. Работа его сервисов **не должна потреблять VPN-трафик** и не должна требовать перезапуска VPN при обычной операции.

Уникальные системные службы: `vps-vk`, `vps-vk-network`, `ftm-api`, `ftm-agent` (или эквивалент root-only CLI/служба), `caddy`; фронтенд — статические файлы. Не допускать root у веб-приложения.

## 3. Модель пользователей и устройств

### Основной сценарий

- Админ создаёт пользователя «Александр», получает одну стабильную ссылку `https://vpn.example.org/sub/<USER_SECRET>` либо клиентскую `freeturn://enroll?...`, которая указывает на эту подписку.
- На каждом Android/Windows клиенте он вставляет **одну и ту же ссылку**. При доступном API клиент создаёт **собственный** WireGuard ключ локально (при необходимости отдельный Ed25519 identity key или защищённый device token), генерирует случайный Client ID и регистрирует устройство.
- FastAPI в одной транзакции добавляет устройство и выдаёт уникальный незанятый IP (например, 10.77.43.10), разрешает его публичный WG-ключ и CID через привилегированный помощник, возвращает параметры сервера/VK TURN/подписки. Не возвращает чужие приватные ключи.
- На ноутбуке/телефоне/планшете разные peer keys, CID и IP; одновременные подключения работают. Один пользователь может иметь несколько активных устройств.
- При отзыве устройства удаляются его WG peer и CID; при отзыве пользователя — все связанные устройства. Не использовать общий WG ключ для всех устройств.
- iPhone (Anton48): вручную создать отдельное устройство, сгенерировать совместимый импортируемый `vkturnproxy://` профиль. Веб-панель позволяет увидеть/скопировать/скачать профиль **после подтверждения администратора**; не модифицировать iOS-клиент.

### Регистрация при блокировке публичного IP

**Это обязательный отдельный сценарий, а не случайная опция.** Прямой HTTPS к VPS может отсутствовать, хотя VK TURN к нему продолжает работать.

1. В панели администратор выбирает «Выдать стартовый профиль» для **конкретного устройства**. Сервер регистрирует отдельный WG peer и CID и формирует одноразовый безопасный профиль/QR/файл с необходимым приватным ключом устройства, VK TURN-параметрами и ссылкой на последующую подписку. Профиль передаётся пользователю по доверенному каналу; не публикуется открыто. Если безопасный local-key handshake невозможно сделать offline, допустимо генерировать индивидуальный приватный ключ администратором только для этого профиля, а после регистрации безопасно ротировать ключ, если это возможно без обрыва.
2. Android/Windows импортирует этот профиль и подключается через VK TURN. **Не требовать публичного HTTPS на этом шаге.**
3. С уже поднятым VPN клиент обращается к API по внутреннему VPN IP `10.77.43.1`, сохраняя TLS-проверку домена `vpn.example.org`. Реализовать явный internal-address override в HTTP-клиенте/локальное DNS-разрешение (не отключать проверку сертификата). Маршрут к API должен идти **внутри** VPN, а маршруты самого TURN-транспорта — **в обход** VPN для защиты от петли.
4. Получить и проверить конфигурацию, связать локальное устройство с подпиской, пометить профиль как `managed`. Не рвать VPN при отсутствии изменения backend и ключей. При изменениях — использовать безопасную поэтапную замену и rollback.
5. Сохранить последний исправный bootstrap для аварийного восстановления. Дальнейшие обновления — через VPN API.

**Принципиальное ограничение:** если VPS недоступен и через VK TURN или стартовый профиль содержит устаревший IP после недоступной миграции, одна серверная машина не может самостоятельно доставить новую конфигурацию. Предусмотреть ручную выдачу нового файла/QR и экспорт зашифрованной резервной копии вне VPS. Не обещать непрерывную доступность при любом сценарии блокировки.

### Схема SQLite (минимум)

`users` (id, name, enabled, device_limit nullable, created_at, updated_at); `devices` (id, user_id FK, name, platform [android/windows/ios/other], vpn_type [wg/awg], wg_public_key unique, cid unique, ip unique, enabled, last_handshake_at, created_at); `subscriptions` (id, user_id FK unique, token_hash unique, version, revoked_at); `device_tokens` (id, device_id FK, token_hash, created_at, revoked_at); `bootstraps` (id, device_id FK, nonce_hash, expires_at, consumed_at); `config_revisions` (id, revision, hash, created_at, applied_at); `audit_events` (id, actor, action, subject_type, subject_id, ts, sanitized_details); `metrics_samples` (ts, cpu_pct, mem_bytes, rx_bytes, tx_bytes, vpn_peers_active_estimate); `settings`/`migration_versions`.

- SQLite `WAL`, `foreign_keys=ON`, `busy_timeout`, транзакции, уникальные индексы и миграции (Alembic + SQLite-compatible migrations или versioned SQL).
- Токены хранить **в виде криптографических хешей**, plaintext показывать только при выпуске; серверные ключи и VK-секреты хранить с UNIX permissions 0600 и не писать в логи.
- Две одновременные попытки создать устройство не могут получить одинаковый IP/CID: БД-транзакция + проверка уникальности + идемпотентный ключ операции + reconciler.
- Резервное копирование через SQLite Backup API/`VACUUM INTO` с проверкой восстановления; не копировать WAL-базу «наживую» обычным `cp` без согласования.
- Если подписка пользователя скомпрометирована, администратор может перевыпустить ссылку, **не отключая уже зарегистрированные устройства**, если выбран такой режим; отдельный отзыв устройств обязателен.

## 4. Server Core и privilege separation

- Сохранить рабочую связку FreeTurn Server + VK TURN + kernel WireGuard из `NimmWee/Vps` на этапе начального внедрения.
- Удалить фиксированное условие `clients == {'iphone','android'}`, `.2/.3`, ожидаемое число peer=2. Любое устройство имеет набор параметров (CID/WG pubkey/IP), не привязанный к OS. Мигрировать старые iPhone/Android как существующие устройства без изменения их ключей.
- Привилегированный agent (локальный root-only UNIX socket или строго whitelisted CLI) принимает только структурированные команды `add_peer`, `revoke_peer`, `sync_cids`, `status`, `apply_network_rule`, `backup`; **никакого исполнения произвольных shell-строк из API**. Валидация CID/IP/ключа/порта, ограничение sudo, file ownership.
- WG peers добавлять без полного перезапуска туннеля (`wg set`, `wg syncconf` или проверенный эквивалент); обновление `clients.json` атомарно. Проверить поддерживается ли hot reload закреплённой серверной сборкой; если нет — объявить контролируемый restart с предупреждением, тестом и rollback, либо реализовать безопасный reload.
- Источник истины — SQLite для метаданных, согласованное состояние peer/CID в системных файлах. Reconciler сравнивает desired и actual, не удаляет незнакомые peer без явно подтверждённой миграции.
- Не сбрасывать весь firewall, не менять SSH-порт/ключи, не удалять прочие сетевые интерфейсы и правила; все свои firewall правила маркировать/изолировать. `56001/udp` открыт по условиям FreeTurn; `51830/udp` наружу **закрыт**; порты 80/443 TCP для сайта и TLS; доступ к management API из VPN — только нужный HTTPS маршрут/IP. Запрет прямого доступа VPN-пользователя к прочим private/metadata адресам сохранить, не ломая DNS/TLS.
- Не включать IPv6 full tunnel без подтверждённого корректного IPv6 выхода и leak tests. По умолчанию ясная политика IPv6 (блокировка либо нативная поддержка после тестирования).
- Бэкап включает SQLite, ключи backend, CID, сервисные конфиги, DNS/domain settings и сертификатные настройки, но исключает ненужные логи/сборочные артефакты. Шифрование и аутентификация архива; проверка restore на чистом VPS.

## 5. Подписка и API: функциональный контракт

**Устойчивость браузера CAPTCHA,17.11,0.19.1:** Windows зафиксировала необработанный finalizer crash0.18 в GraphicsItemD3DImage.ReleaseDevices (ObjectDisposedException). CAPTCHA использует стандартный WPF WebView2 без composition D3D capture, внутри прежнего окна; автоматический HWND явно скрыт, ручной виден. Single-flight initialization и disposed guard после await, идемпотентное закрытие до detach; private cookies/local URL/new-window/download/permissions ограничения сохраняются. Native local12-cycle GC/cancel/hidden JS/crypto/timer/manual и single-window/build/offline PASS. Короткий baseline crash не воспроизвёл; конкретный триггер SDK и live VK/VPN/display-change/soak E2E остаются открыты. [Доказательства и проверки](WINDOWS_WEBVIEW_CRASH_PLAN.md).

**Восстановление Windows bootstrap claim,17.11,0.19:** потерянный ответ активации не должен требовать нового устройства/ключа. При ручной проверке клиент сначала выполняет internal HTTPS GET status с прежним device token, после saved derived-key/origin validation и под authenticated runtime lease. Matching active status подтверждает уже принятый запрос даже после expiry nonce. Только401 неизвестного token при неистёкшем nonce разрешает POST с прежним token hash; pending/error/403/429/503/redirect/network/invalid replies не инициируют новый claim. Expected metadata/share и runtime profile/attempt/path recheck запрещают stale commit. После expiry UI предлагает проверку восстановления, при неизвестном token требует администратора. Код/local DPAPI/targeted server logic/actual Go/build/native/offline PASS;4 HTTP wrapper checks SKIPPED (web development dependencies); real TLS/VPN recovery E2E NOT RUN. Старые keys/tokens/selection сохраняются. [Результат и границы](WINDOWS_CLAIM_RECOVERY_PLAN.md).

**Состояние Windows17.11,0.17:** opt-in Direct↔Relay реализован в локальном клиенте, без изменения v1 manifest/portable URI/server API. Manual Connect запускает Direct, после30с неподтверждённого трафика — Relay с60с ожиданием; terminal error может переключить после5с. Максимум2 switches за attempt, working path не перебирается, CAPTCHA/sleep pause, auth/rate-limit/cancel/foreign epoch отказ. Owner IPC сохраняет фиксированный SYSTEM DPAPI journal и проверяет scope/health до действия. Runtime вызывает только proxy mobile.Restart(config,0), WG/TUN/маршруты/DNS/WFP сохраняются. Path epoch связывает status/probes/leases/late HTTP и LKG proven path; subscription commit от прежнего path отклоняется. Local build/crypto/interop/fake restart/UI/offline PASS; real Direct/Relay/mobile.Restart/VPN/leak/sleep/crash E2E NOT RUN. Автоматическая смена физического uplink и восстановление UI intent после перезапуска не реализованы. [Дизайн и ограничения](WINDOWS_TRANSPORT_PLAN.md).

**Состояние Windows17.11,0.16:** реализованы DPAPI KnownGood snapshot/backup и однократный автоматический возврат после неудачной принятой manual Connect попытки нового managed-профиля. Promotion требует≥5с service proof для одного runtime с handshake/egress/Rx/Tx, Go key/manifest verification и fresh authenticated status. Trial120с не засчитывает CAPTCHA/длинный sleep; user action/auth/rate-limit/revocation/session mismatch запрещают recovery. Условный owner IPC проверяет active/stopped attempt и private-key equality под broker mutex; сохраняет прежние routing/CAPTCHA настройки и candidate/token/seen revision. Manual stop не зависит от доступности записи cancellation marker: memory gate ставится сразу, persistent marker — при доступном диске. Backup/UI restart не восстанавливает connect intent. Local build/crypto/interop/synthetic lifecycle/UI/offline PASS; live VPN/LKG/SCM stop/leak/sleep E2E NOT RUN. Это клиентский bounded return при принятом Connect; bootstrap claim recovery после expiry и Direct↔Relay ещё впереди. [Результат и ограничения](WINDOWS_LKG_PLAN.md).

**Состояние Windows17.11,0.15:** opt-in periodic sync реализован поверх прежнего HTTPS API: первая проверка через15с, затем30мин при подтверждённом owned managed runtime, single-flight, bounded backoff/Retry-After, staging без live apply. Рабочий профиль определяется по configuration digest и attempt id, не по выделенной строке списка; identity подтверждается свежим runtime/PID/options. Перед HTTP и сохранением проверяется текущий сеанс; закрытие/отключение/действие пользователя отменяет запрос.401/403 сохраняет отказ и запрашивает conditional stop только соответствующего runtime под broker mutex. Настройка выключена по умолчанию, работает пока открыто приложение и входит в encrypted backup. Local build/crypto/interop/synthetic HTTP+actual Go/UI/offline checks PASS; live HTTPS/revoke/VPN E2E NOT RUN. Traffic-proven LKG/automatic rollback/Direct↔Relay и отдельная служба фоновой подписки ещё впереди. [Результат и ограничения](WINDOWS_SYNC_PLAN.md).

**Состояние Windows17.11,0.14:** реализована регистрация по действующему `ftm-enrollment` JSON из панели и локальной URI-обёртке `ftm-enroll://<base64url JSON>` (не HTTP endpoint). Windows создаёт/сохраняет отдельную WG пару/CID/device token/request UUID до HTTPS и восстанавливает ту же попытку после перезапуска/потери ответа. Source user token очищается из текущей записи после acknowledgment; first manifest проверяется по device/key/CID/origin/revision/ETag, профиль добавляется без автоматического VPN. Pending backup/merge поддержан. API/schemas не менялись. Local crypto/DPAPI/fake HTTP+actual Go builder/UI checks PASS; live TLS/enroll/new CID/VPN E2E NOT RUN. Periodic sync, runtime LKG и Connection Manager впереди. [Результат и ограничения](WINDOWS_ENROLLMENT_PLAN.md).

**Состояние Windows17.11,0.13:** персональный bootstrap import/claim и ручной subscription refresh реализованы. Manifest проверяется по device/origin/derived public key/revision/canonical ETag, private key берётся только из локального WG. Обновление сохраняется отдельным кандидатом; explicit apply/return меняет только каталог для следующего ручного подключения. Есть DPAPI/backup/revision/refusal guards. Локальные Python↔Go/C#/crypto/UI проверки PASS; actual managed HTTPS/VPN/revoke E2E NOT RUN. Это не готовые enrollment по user URL, periodic sync, traffic-proven LKG или Direct↔Relay Connection Manager. [Проверенный объём и ограничения](WINDOWS_MANAGED_REFRESH_PLAN.md).

Одна user subscription URL, независимые device credentials; токен подписки не должен содержать в себе один общий приватный VPN-ключ.

Пример версионированного ответа **не финальная схема**:

```json
{
  "schema_version": 1,
  "subscription_id": "opaque-uuid",
  "revision": 7,
  "device_id": "opaque-uuid",
  "profile": {"backend": "wireguard", "client_ip": "10.77.43.10/32", "server_public_key": "...", "internal_api_host": "vpn.example.org", "internal_api_ip": "10.77.43.1"},
  "transports": [
    {"id":"vk-relay", "provider":"vk", "priority":1, "freeturn_peer":"vpn.example.org:56001"},
    {"id":"direct", "provider":"direct", "priority":2, "freeturn_peer":"vpn.example.org:56001"}
  ],
  "refresh_seconds": 1800,
  "issued_at": "2026-11-09T00:00:00Z"
}
```

В реальной схеме нельзя выдумывать параметры `freeturn://`/TURN. Codex обязан сначала сверить текущие парсеры FreeTurn Android/Go и существующие `profile_links()`; оформить совместимую спецификацию (JSON Schema + encode/decode/validation + round-trip tests). Отдельно учесть серверные VK link/credential lifetime и CAPTCHА: автоматическое создание свежих TURN-учётных данных не гарантируется.

API под `/api/client/v1/` и `/api/admin/v1/` (внутренние пути админки можно скрывать вместе с базовым путем), примерные операции:
- `POST enroll` — регистрация нового устройства, локально созданный public key + CID + idempotency key; авторизация user secret/approval, отработка повторного запроса;
- `GET subscription` — профиль **конкретного устройства** под его device token; `ETag`/`If-None-Match`, ревизия, подпись при необходимости; `304` без изменений;
- `POST bootstrap/claim` — связывание предварительно выданного bootstrap с подпиской изнутри VPN;
- `POST client/heartbeat` — опционально лёгкая телеметрия режима и ошибок без содержимого трафика;
- admin CRUD users/devices, bootstrap, subscription token rotation, status/metrics, backup and restore trigger with re-auth.

Ошибки: `401` нет токена, `403` отключён/лимит, `409` конфликт/устройство уже зарегистрировано, `410` истёк bootstrap, `422` ошибка данных, `429` throttling, `503` agent unavailable. Единая структура ошибки с кодом, машинным полем `code`, текстом RU, correlation ID без секретов.

Модель статусов клиента: `UNCONFIGURED -> BOOTSTRAP_READY -> CONNECTING -> VPN_UP -> SYNCING -> MANAGED -> CONNECTED`; отдельные `DEGRADED`, `RETRYING`, `ERROR`, `REVOKED`. При ошибке синхронизации не терять рабочий VPN.

**Интернет/blocked-IP:** метод получения по внутреннему адресу VPS должен работать даже при недоступности внешнего `443` из РФ, если TURN-подключение уже установлено. Выдача нового устройства одним только токеном без первого транспорта тогда невозможна: bootstrap обязательно предусмотреть и протестировать.

### 5.1. Авторизация VK и CAPTCHA — уточнение 14.11.2026

**Решение пользователя:** переиспользовать существующую автоматическую обработку CAPTCHA FreeTurn. Отдельный перенос/разработка автоматического solver из iOS или VPNN не требуется. Успех отдельных реальных попыток upstream-клиента не подтверждает готовность Android/Windows FTM и не гарантирует прохождение любой проверки VK.

- Сохранить штатный автоматический механизм и согласованный ручной fallback. Проверять фактическую загрузку страницы и её JS/CSS; пустое окно, HTTP 404 ресурсов или тайм-аут не считать требованием пользователя пройти проверку повторно. Показывать понятное состояние и безопасный код ошибки.
- Один координатор владеет auth attempt/challenge; потоки одной credential group ожидают общий fetch. Не открывать дубли UI одного challenge, не терять ручной ответ при retry, поддержать cancel/backoff. Самостоятельные проверки разных необходимых credential groups не объявлять дублями без диагностики; `n/spc` менять только после проверки квот и качества.
- Ограниченный изолированный кэш пригодных credentials: проверенный TTL с запасом, invalidation и соблюдение allocation quota. Не смешивать devices/calls/accounts и не возвращать отозванные credentials. Invalid link/call full/anonymous blocked/rate limit не вызывают перебор identities или шторм запросов; фон не открывает интерактивное окно самовольно.
- **К проработке, не обязательный перенос:** Calls-first авторизация из iOS/VPNN — отдельный кандидат только при подтверждённых проблемах существующей авторизации. Исследование от 10.11.2026 сохранено в [VK_AUTH_RESEARCH.md](VK_AUTH_RESEARCH.md); его прежнее решение об обязательном переносе заменено этим уточнением. При выборе адаптера отдельно закрепить исходники/лицензии, TLS/HTTP ограничения и socket protection; личные VK account/cookies администратора не требуются.
- WG keys/CID/PSK, профиль iPhone, wire protocol и `vendor/vps/` ради auth-доработки не менять. Не выводить secrets, challenge URLs, тела auth-запросов и TURN credentials в logs/API/Git.
- Приёмка T28: реальные Android/Windows подключения со штатной автоматикой там, где VK её допускает; работоспособный manual fallback, отсутствие дублей одного challenge, cache/TTL/scope/cancel/backoff и настоящий VPN-трафик. Текущий статус интеграции FTM — **NOT IMPLEMENTED / NOT RUN**. Автотесты только для существенных credential/concurrency/security рисков, остальное сборкой и рабочим сценарием.

## 6. Connection Manager: Direct ↔ VK Relay

**Семантика:** сохраняется тот же WG/AWG peer, тот же CID и VPN-IP; меняется только транспорт FreeTurn к серверу. Не путать переключение транспорта с заменой криптопротокола WireGuard на TURN.

- Режимы UI: `Автоматически` (по умолчанию), `Только через VK TURN`, `Только Direct`.
- При `Auto`: сначала использовать **последний успешный маршрут**, если он достаточно свежий; иначе configurable prefer Direct, затем VK Relay. Переходить по подтверждённому неуспеху, а не просто на основании недоступности ICMP ping.
- Проверка: handshake WG + поступление rx/tx + запрос к известному контрольному endpoint **через туннель**; не считать запуск интерфейса доказательством связи. Дополнительно учитывать DNS и MTU.
- Для первой версии разумные **настраиваемые стартовые значения**, не выдавать их за оптимум: 6–10 секунд проверки, 2 последовательные неудачи, cooldown 30–60 секунд, backoff с jitter, запрет oscillation. Значения выбрать по измерениям.
- После нескольких ошибок Direct переключить FreeTurn в Relay, не создавать новых peer/ключей; после ошибочного Relay выполнять диагностику/бэк-офф, не зацикливаться.
- Если Relay работает, не переключать автоматически обратно на Direct при одном удачном пакете. Поддерживать sticky route и manual override. Возвращение на Direct только после устойчивых подтверждений и безопасного probe, без разрушения активного соединения (если невозможно make-before-break — не переключать при активной передаче).
- Исключить трафик самого TURN-клиента из VPN, чтобы не было packet routing loop; Windows применяет маршруты интерфейса/защищённый service, Android использует `VpnService.protect()` и актуальную модель приложения.
- При включённом VPN не переводить VPN-classified трафик в DIRECT при ошибках; соблюдать DNS/IPv6 и split tunneling. Самостоятельная постоянная блокировка интернета вне работающего VPN исключена по решению18.11. В UI показывать фактический транспорт и причину последней смены.
- Возможность сброса диагностики и экспорта очищенного лога (без ключей/ссылок/VK-secret).

### 6.1. Раздельная маршрутизация сайтов и DNS — уточнение 10.11.2026

**Актуализация17.11,0.11:** private unicast DNS для single-label/home.arpa/lan/home/internal/corp/intranet/test реализован через configured private on-link resolver физической сети, без public/VPN fallback; localhost локально, .local/mDNS остаётся отдельной задачей. Durable fake-IP cache содержит только keyed HMAC→IP под AES-GCM/DPAPI, без hostname/URL/времени посещений; legacy migration сохраняет ключ/IP/head. Bounded TLS SNI/HTTP Host может восстановить известную TCP identity после reconnect до remote dial; ECH/unknown UDP без свежего DNS закрываются. Private A не попадает в journal и управляется общим LAN toggle; доменный BLOCK не заменяет IP firewall. Локальные crypto/privacy/build/UI проверки PASS, live OS/SYSTEM/TUN/WFP/LAN/leak E2E NOT RUN. [Решение и проверенный пакет](WINDOWS_LAN_DNS_PLAN.md). Запись0.10 ниже — история.

**Актуализация17.11, checkpoint0.10:** Windows opt-in backend связан с IPC/SYSTEM options, service/health/egress,7 presets/domain editor/direct DNS и encrypted preference backup. Stable fake-IP identity journal защищает reconnect от alias; in-memory packet/crypto/rollback, C# interop/UI и readonly checks PASS. В обычном режиме остаётся WGNT; службы/реальный VPN не обновлялись/не запускались. Private names/mDNS, полноценный GeoIP, app matching, policy delivery, always-on lock и общесистемная T29–T31 приёмка остаются открытыми; actual TUN/WFP/leak/crash E2E NOT RUN. [Фактическое состояние и передача](WINDOWS_SYSTEM_ROUTING_PLAN.md). Промежуточные записи ниже относятся к состоянию до интеграции0.10.

По запросу пользователя добавить в панель/клиенты routing policy по скриншоту `POLESNIESOVETI12/web-panel-proxy`: российские сайты и локальные сети напрямую, YouTube и push Apple/Google через VPN, connectivity checks напрямую, BitTorrent block, split DNS и простое добавление доменов администратором. Исследование, pinned source, порядок правил и ограничения: [ROUTING_POLICY_RESEARCH.md](ROUTING_POLICY_RESEARCH.md). Полная общесистемная приёмка впереди; статус текущих подэтапов указан ниже.

**Промежуточная реализация17.11.2026:** рабочий Windows0.9 сохраняет custom domain rules для SOCKS5 TCP/IPv4. В новой разработке реализованы policy/pinned datasets/fake DNS и общесистемный per-flow backend; реальные in-memory gVisor→WG TCP/UDP/DNS проверки PASS. Root-only TUN/WFP lifecycle подготовлен как код, но **ещё не связан с рабочей службой/IPC/UI**; текущий0.9 не применяет presets. Полная системная маршрутизация, private names/mDNS, проверенный GeoIP, panel delivery и T29–T31 не приняты; реальное OS/VPN/leak E2E **NOT RUN**. [Текущее состояние и остаток](WINDOWS_SYSTEM_ROUTING_PLAN.md), [границы SOCKS](WINDOWS_ROUTING.md). Это не меняет требуемую ниже общесистемную приёмку.

- «Напрямую» — физический канал клиента с его провайдерским IP, не FreeTurn Direct до VPS. Исполнение в Android/Windows до WG encryption; server-side egress и обычный WG AllowedIPs не считаются доменным маршрутизатором. Сохранить WG/FreeTurn и текущий server baseline, не ставить Xray/чужую панель ради копирования UI.
- В разделе «VPN/Транспорт → Маршрутизация» семь переключателей со скриншота и поля DIRECT/VPN/BLOCK: один домен в строке, без raw JSON/regex. IDNA/hostname validation, exact/«с поддоменами», предел300 custom domains как начальная настройка, dedup, конфликтный preview, добавление/удаление/поиск. Domain-boundary matching обязателен; URL/path/port/credentials/IP/public-suffix-only записи не принимать.
**Правила приложений Windows17.11,0.22:** optional full drive EXE path→direct/vpn/block,≤64 rules/1024 UTF-8 bytes/path, case-insensitive exact matching, без basename/masks/UNC/ADS/env/parent inheritance. Работают только в opt-in system routing после нового Connect. Bounded IP Helper TCP exact tuple/UDP unique local endpoint PID + held query-limited process handle/liveness/creation/tuple recheck; unknown/ambiguous data owner блокируется, при отсутствии правил lookup отсутствует. UDP перед send/delivery проверяется заново. App action выше обычных domain/preset rules, но не base BLOCK/служебной защиты; DNS53 общий и не блокируется per-app BLOCK. Настройки в DPAPI/backup, UI embedded editor, status без путей/PID. Snapshot API/creator PID не дают атомарной kernel attribution и не являются sandbox/подписью; transferred socket/helper/версионированный путь имеют ограничения. Local Go/native loopback/C#/actual preview/in-memory encrypted WG/UI/build/offline PASS; реальные application/TUN/WFP/UDP performance/leak E2E NOT RUN. [Дизайн, проверки и downgrade](WINDOWS_APP_RULES_PLAN.md).

**Локальные имена Windows17.11,0.21:** DNS-путь A-имён.local реализован через bounded legacy mDNS RFC6762§6.7 на выбранном физическом private IPv4 интерфейсе при LAN DIRECT. Ephemeral source/TTL255, fresh query ID,≤4 sockets/2s/64 packets/4096 bytes; LUID/index/source/mask и WSA packet-info проверяются перед принятием on-link response, private target/CNAME/class/TTL≤10 ограничены. Нет public/unicast/VPN fallback, durable имён, native5353 listener/membership или расширения firewall. MDNSConfigured — mode, не подтверждение обнаружения. Local Go/real loopback WSA/C#/native/offline проверки PASS; real multicast/LAN/native Windows/Bonjour/TUN/WFP/leak E2E NOT RUN. Полный DNS-SD discovery/PTR/SRV, IPv4 link-local и публично адресованные LAN этим кодом не реализованы. [Дизайн и реальные проверки](WINDOWS_MDNS_PLAN.md).

**GeoIP Windows17.11,0.20:** IP fallback переведён с RIR allocation hint на DB-IP Lite2026-11 (приблизительная геолокация).12902 RU IPv4 prefixes, original CSV.gz/CC BY4.0/attribution/modification notice и pinned compressed/raw SHA/record count. Bounded strict compiler и runtime проверяют hash/provenance/date/source/canonical nonoverlap/protected ranges; невалидный source не заменяется RIR fallback. Priority BLOCK/protected management/custom/YouTube/push/domain выше country IP; unknown/non-RU остаётся VPN. Pure preview возвращает metadata, UI показывает источник/дату базы пакета, а не активную базу старой службы. Local Go/Python/actual C# bridge/build/native/offline checks PASS; реальные GeoIP/TUN/WFP/VPN/leak E2E NOT RUN. Безопасное обновление списков и managed policy delivery пока не реализованы; runtime не скачивает базы. [Дизайн, источники и проверки](WINDOWS_GEOIP_PLAN.md).

- RU preset: контролируемые версии GeoSite/RU domain list, .ru/.su/.рф и GeoIP RU fallback. YouTube/push domains выше широкого RU/GeoIP bypass. Явные admin domain exceptions выше пресетов; BLOCK и защитные invariants выше исключений. Default — VPN; недоступность туннеля не превращает VPN-classified flow в DIRECT. Админские DIRECT исключения сохраняют согласованную split routing/DNS политику работающего VPN.
- LAN bypass не ослабляет запрет доступа к закрытым private/metadata службам VPS. Точный internal management IP/TCP443 остаётся **VPN-only** и приоритетнее пересекающейся домашней сети; TURN/VK/auth sockets защищены от попадания в свой туннель. Connectivity/captive portal checks direct отделены от tunnel health checks.
- Split DNS: стартовые кандидаты Яндекс для RU/DIRECT и Cloudflare/Google для VPN/остального, настраиваемые администратором; локальные имена — через resolver/mDNS домашней сети, без отправки private names публичному DNS. До реализации подтвердить TLS endpoints/маршруты. DNS следует routing intent домена, CNAME/TTL/A/AAAA/shared CDN, без скрытого direct plaintext fallback при ошибке VPN resolver. Проверить own DoH/DoT, QUIC, IP literals и невозможность domain classification; TLS interception не добавлять. Текущий IPv6 block не отменять без leak tests.
- BitTorrent checkbox требует настоящего enforcement в заявленном клиентском/серверном scope, без DIRECT обхода. Одна блокировка портов/скопированное Xray protocol rule не доказывает обнаружение любого encrypted BitTorrent. Отдельно проверить DHT/смену порта и ложные срабатывания; неподдерживаемую возможность честно показывать в UI.
- Routing policy версионируется, доставляется managed client с schema/capability negotiation, применяется атомарно с rollback/LKG и отображением фактической device revision. Не добавлять неизвестные поля в текущий strict v1 или импорт Anton48. Изменения через защищённый admin API/ограниченный IPC, root SQLite ownership сохраняется; policy входит в encrypted backup. Не вести персональный журнал посещений/DNS.
- Цель — доступность выбранных сервисов с обычного IP при включённом VPN. **Не обещать исчезновение всех VPN-detection сообщений:** OS VPN state, account/geolocation/IP reputation могут проверяться независимо. Приёмка T29–T31 требует измеренного DIRECT/VPN egress, DNS и настоящих native-client сценариев; текущий профиль этих правил ещё не применяет.

## 7. Android FreeTurn

- Ответвиться от официального FreeTurn, проверить версию/двоичные native-библиотеки, сохранив прежние функции: профили, импорт, WG/AWG, Relay/Direct, split tunneling, reconnect, настройки DNS.
- Добавить вкладку «Подписка»: вставка `https://...`/QR/Deep link; одна ссылка пользователя; on-device генерация ключей при обычной регистрации; список устройств/профилей; ручное «Обновить», автообновление каждые ~30 минут **и** при запуске/после успешного восстановления VPN (не бесконечный polling).
- Безопасное локальное хранение токенов/ключей в системном хранилище Android; не показывать полный секрет в логах/уведомлениях/бэкапах.
- Bootstrap → managed без повторного импорта, с rollback.
- Интеграция Connection Manager по спецификации §6, статусы Direct/Relay, полезные причины ошибок на русском.
- APK debug/release (release signing — только из секретов локально/CI, без private key в repo). Миграция данных и tests, проверить Android 7+ с реальными версиями и устройствами. Тестировать обновление поверх существующей официальной установки с учётом package signature (если подпись другая, install-in-place может быть невозможен; дать безопасную процедуру миграции).
- Учитывать GPL-3.0, публикуемые исходники производных работ и notices.

## 8. Windows FreeTurn Desktop

- Проверить существующий форк `l1ch666/turn-proxy-android/desktop` и его ограничения. UI можно сохранить/портировать на Compose Desktop; адаптировать под Windows 10/11 x64; архитектуру движка выбрать только после spike на реальном туннеле. Не считать sing-box автоматически совместимым с нужной сборкой AWG.
- Поставлять **настоящий системный VPN**, не только SOCKS5/HTTP proxy. Wintun/WireGuardNT или корректно лицензируемый совместимый WG-драйвер; AWG — только проверенная реализация, при необходимости отложить до отдельного тестируемого этапа.
- UI непривилегированный, Windows Service с необходимыми правами управляет адаптером, маршрутами и transport; ограниченный IPC/ACL между приложением и сервисом, отсутствие исполнения произвольных команд.
- Импорт тех же ссылок / QR / bootstrap, автообновления, переход bootstrap→managed, три режима соединения, auto-reconnect, трэй, автозапуск по выбору, отображение IP, маршрута, нагрузки/трафика; русская локализация.
- Устанавливать/удалять сетевой адаптер и маршруты корректно; после sleep/resume, смены Wi-Fi, перезапуска службы сеть восстанавливается; DNS/IPv6 protection активного VPN и rollback маршрутов при uninstall.
- Подписанный EXE/MSI/MSIX при наличии сертификата; если платный код-сайнинг недоступен — предложить явный **unsigned build** с объяснением SmartScreen и воспроизводимой сборкой, не заявлять «подписано». Лицензии Wintun/драйверов проверить.
- Обязательная проверка с 2 одновременно работающими клиентами Android+Windows и 3 устройствами одного пользователя.

## 9. Административная панель, домен и UX

**Референс логики — 3X-UI_KIT `scripts/3x-ui.sh`:** случайный panel path (`rand_str 18`), proxy routes к панели и подписке, для `location /` статическая заглушка. У нас Caddy и собственная панель; не нужен и не устанавливается 3X-UI KIT.

Маршруты примерные:

- `https://vpn.example.org/` → статичная аккуратная светлая/тёмная заглушка «Сайт находится в разработке»; не раскрывать тип VPN, версии, адреса админки.
- `https://vpn.example.org/a/<RANDOM_24PLUS>/` → React SPA панели; случайный путь достаточной энтропии, **но он не заменяет логин, стойкий пароль, CSRF/session protection и 2FA (TOTP по желанию)**.
- `https://vpn.example.org/sub/<USER_SECRET>` → клиенты; регистрация строго по API и политикам; не отдавать приватные конфиги случайному посетителю.
- FastAPI на `127.0.0.1`/Unix socket, закрыт публично; Caddy обслуживает TLS/route. Внутренний VPN DNS override для одного и того же имени домена при подключении к `10.77.43.1`; проверки TLS сохраняются.

**Вкладки (обязательный MVP):** «Обзор», «Пользователи», «Устройства», «Подписки», «VPN/Транспорт», «Мониторинг», «Журнал событий», «Настройки»; responsive desktop/mobile, dark/light mode, русский язык, ясные ошибки/empty states, доступность клавиатуры, настоящий поиск/фильтры, loading states и подтверждение опасных действий.

Содержимое «Обзор»: статус services, 1 VPS, текущие CPU/RAM/диск, network rx/tx, оценочное число недавно активных peers, число устройств/пользователей, длительность работы, история ошибок. Таблица устройств: имя, OS, assigned IP, wg peer, последний handshake, последняя ревизия подписки, последний сообщённый маршрут, rx/tx, enabled. Для iOS маршрут не всегда известен — показывать «нет данных», не придумывать.

Графики только по реальным замерам с лёгким collector systemd+`/proc`/`wg show` и агрегированными samples в SQLite (интервал например 60 с, retention 7/30 дней). **Не устанавливать Prometheus+Grafana/InfluxDB** на 1 ГБ RAM. Никаких персональных журналов посещённых сайтов.

**Состояние 18.11.** Разделы подписок, VPN и транспорта, мониторинга и настроек проверены локально. История агрегатов хранится 7 дней отдельно от БД профилей. Таблица устройств показывает серверную ревизию, последний handshake и текущие счётчики. Получение фактически применённой клиентом ревизии и маршрута остаётся открытым. Развёртывание новых разделов на VPS — NOT RUN. [Проверки](PROGRESS.md).

Безопасность: HTTPS TLS, `Secure HttpOnly SameSite` cookies, password hashing (Argon2id если помещается/зависимости доступны, откалибровать память; либо scrypt/PBKDF2 с достаточной стоимостью), rate limiting, session expiry, TOTP как опция, sanitization, CSP/CORS, CSRF для cookie-auth, XSS protections. Скрытый URL — лишь дополнительный слой; никогда не считать его авторизацией. Автогенерация длинного admin path, admin credentials при установке; печатать их только на консоль root либо в root-only файл.

## 10. Ресурсы и производительность

**Железо:** 1 vCPU / 1 GiB RAM, заявленный сетевой порт 1 Gbit/s — **это верхний предел порта, а не измеренная пропускная способность через VK TURN**. Узкие места: relay/оператор, single-core CPU, обработка FreeTurn, MTU, RTT, NAT.

- Не компилировать Android/Windows/React/Go в production на 1 ГБ VPS. CI/local компилирует и публикует подписанные и хешированные артефакты. VPS получает готовые бинарники и static web.
- Без Docker, PostgreSQL, Redis, Node.js runtime, Grafana. Одна API worker, SQLite WAL, умеренный пул соединений, ротация журналов.
- RAM: целевой **idle used RSS/PSS** измеряется; ориентир — иметь >= 150 MiB available под нормальную нагрузку, но не утверждать без стендовых тестов. `MemAvailable` + OOM + swap-in/swap-out отслеживать. При нехватке памяти сначала оптимизировать API/сервисы, а не скрывать проблему swap.
- FreeTurn прежние лимиты CPUQuota 50%/RAM 96М — baseline. Сравнить с более свободной конфигурацией 75/100% CPU, 96/128/160 MiB RAM; оценивать p50/p95 throughput, RTT, CPU, OOM. Не снимать защиту, не измерив результат и стабильность.
- Benchmark matrix: прямой сервер (без VPN) → FreeTurn Direct + WireGuard → FreeTurn VK Relay + WireGuard → AWG при наличии; один Android, один Windows, одновременно 2/5/10 клиентов; `iperf3`, реальные HTTPS-download и ping/RTT; минимум 3 прогона и условия сети/оператора.
- Проверки: загрузка/отдача, 100+ MiB file, UDP/TCP, видео, reconnect Wi-Fi/LTE, Windows sleep/resume, DNS leaks, IPv6 leaks, нагрузка CPU/RAM, MPTU/MTU. Не обещать 1 Гбит/s через relay; использовать замеры.
- Не проводить непрерывные тесты скорости фоном; только по запросу администратора.
- **Уточнение17.11.2026:** оптимизацию скорости вынести после текущего согласованного технического объёма. Начать с замеров Direct/Relay, CPU/RAM клиента/VPS и влияния потоков/повторной авторизации; затем исследовать закреплённое ядро и, если пользователь предоставит другую версию, сравнить их. Менять один фактор за раз, сохранять ключи/совместимость и ограничения ресурсов. До замеров не обещать прирост и не менять лимиты автоматически. [Отложенный объём](REMAINING_WORK.md#отложенная-оптимизация-скорости--поручение17112026).

## 11. CLI, мониторинг, резервное копирование и диагностика

Установить локальную команду `ftm` с меню и скриптовыми подкомандами:

```bash
ftm status
ftm doctor
ftm users list
ftm devices list
ftm backup /root/ftm-2026.vpnbackup
ftm restore /root/ftm-2026.vpnbackup --dry-run
ftm logs --sanitize
ftm update --check
ftm uninstall --dry-run
```

`doctor` проверяет unit states, listen-ports, DNS, TLS/cert renew, local API, SQLite `PRAGMA integrity_check`, WG peers, CID consistency, firewall exceptions, free RAM/disk, E2E probe где возможен. `backup` включает бэкап существующего `vps-vk` + SQLite и защищённую конфигурацию manager; хранить копию **вне VPS**, проверять restore на отдельной временной/чистой машине (в тестовой среде).

`ftm update` скачивает **закреплённый релиз**, сверяет подписи/хеши, сначала делает snapshot, затем миграции, healthcheck, при неуспехе rollback. Не делать бесконтрольный update на latest. `ftm uninstall` удаляет только свои службы/правила/файлы; не трогает SSH, чужие сайты и пользовательские правила.


### 11.1. Автовосстановление на одном VPS — К ПРОРАБОТКЕ, 14.11.2026

**Статус:** предложения для последующего проектирования и оценки реализации, а не готовая функция и не разрешение менять VPS/клиентов сейчас. Пользователь просит продумать предотвращение и быстрое устранение инцидентов наподобие сегодняшнего. Разрешена только запись требований; параметры, сроки восстановления, resource budget и конкретные release gates определить по измерениям до реализации.

**Жёсткая граница:** один VPS, без резервного VPS, внешнего control plane или кластера как обязательной зависимости. Резервирование здесь означает альтернативный проверенный транспорт/порт/экземпляр на той же машине. Полный отказ VPS, всего его IP/канала или необходимой инфраструктуры VK автоматически обойти нельзя. Если все пути до этой машины недоступны, сохранённый bootstrap и подписка на ней не доставят исправление: показать честное состояние и порядок ручного восстановления. Не обещать непрерывность TCP-сессий при переключении или отсутствие любых сбоев.

**Что рассмотреть:**

1. **Connection Manager по этапам сбоя.** Различать VK auth/CAPTCHA, TURN allocation, DTLS, регистрацию CID, WG handshake, DNS, MTU и выход в интернет. Проверять handshake/обмен и контрольный запрос через туннель, не только process up/ping/API. Последний успешный маршрут хранить локально. Пробовать заранее разрешённые кандидаты в ограниченном порядке; backoff с jitter, cooldown и sticky route предотвращают переключения туда-обратно. Бюджеты cold VK auth и тёплого reconnect различать; конкретные тайм-ауты измерить. Использовать только поддержанные кандидаты, возвращённые VK, без гарантии выбора произвольного relay.
2. **Согласованные запасные варианты в подписке.** Одна постоянная user URL, индивидуальный device credential и заранее подготовленные параметры доступных endpoints одного VPS. Каждый вариант — согласованный набор server key/адресов/портов/CID/OBF/backend и capabilities, а не замена одного IP/порта наугад. Не регистрировать устройство и не ротировать ключи на каждый retry. До публикации проверить доступ и серверную готовность. Вариант с параллельной systemd-службой/портом оценить на 1 vCPU/1 GiB; не делать постоянное удвоение служб обязательным, не вводить Docker. Старый Anton48 сохраняет свой проверенный профиль.
3. **Эволюция managed-контракта.** Текущий actual managed v1 допускает один `freeturn.peer`, фиксирует часть transport settings и связывает peer с management origin; несколько кандидатов и развязка адресов ещё не реализованы. Спроектировать версию контракта, capability negotiation и миграцию старых клиентов. Не добавлять неизвестные поля в upstream `freeturn://`; не ослаблять TLS identity/проверку origin. Подписка переносит данные конфигурации, не исполняемые команды ремонта.
4. **Подписка и последняя исправная конфигурация.** Проверять подлинность/структуру/revision, защищённо сохранять пригодные основной и запасные варианты на устройстве. Обновление применять атомарно после проверки, при неуспехе возвращаться к рабочему набору. Недоступность API не уничтожает работающий VPN/LKG. Использовать публичный HTTPS либо API внутри уже работающего VPN с прежней TLS-проверкой. Не обходить revoke/expiry: срок допустимого offline использования согласовать явно. Восстановление прежних настроек не должно оживлять отозванные tokens/peers; конфигурационный rollback отделить от защиты от replay старой подписки.
5. **Ограниченное серверное восстановление.** Лёгкий watcher проверяет process/socket/WG/config revision, RAM/disk и повторные сбои. Разрешённые будущие действия — ограниченный restart конкретной принадлежащей FTM службы, изоляция неисправного кандидата, уведомление и отчёт; privileged операции через проверенный agent. Не переустанавливать ОС/пакеты, не сбрасывать firewall и не перезапускать общий VPN по тайм-ауту одного устройства. Разделять общую исправность узла и доступность пути для конкретной сети/клиента. API/панель/SQLite не становятся обязательной зависимостью уже установленного data plane.
6. **Совместимые и постепенные обновления.** Закреплённые версии/hash/signature и матрица app/core/server/profile/schema отдельно для Android, Windows и Anton48. Равенство номеров не гарантирует E2E; разные номера не доказывают несовместимость. Snapshot и проверка на изолированном экземпляре того же VPS при достаточных ресурсах, малая группа устройств, E2E/ресурсы, затем расширение или откат. Не обновлять автоматически `vendor/vps/`/iOS ради исправления Android. Частичный сбой обновления не лишает SSH и рабочего старого пути; состояние должно переживать reboot. Offsite encrypted backup и проверяемое восстановление остаются обязательной основой.
7. **Диагностика и понятные статусы.** Correlation ID одной попытки, безопасные build/config identifiers, transport/endpoint identifier, стадия ошибки, счётчики pipe/network write/read и результат туннельной проверки. Ошибка сетевой отправки записывается сразу, а не только как поздний DTLS timeout. В панели показывать причину переключения, активный кандидат и историю восстановления; user heartbeat не должен быть единственным источником истины. Не собирать историю сайтов, payload, ключи, полные subscription/VK URLs или токены. Логи/экспорт/телеметрия ограничены по объёму/сроку; секретные CID и адреса маскируются согласно действующим правилам проекта. Проверки лёгкие, без постоянных speed tests и тяжёлого мониторинга.

**Матрица будущей проработки — не уже выполненные тесты:** падение одной службы; недоступный основной порт при рабочем альтернативном; auth/CAPTCHA/rate limit; DTLS без ответа; WG без интернет-трафика; сбой DNS/MTU; API недоступен; повреждённая/устаревшая/несовместимая подписка; истёкший/отозванный доступ; Wi-Fi/mobile и sleep; неудачный upgrade/rollback; reboot; полный отказ единственного VPS; одновременно несколько переподключающихся устройств. Проверять сохранность остальных клиентов/Anton48/SSH, отсутствие DNS/IPv6 leaks, соблюдение split routing и временных сетевых правил активного VPN, отсутствие retry storm и выполнение resource budget. Обязательную приёмку детализировать отдельно, не объявлять текущие T01–T31 расширенными проверками автоматически.

**Урок текущей диагностики:** успешное upstream-подключение к отдельному тестовому экземпляру не является FTM E2E. Версия, профиль, порт и TURN-путь менялись вместе; единственная причина прежнего сбоя не доказана. Не фиксировать в реализации вывод «любой timeout лечить обновлением ядра».

## 12. Однокомандная установка: ИНТЕРАКТИВНЫЙ мастер, как в 3X-UI_KIT (обязательное UX-требование)

**Важное уточнение пользователя:** финальная команда **НЕ должна требовать обязательного `--domain`, `--manager` или заранее введённых параметров**. Она запускает интерактивный мастер, который в SSH-терминале спрашивает необходимые настройки и автоматически разворачивает сервер. Дополнительно поддерживается неинтерактивный режим для CI/воспроизводимых установок.

**Референс реализованного UX:** `https://github.com/itsnotkubrick/3X-UI_KIT/blob/main/scripts/3x-ui.sh`, функции `choose_masking()` (п. 1: собственный домен, п. 2: автоматическая маскировка REALITY, п. 3: внешний сайт), `panel_on_choice()` (выбор IP/домен для панели и подписки), `domain_points_here()` (DNS-проверка). Это **UX-референс**, а не копия реализации: FreeTurn не использует REALITY/SNI-маскировку, поэтому подбор «соседа по подсети», чужого SNI и десятка протоколов **НЕ добавлять**. Веб-маршруты реализовать через Caddy, не через весь стек `3X-UI_KIT`.

**Целевая команда для интерактивного запуска (ПОСЛЕ разработки и E2E-проверки):**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NimmWee/Vps/main/install.sh)
```

В релизной документации **рекомендовать фиксированный тег или проверяемый bootstrap с pinned SHA256/подписью**, не плавающий `main`. Команда выше обозначает UX, а не гарантию, что текущая версия `install.sh` уже умеет устанавливать FreeTurn Manager.

### 12.1 Мастер настройки — последовательность вопросов

0. До первого вопроса: detect root, Ubuntu 24.04/architecture, доступные CPU/RAM/диск, системное время, занятые 22/80/443 TCP и порт FreeTurn UDP, существующую инсталляцию `NimmWee/Vps`, конфликтующие сервисы; **не делать firewall reset и не терять SSH**. Если установлен старый VPN, предложить «безопасно обновить/мигрировать», не перезаписывать текущие ключи.
1. **Режим установки**: `1 — Новая установка [по умолчанию]`, `2 — Обновление/миграция существующей`, `3 — Проверка/восстановление`. При обнаруженной прежней установке поменять рекомендацию на миграцию. Не спрашивать повторно факты, которые можно надёжно определить.
2. **Адрес панели и подписок:** `1 — Свой домен [рекомендуется]`, `2 — Публичный IP VPS (без домена)`. Смена варианта после установки должна поддерживаться через `ftm config web` без сброса пользователей и VPN-ключей.
3. Если домен: попросить FQDN (без `https://`); проверить DNS A/AAAA и внешний адрес VPS, статус Cloudflare-прокси/прохождения HTTP challenge при возможности, отсутствие конфликтов 80/443 TCP; предложить понятные действия `Повторить проверку / Выбрать IP / Выйти без изменений`. По умолчанию DNS-only (серое облако) для простой первичной настройки; не считать оранжевое облако универсально несовместимым, но не обещать поддержку без тестов. Caddy автоматически получает и продлевает публично доверенный сертификат для домена (80/443 должны быть доступны либо нужна явно реализованная поддержка альтернативной проверки). При неуспехе ACME **не показывать «всё готово»**, не отключать проверку TLS на клиентах, не разрушать рабочий VPN.
4. Если IP: обнаружить внешний IPv4; проверить, можно ли получить **публично доверенный сертификат именно на IP** с поддерживаемыми Caddy/ACME/CA в выбранном релизе. Если нельзя: предложить защищённое администрирование **через SSH-туннель или внутри VPN**, а не публичный HTTPS с недоверенным сертификатом. Не делать `curl -k`, отключение cert validation или открытую HTTP-панель стандартным режимом. В этом случае внешние HTTPS-подписки считать недоступными до настройки доверенного TLS, применять стартовый импорт/внутренний API по поддерживаемому доверенному имени и явно показать ограничение.
5. **Доступ к панели:** `1 — HTTPS на публичном домене/IP со случайным длинным путём + auth [по умолчанию при доверенном TLS]`, `2 — только через VPN/SSH-туннель`. Скрытый URL — не защита вместо пароля. Для `2` сохранить удобный root-only способ узнать адрес/команду туннеля.
6. **Страница на `/`:** `1 — «Сайт находится в разработке» [по умолчанию]`, `2 — свой статический HTML из проверенного локального файла`. Не запускать отдельный Node/Nginx, не копировать REALITY-подбор чужого сайта. Любой неизвестный путь — аккуратный 404 или заглушка согласно согласованным роутам, но не редирект на секретную панель.
7. **VPN-часть:** по умолчанию переиспользовать актуальные проверенные WireGuard+FreeTurn Server+VK TURN настройки/порт, спросить только реально недостающие данные (например, VK link) с защищённым вводом; AWG только если E2E-подтверждён. Предложить импорт существующих ключей; не навязывать WireGuard/AWG выбор, если на данном билде работает только WG. Существующий Anton48 должен работать после миграции.
8. **Администратор:** предложить имя; сгенерировать длинный случайный пароль с однократным защищённым выводом или принять безопасный ввод; сгенерировать секретный путь панели и закрытые учётные данные. Никаких секретов в world-readable output/log или аргументах shell. Тема панели по умолчанию dark, настраивается позднее из UI.
9. **Сводка перед установкой** (домен/IP, DNS/TLS статус, доступ панели, сайт, порт VPN, установка/миграция, ресурсы, конфликтующие порты) и один вопрос `Продолжить? [Y/n]`. Не показывать пароли и Client ID. Если нужно изменить пункт — разрешить вернуться к нему.
10. **Установка:** prebuilt pinned artifacts + sha/signature verification; существующий `vps-vk`/WireGuard/Fail2ban, FastAPI, SQLite WAL, статичный React, Caddy, systemd, firewall только для необходимых портов, privilege separation; при ошибке восстановить предыдущую работоспособную конфигурацию.
11. **Завершение:** реальные healthcheck `ftm doctor`; напечатать domain/IP URL, секретный путь панели, состояние TLS, команду `ftm`, каталоги бэкапов и статус пользователей, отдельно выделить *неработающие* шаги. Логин/одноразовый пароль в root-only файле или защищённый вывод; файл с permissions 0600. Если публичный TLS невозможен — честно подсказать SSH/VPN-only доступ.

### 12.2 CLI после установки

Команда `ftm` без аргументов открывает компактное текстовое меню: `Статус/диагностика`, `Панель и домен (перенастроить)`, `VPN/FreeTurn`, `Пользователи/профили`, `Резервное копирование/восстановление`, `Обновление`, `Логи`, `Выход`.

Отдельно должны работать `ftm status`, `ftm doctor`, `ftm config web`, `ftm backup`, `ftm restore`, `ftm update`, `ftm uninstall` и `ftm help`. `ftm config web` должен менять IP↔домен и пересобирать Caddy/сертификат без потери текущих ключей/подписок; если адрес подписки меняется, показать миграционные риски и сохранить redirect/alias, когда безопасно и возможно.

### 12.3 Неинтерактивный режим (дополнительно, а не вместо мастера)

Предусмотреть `install.sh --non-interactive --config /root/ftm-install.env` для тестов и CI, с файлом конфигурации `0600`, валидацией всех полей и `--dry-run`. Явные `--domain` и `--mode ip` допустимы как необязательные shortcut-флаги; никаких секретов на командной строке или в истории команд.

### 12.4 Контракты и ограничения

- **Домен влияет на удобство и стабильность URL, но не увеличивает пропускную способность VK TURN и не обходит блокировку IP сам по себе.** DNS только указывает на сервер или проксирующий сервис.
- При недоступном прямом HTTPS первая активация возможна только через персональный **bootstrap-профиль**, доставленный пользователю независимо; после первого VPN клиент делает bootstrap→managed через внутренний HTTPS API. Это остается обязательным сценарием и в domain, и в IP режиме (при корректной TLS identity).
- Нельзя считать `https://<IP>/` надёжной клиентской подпиской без доверенного сертификата и поддержки в клиентах. Надёжный именованный HTTPS endpoint предпочтительнее для мобильных приложений.
- Приложение не требует установки Docker, PostgreSQL, Node runtime и `3X-UI_KIT`; Caddy отдаёт готовую статическую SPA.
- Все стадии идемпотентны; `SIGINT`, loss of SSH, DNS/TLS fail и частичная установка должны быть обработаны без потери текущего VPN/SSH.
- **Файлы:** `/etc/ftm/` (0700), `/var/lib/ftm/` (SQLite/бэкапы, 0700), `/opt/ftm/` (backend/static), `/usr/local/bin/ftm`; согласовать с уже существующими `/var/lib/vps-vk` и unit.

## 13. Миграция и совместимость

- Мигратор обнаруживает старую `NimmWee/Vps` инсталляцию, сохраняет серверные WG-ключи, IPv4 subnet, CID, VK-call link, existing `iphone`/`android` profiles, порт/obf-key/профили, firewall, Fail2ban. До миграции создать бэкап и провести валидацию приватного/публичного ключа.
- Старые CLI `vps-vk status`, `vps-vk profiles` и работа существующих сторонних клиентов не ломаются без явно объявленной deprecation/миграции.
- Не менять существующие ключи и не удалять peer по умолчанию. Не включать новую подписку для Anton48; выдача/экспорт вручную.
- Тест rollback даже при ошибке на половине SQLite migration, при падении agent, при неудачном Caddy TLS и после частичного создания WG peer.
- Добавление новых устройств должно происходить без обрыва старых подключений (если hot reload невозможно — честно описать краткий контролируемый рестарт).
- Разобраться с GPL-3.0 Android/desktop, лицензией core, Wintun/AWG и `NOTICE` каждого третьего проекта; не включать закрытые заимствования без соблюдения условий.

## 14. Этапы выполнения — обязательные gates

### Этап 1. Аудит, baseline и минимальная установочная структура

**Сделать:** форк/рабочая ветка, структура репозитория, матрица версий, lockfiles; воспроизвести работу текущего `NimmWee/Vps` с Anton48 и Android; API/CLI контракт текущих бинарников; зафиксировать тесты и версию FreeTurn Server; создать план миграции и skeleton `--manager` (не утверждать готовность продукта). Автономный smoke test оригинального VPN.

**Приёмка:** baseline tests зелёные, `vps-vk status`, `profiles` и старый VPN работают, нет потери конфигурации. Отчёт о совместимости и рисках.

### Этап 2. Динамические peers, SQLite и privileged agent

**Сделать:** SQL schema/migrations, миграция двух фиксированных клиентов; CRUD users/devices через сервисное API/CLI; уникальные адреса/CID/ключи; безболезненный reconcile `wg`/`clients.json`; Firewall allowlist для внутреннего HTTPS; бэкап SQLite.

**Приёмка:** одновременно 3 устройства одного пользователя, 20 пользователей/60 devices как data model; одновременное создание устройств без коллизий; отзыв одного устройства не рвёт остальных; старый Anton48 продолжает работать. REST backend пока может быть без графического UI.

### Этап 3. Домен, Caddy, API и красивая панель

**Сделать:** FastAPI (user/client/admin endpoints), session auth + rate limiting, статический React build, тёмная/светлая темы; `/` заглушка, `/a/<random>/` админка, `/sub/...` endpoint; HTTPS, TLS renewal, rootless API; оптимизированный сбор метрик.

**Приёмка:** посетитель видит сайт-заглушку; случайный URL без логина не раскрывает данные; админ входит, создаёт пользователя, управляет устройствами, видит реальные показатели; ресурсы измерены на 1 GiB.

### Этап 4. Регистрация, подписки, bootstrap и переход на managed

**Сделать:** user-token, device credential, ETag/revisions, enrollment, per-device config, QR/bootstrap, внутренний VPN API, логика применения/отката, устройство привязывается к единой подписке пользователя. Подготовить один reference client mock для контрактных тестов.

**Приёмка:** обычная регистрация по user URL; когда внешний HTTPS закрыт, индивидуальный bootstrap подключается через VK TURN, загружает новую подписку изнутри VPN, автоматически становится managed; при сбое обновления VPN остаётся в рабочем состоянии. Прямой доступ к прочим службам VPS с VPN по-прежнему закрыт.

### Этап 5. Android FreeTurn

**Сделать:** реальная интеграция enrollment/bootstrap/updates, Connection Manager Direct ↔ VK Relay, корректные маршруты, UI, хранение секретов, сборка APK, миграция профилей.

**Приёмка:** 1-click connect, fallback с Direct на VK, обновление без повторного импорта, перезапуск/смена сети/обрыв, нет loop/DNS leak, старые функции не деградируют.

### Этап 6. Windows FreeTurn Desktop

**Применение настроек, уточнение17.11.2026:** сохранение выбранного ordinary profile должно сохранять выбор и передавать новую запись в следующий Connect. При непустом каталоге без active selection запрещено молча использовать прежний SYSTEM profile. Во время async editor validation исходный share перепроверяется, новые ключи/параметры другой операции не перезаписываются. Global auto/manual CAPTCHA сохраняется и передаётся core; manual profile имеет приоритет. UI различает saved/requested/effective/ready streams (auto Direct использует1, Relay — profile n), показывает необходимость reconnect, различает FreeTurn control DNS и WG DNS. Диагностика effective params — только whitelist чисел/enums/flags, без private/CID/VK/token/конфигов. В0.18 код реализован, native Save/actual Go renderer checks PASS; live VPN/CAPTCHA E2E NOT RUN. [Аудит0.18](WINDOWS_SETTINGS_PLAN.md).

**Сделать:** ревизия форка/спайк Windows туннеля, UI, Windows Service, сетевой драйвер, WireGuard туннель, Direct/Relay и bootstrap/managed, подписки, русский интерфейс, установщик и деинсталлятор.

**Сокращение Windows scope по решению пользователя17.11.2026:** исключить из обязательной разработки и приёмки hotspot/раздачу VPN через LAN, UDP/IPv6-расширение SOCKS, измеритель задержки, дополнительные языки и полный перенос дополнительных Android-настроек. Уже работающие функции сохраняются; защита секретов, безопасные настройки подключения, маршрутизация локальной сети и отсутствие утечек остаются обязательными. Установка/проверка/обновление VPS, администраторский список пользователей/устройств, выдача и отзыв доступов выполняются через веб-dashboard; переносить эти административные операции в Windows-клиент не требуется. Локальный каталог профилей, импорт своей подписки и получение обновлений остаются клиентскими функциями. Установщик/обновление самого Windows-приложения сохраняются в объёме. Это уточнение имеет приоритет над прежним требованием полного паритета Android и историческими матрицами переноса; требования к Android этим не меняются.

**Уточнение пользователя16.11.2026:** QR-генерация, импорт QR-изображений и камера исключены из Windows scope и приёмки. Используются текстовая `freeturn://` ссылка, файл, буфер обмена и зашифрованная резервная копия. Телефонные и серверные требования к QR этим не отменяются. Дизайн Windows должен сохранять композицию исходного Android FreeTurn: вертикальное окно, пять нижних вкладок с исходными иконками, expressive-кнопка/статус/статистика и блок сервера, четыре категории настроек, единые формы/палитра/типографика. Платформенные различия описывать отдельно; похожий UI не закрывает неперенесённый backend. Текущая реализация и остаток — [WINDOWS_DESIGN_PARITY.md](history/windows/WINDOWS_DESIGN_PARITY.md).

**Desktop flow, уточнение16.11.2026:** сохранить компактное вертикальное окно и нижние вкладки. Обычное подключение не требует поиска кнопки обновления службы: проверить ядро, при необходимости выполнить guarded setup с UAC, заново подтвердить authenticated IPC/версию и продолжить исходное подключение. При отмене/ошибке/несовместимости подключение не начинать; актуальное ядро не переустанавливать, более новое не понижать, активный tunnel не обновлять. Фоновый retry не вызывает UAC. Профиль импортируется/выбирается локально и применяется при подключении, без изменения ключей. Серверы, редактор, SSH, SOCKS, routing, backup и CAPTCHA открываются внутри общего окна с возвратом; file pickers, UAC и подтверждения остаются системными. Блокировать уход во время сохранения. Новые релизы из интернета — отдельный подписанный updater, не этот сценарий. Состояние: [WINDOWS_DESKTOP_FLOW.md](history/windows/WINDOWS_DESKTOP_FLOW.md).

**Последующее уточнение16.11.2026, имеет приоритет для будущего дизайна:** пользователь подтвердил работающий VPN0.8 и разрешил полностью изменить расположение элементов/навигацию; прежняя обязательная portrait/bottom composition больше не ограничивает следующий редизайн. Сначала пользователь подбирает примеры. Нужны полноценная EXE/window/tray иконка, понятные состояния без самопроизвольного выхода, подробный журнал ядра по аналогии с исходным FreeTurn (уровни/потоки/поиск/export без секретов), отзывчивый UI без двухсекундных скачков. Быстродействие транспорта улучшать по измерениям, а не обещаниям. Запрос закрытия без явного действия не должен предлагать остановить соединение. Ближайшая очередь и проверки — [WINDOWS_POLISH_PLAN.md](WINDOWS_POLISH_PLAN.md).

**Приёмка:** реальная передача трафика **всей системы**, не только браузера; Android+Windows одновременно с разными peer keys; sleep/resume/reconnect, удаление маршрутов при uninstall; сборка EXE/MSI и тест чистого Windows 10/11 x64.

### Этап 7. Оптимизация, безопасность и отказоустойчивость

**Сделать:** CPUQuota tuning с измерениями, mem/RAM target, бенчмарки Direct/Relay, keepalive/MTU, throughput+RTT, многоклиентность, аудит API, отсутствие секретов в логах, тесты возврата/бэкапа, совместимость Anton48, проверка реальных телефонов и операторов.

**Приёмка:** отчёт с таблицей измерений и условиями, ни один критический тест не пропущен; нет OOM/repeated reconnect; трассы и маршруты очищаются при удалении; контроль отказов VK и VPS не обещает невозможного.

### Этап 8. Финальная установка одной командой и релиз

**Сделать:** release artifacts CI, контроль подписи/хеша, установщик root bootstrap на Ubuntu 24.04, install/upgrade/repair/migrate/uninstall/restore, документация с примерами и скриншотами, release APK/Windows installer.

**Приёмка:** на **чистом VPS 1 vCPU/1 GiB** ОДНА команда установила сервер+SQLite+панель+сайт+подписки; `ftm doctor` прошёл; Android/Windows работают; iPhone Anton48 импортирует ручной профиль; повторная установка идемпотентна; rollback tested. Команда задокументирована и реально протестирована, не псевдокоманда.

## 15. Обязательное правило работы Codex

1. Перед стартом прочитать оригинальные репозитории и реально проверить их файлы/доступность, версии и лицензии. Если сеть недоступна, честно отметить блокер и не выдумывать исходники.
2. Составить в репозитории `docs/IMPLEMENTATION_PLAN.md` и `docs/DECISIONS.md` с конкретными решениями/версиями, допущениями и рисками. Поддерживать `docs/PROGRESS.md`.
3. Выполнять **строго последовательно** этапы 1→8; внутри каждого писать рабочий код, тесты, фиксировать изменения. Для проблем с высокой неопределённостью выполнять короткий spike перед полномасштабной разработкой.
4. Не давать декоративный макет вместо реального API; не заявлять UI/подписку/Windows VPN рабочими, пока нет E2E.
5. Команда не может подключаться к реальному VPS без явных параметров доступа и согласованного deploy: разработка в локальной среде; destructive действия на боевой машине только после бэкапа и команды пользователя.
6. После этапа публиковать отчёт: изменённые файлы, команды проверки, тесты PASS/FAIL, ресурсные показатели, проблемы, rollback, следующий этап.
7. Если инфраструктурное ограничение препятствует выполнению (нет Windows runner/Android SDK/VPS/сертификата), завершить доступные части этапа с тестами и чётко пометить неподтверждённые пункты, не выдавать mock за release.
8. Приоритет при спорных решениях: **(1) сохранность существующего VPN и Anton48, (2) корректное E2E, (3) лёгкость на 1 GiB, (4) скорость, (5) красивый UI**. При этом интерфейс должен быть завершённым, не прототипом.

## 16. Матрица обязательных acceptance tests

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| T01 | Fresh Ubuntu 24.04 1 vCPU/1 GiB, one command | Появляется интерактивный мастер; с доменом запускаются сервер и доверенный TLS, сайт/панель/API, без Docker и Node runtime |
| T02 | Повтор install | Сохранены все пользователи/ключи/пиры; нет лишних правил |
| T03 | Миграция с существующего `NimmWee/Vps` | iPhone Anton48 и прежний Android не теряют доступ |
| T04 | Одна user URL на телефон/ноутбук/планшет | 3 разные ключа, IP, CID; все подключаются одновременно |
| T05 | Конкурентный enroll 10 устройств | Нет дубликатов IP/CID; идемпотентность |
| T06 | Отзыв одного устройства | Только это устройство потеряло доступ |
| T07 | Прямой путь работает | FreeTurn Direct выбран/работает, handshake и трафик подтверждены |
| T08 | Direct недоступен, VK relay доступен | Auto fallback без вмешательства человека |
| T09 | Relay перестал работать | Backoff, понятная ошибка, без бесконечного CPU loop |
| T10 | Внешний IP HTTPS заблокирован, bootstrap рабочий | Подключение через VK → внутренний API → managed без ручного импорта |
| T11 | Подписка обновлена | Клиент видит новую ревизию, применяет безопасно или откатывает |
| T12 | Ошибка новой конфигурации | Последний исправный профиль сохранён |
| T13 | `/` на домене | Заглушка, а не панель/список сервисов |
| T14 | Случайный admin path без авторизации | Нет данных, полноценная auth и audit работают |
| T15 | VPN-клиент пытается обратиться к внутренним службам VPS | Разрешён только согласованный HTTPS API, остальное блокируется |
| T16 | 1 ГБ RAM стресс/idle | Ресурсы измерены; не OOM; пределы указаны |
| T17 | Speed matrix | Отчёт Direct/VK, 1/2/5/10 устройств и CPU нагрузка |
| T18 | Обрыв Wi-Fi и Windows sleep | Возобновление по выбранной политике; без DNS/IPv6 leak |
| T19 | Backup/restore на чистой тестовой машине | Сохранены ключи/пиры/SQLite/панель |
| T20 | Caddy TLS renewal и reboot | Сертификат валиден, службы стартуют после перезагрузки |
| T21 | Windows uninstall | Удалены собственные службы/маршруты/адаптер, интернет работает |
| T22 | iOS Anton48 вручную | Поддерживаемый профиль импортируется и передаёт трафик |
| T23 | Wizard: свой домен, DNS A корректен | Caddy валидный TLS, `/` заглушка, случайный URL панели, подписка, без обязательного `--domain` |
| T24 | Wizard: IP without domain | Разрешён защищённый вариант с доверенным IP TLS либо VPN/SSH-only; нет публичного HTTP/admin с отключённой TLS-проверкой |
| T25 | Wizard: некорректный DNS/закрытый 80/443 | Понятная ошибка, retry/switch/cancel, старый VPN и SSH сохранены; false success нет |
| T26 | Reconfigure IP ↔ domain через `ftm config web` | Нет потери пользователей, ключей и VPN; предупреждение о смене URL и безопасная миграция подписок |
| T27 | `--non-interactive --config` на тестовой чистой VM | Воспроизводимая установка/repair, секреты не попадают в аргументы/логи, проверены повторный запуск и rollback |
| T28 | Android/Windows VK auth и повторные CAPTCHA | Переиспользована штатная автоматика FreeTurn; manual fallback и загрузка ресурсов, нет дублей одного challenge, корректные TTL/изоляция/cancel/backoff; реальный VPN-трафик. Calls-first — отдельный кандидат к проработке (§5.1), обязательного переноса solver нет; FTM implementation/E2E NOT RUN |
| T29 | Domain routing и администраторские исключения | RU/LAN/custom DIRECT через физический канал, YouTube/push/custom VPN через VPS; приоритеты/shared IP, protected management и actual applied revision проверены на Android/Windows |
| T30 | Split DNS при routing policy, смене сети и сбоях | Resolver/путь согласованы с domain policy, корректны CNAME/TTL/A/AAAA; нет скрытого direct DNS/VPN fallback, IPv6 leaks и маршрутной петли |
| T31 | BitTorrent blocking | Реальное enforcement в заявленном scope, DHT/смена порта и отсутствие DIRECT обхода; обычные HTTPS/QUIC работают, unsupported client не получает ложный статус «применено» |

## 17. Что вне проекта

- Разработка iOS-приложения, Apple signing/TestFlight/App Store.
- 3X-UI_KIT, Xray/VLESS, Hysteria2, TUIC, Clash/VMess/Trojan и их подписки.
- Второй оплачиваемый VPS, облачный managed Postgres, Redis, Docker/Kubernetes.
- Свой TURN relay, заменяющий VK.
- Гарантия доступа при полной недоступности VPS/VK; гарантия 1 Гбит/с через TURN.
- Непроверенное «автоматическое» обновление старого чужого клиента Anton48.

## 18. Ссылки для технической верификации

- NimmWee: https://github.com/NimmWee/Vps/blob/main/README.md и https://raw.githubusercontent.com/NimmWee/Vps/main/src/vps_vk.py
- FreeTurn core Direct/Relay: https://raw.githubusercontent.com/hackdiaz-dev/free-turn-proxy/master/docs/modes.md
- FreeTurn core sub.md: https://raw.githubusercontent.com/hackdiaz-dev/free-turn-proxy/master/docs/sub.md
- FreeTurn Android: https://github.com/hackdiaz-dev/turn-proxy-android
- FreeTurn Desktop proof-of-concept: https://github.com/l1ch666/turn-proxy-android
- iPhone Anton48: https://github.com/anton48/vk-turn-proxy-ios
- 3X-UI_KIT, только идея маршрутизации сайта: https://raw.githubusercontent.com/itsnotkubrick/3X-UI_KIT/main/scripts/3x-ui.sh (см. `panel_path=$(rand_str 18)`, `location $panel_path`, `location $SUB_PATH`, `location / { root /var/www/kit; }`).
