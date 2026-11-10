# Персональный стартовый профиль и активация

10.11.2026. Серверный bootstrap/claim установлен и проверен на согласованном тестовом VPS. Следующим блоком добавлена [выдача из панели](ADMIN_EXPORT.md). Интеграция нового envelope в нативные Android/Windows приложения остаётся отдельной работой.

## Выдача

Root-only `python3 -m ftm.bootstrap_cli --user-id UUID --name NAME --platform android --output /root/PRIVATE/new-bootstrap.json` создаёт новый персональный peer и `ftm-bootstrap` v1 artifact. Нужны enabled user и действующая subscription identity (её root выпуск описан в STAGE4_PROGRESS). `PRIVATE` — существующий root700 каталог; файл должен быть новым, получает0600. CLI печатает только device_id/state/expiry. Общий Manager install/apply не включается.

На установленном стенде выполнять module command из `/opt/ftm/current`; Python package глобально в system site-packages не устанавливался.

WG private key генерируется wg tools только для этого устройства. В SQLite находятся public key, PSK/CID и SHA256 nonce; WG private key и plaintext nonce в БД не записываются. В private artifact — готовый native freeturn share и отдельные поля management/одноразового claim. Не добавлять nonce в upstream freeturn JSON. Схемы: `schemas/bootstrap-profile-v1.schema.json`, `schemas/bootstrap-claim-v1.schema.json`.

Файл и его родитель fsync до commit. Ошибка delivery откатывает peer metadata, IP allocation, nonce и audit; CLI удаляет неудавшийся новый файл. Reconciler применяет pending peer отдельно. Выдача без применения сети не доказывает готовность подключения: дождаться active через management status. Автоматического повторного экспорта private key из БД нет — его там нет; при утрате артефакта отключить устройство и явно выдать новое. Не отправлять файл в Git/логи/общий каталог.

## Claim

`POST /api/client/v1/bootstrap/claim`, Authorization Bearer `ftmb1_…`, body только device_id/device_token_hash. Device token генерирует клиент и сохраняет у себя до отправки; сервер получает domain-separated hash. Root проверяет фактический IP через доверенный loopback Caddy/Unix IPC, точное совпадение с WG address своего устройства, enabled user/device, действующую subscription, active registry/spec и срок nonce.

BEGIN IMMEDIATE атомарно создаёт один credential и потребляет nonce. Потеря ответа допускает retry с тем же ещё активным hash в пределах TTL; другой hash/отозванный token не переиздаётся. WG keys, CID, PSK и профиль не меняются. Далее `/subscription` возвращает managed manifest и ETag. Reference caller имеет `claim_bootstrap`; он не создаёт VPN адаптер и не заменяет native secure storage.

По умолчанию TTL1час, `--ttl-seconds` допускает60–86400. **TTL относится к активации управления, а не к сроку жизни VPN peer.** Чтобы отключить VPN, отключить device/user. Disable истекает unused nonce фиксированной датой1970, поэтому enable и откат системных часов не оживляют его. User URL rotation сохраняет identity; revoke URL блокирует незавершённый claim, сохраняя WG peer. Старый backup возвращает сохранённое в нём состояние авторизации — это общее свойство restore, не механизм безусловного сохранения последующих отзывов.

Ошибки410 истёк/использован,403 неправильный source/disabled,401 credential/subscription,422 форма,429 лимит,503 pending/agent. Code/RU message/correlation без echo nonce/input. Claim получает тот же bounded budget10/IP/credential и общие global/IP/concurrency limits. Cookie не заменяет nonce. Source IP не принимается из body или произвольного forwarded header.

## Реальные проверки

`/root/ftm-bootstrap-report.json`: private offline issue → настоящий synthetic WG peer → отдельный namespace с **единственным маршрутом к internal API** → trusted TLS claim/retry → managed200/304. Публичный443 для положительного сценария не использовался. Запрос с VPS через публичный HTTPS origin с поддельным X-Forwarded-For получил403: это проверка public endpoint, не отдельная внешняя сеть. Отозванный credential нельзя восстановить потреблённым nonce (410). Config/CID/WG/registry hashes при claim совпали.

Cleanup отключил временное устройство/пользователя и удалил namespace/private test artifacts. Снова2 исходных peers; baseline state/WG/CID/obf/registry/iPhone hashes и PID VPN/SSH сохранены. Control/API/Caddy перезапускались для нового кода/маршрута; VPN/SSH не перезапускались. В service journals тестовых nonce/private keys/token/CID/VK/obf не обнаружено.

Windows121 tests116PASS/5skips; WSL121 tests114PASS/7web dependency skips, исходные8 и binary smoke PASS. Добавлено5 целевых bootstrap checks: delivery rollback, source/expiry/replay, disable/enable, competing claims, HTTP source boundary. Проверка disable выявила зависимость от отката wall clock — nonce теперь истекает без возможности восстановления при сдвиге часов назад.

Offsite `/root/ftm-managed-05ae079d39.vpnbackup` → приватный локальный `manager-bootstrap.vpnbackup`; SHA256 `4b64466240084712c056627192bc67d8c033c2d4e2a8559c97e992bf0cb16c17`. WSL decrypt/stage PASS:15 metadata devices,2 owned peers,web v2. Персональные bootstrap private artifacts не добавляются в серверный checkpoint: их надо сохранять отдельно в доверенном клиентском хранилище. Новый live restore/reboot в этом блоке не выполнялся; предыдущие same-host restore/rollback остаются отдельно подтверждёнными результатами.

Финальный runtime с обеими JSON Schema: `671bdabd340bf011` (первый functional proof — `c1f678eee019424b`, код поведения тот же). Offsite snapshot после упаковки совпал с live; root0600 SQLite, собственное internal правило и все8 служб healthy.

Namespace использует host-loopback WG underlay и обходит TURN. T10 с VK и настоящим Android/Windows при заблокированном внешнем443 **NOT RUN**. iPhone profile не менялся; новый physical iPhone E2E NOT RUN. [Admin re-auth/выдача из панели](ADMIN_EXPORT.md) добавлены следующим блоком; далее native integration и безопасное применение обновлений.
