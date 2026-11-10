# Клиентский API v1

10.11.2026, продолжение по новому поручению пользователя после ночного окна. Runtime использует тот же root-owned SQLite и Unix boundary. Общий installer остаётся dry-run. Android/Windows client E2E этим не подтверждается.

## HTTPS и роли

`/api/client/v1/enroll` — POST, Authorization Bearer **user token**. Body: name/platform/public_key/client_id/device_token_hash/request_id, строго без private_key/plaintext device token/unknown fields. Одна atomic transaction, idempotency и device limit из предыдущего enrollment core. Возвращает200 для уже active retry либо202/pending. Применение выполняет периодический root worker.

`/api/client/v1/status` — GET под **device token**, ready/state/revision без секретов. `/api/client/v1/subscription` — GET под тем же device token:202 без конфигурации до active,200 с индивидуальным manifest либо304 с пустым body при совпавшем ETag. Любой conditional request сначала проходит token/disable/rotation и root ownership/spec checks. Смена user URL не меняет конфигурации существующих устройств. Revision сейчас относится к device state; ETag покрывает всё содержимое, включая server transport settings.

Admin cookie не авторизует client routes. Tokens принимаются только через Authorization, не query/body/URL. Caddy проксирует только три явных HTTPS paths; private web mode закрывает их. API остаётся127.0.0.1. Нет открытого CORS, access logs выключены, request object удаляется из Caddy error logs. Ошибки содержат RU message/code/случайный correlation_id, но не input. HTTP body ограничен16KiB.

Bounded rolling budgets60s: global300, IP120, credential30; enrollment дополнительно10/IP и10/user credential. В памяти только token hashes, max2048 buckets;4 concurrent RPC делят semaphore с admin API.429/503 имеют Retry-After. Это ограничение ресурсов, не измерение устойчивости под внешним DDoS.

## Managed manifest

Отдельный `ftm-managed` schema_version1, не неизвестные поля внутри native freeturn share. JSON Schema `schemas/managed-device-v1.schema.json`; enrollment schema экспортирован из actual Pydantic model в `schemas/client-enrollment-v1.schema.json`.

Manifest содержит только своё устройство, public key, адреса, собственный PSK/CID и необходимые общие VK/obf transport параметры. Server/client WG private keys, admin password, user/device tokens не возвращаются. Для active device metadata недостаточно: проверяется root registry phase/enabled/spec. Обычные admin lists по-прежнему redacted.

`ftm.managed_profile` проверяет contract/key/origin/размер и собирает существующий freeturn v1 share с **локальным** private key. Caller обязан предоставить пару WG keys, созданную нативным backend. Политика IPv6 явно block; реальный клиент должен обеспечить её на уровне ОС. Нативные DNS/IPv6 leak tests NOT RUN.

`management.internal_api_ip` используется при явном выборе internal transport; узкий firewall и TLS override проверены следующим блоком: [INTERNAL_HTTPS.md](INTERNAL_HTTPS.md). Публичный HTTPS origin остаётся TLS identity и адресом первой регистрации. VK credential lifetime/CAPTCHA по-прежнему могут требовать ручного действия; Direct/Auto здесь не реализован.

## Что проверено

Root report `/root/ftm-client-api-report.json`: настоящий HTTPS reference caller зарегистрировал два synthetic устройства, повторил запрос, дождался periodic apply и **четырёх kernel peers** (два исходных плюс два тестовых). Устройства получили разные адреса/PSK/CID, собственные manifests; private key появился только при локальной сборке share. Повторный refresh304, user-link rotation не изменила ETag. После revoke запрос со старым ETag получил403; другой device сохранил304. Настоящий admin cookie не дал доступ к client config. В API/control/Caddy journal тестовых private values не обнаружено.

Тестовые devices/user отключены, снова2 исходных peers. Hashes state/WG/CID/obf/registry/iPhone и PID VPN/SSH совпали с pre-deploy. API/control/Caddy перезапускались для кода/маршрутов, VPN/SSH не перезапускались. Внешний trusted HTTPS request с рабочего ПК без токена401.

Windows113 tests108PASS/5skips; WSL113 tests107PASS/6web dependency skips, baseline8 и binary smoke PASS. Добавлено7 целевых security/last-good cases; обычные wiring/route изменения проверены реальным сценарием.

Установленный runtime: `30e093b4aaeb5af8`. После cleanup сделана новая encrypted копия `/root/ftm-managed-65d18c0086.vpnbackup`, скачана вне Git как `manager-client-api.vpnbackup`. SHA256 `f44e944ae3e6af71a40a8158967daf49cddec8f4e40c9c9872df3b0b95127fe8`. Независимый decrypt/stage в WSL PASS: v2,12 metadata devices,2 owned peers, web settings включены. Это проверка данных восстановления, не новый live restore и не clean-host recovery.

`ftm.reference_client` — явно **контрактный caller**, без адаптера VPN и без native secure storage. HTTPS certificate validation включена, redirects запрещены. LKG/ETag обновляются только после полного validate и local share assembly; malformed update/сбой сохраняет последнюю конфигурацию,401/403 помечает REVOKED. Сохранение LKG в памяти не является доказательством непрерывности VPN-трафика.

Internal TLS override/firewall и [bootstrap/claim](BOOTSTRAP.md) уже проверены. Далее native applications. UI выпуска подписок/экспорта ещё требует re-auth и пока не добавлен.
