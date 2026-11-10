# Передача после ночной работы

10.11.2026. Ночное разрешение действует до **08:20 Asia/Tomsk /01:20 UTC**. После этого времени разработку продолжать только по новому поручению. Работа одним агентом, без GitHub push и без обращения к production.

## Что готово на тестовом VPS

- Managed startup, совместимый CLI и restricted root control service; SQLite остаётся root600. Durable operations повторяются автоматически, maintenance lock и error backoff проверены.
- Русская HTTPS панель: вход/logout/CSRF, пользователи, устройства, настоящие показатели и журнал изменений с поиском. Light/dark и desktop/mobile browser проверены. API только127.0.0.1, Caddy с настоящим Let’s Encrypt IP certificate.
- Encrypted managed checkpoint с web identity/HTTPS origin. Actual same-host restore, injected rollback и private/public edge transitions проверены; offsite decode/stage выполнен вне VPS.
- Hash-only user/device credential lifecycle и atomic enrollment **core**. Client-held private key/CID/token, concurrent retry/limit/collision/revoke checks, настоящий synthetic WG peer через periodic worker. Публичного client enrollment/config пока нет.
- Share codec/JSON Schema, pins Go/Android parsers; три профиля прошли настоящий Go Parse/String. Android source verified, Kotlin runtime NOT RUN.
- `ftm status` и `ftm doctor` реально проверены; читают службы/права/socket/loopback/TLS без применения изменений.

## Последняя системная проверка

Перед финальным reboot выполнен **actual restore последнего offsite checkpoint** и health check. После reboot подтверждены новый boot_id, свежий SSH с прежним host key, автоматический запуск **SSH/Fail2ban/VPN/network/control/API/Caddy/firewall hook**, настоящий HTTPS login/events/logout. Никакие службы после boot вручную не запускались.

Текущий snapshot совпал с offsite, kernel WG server public key и peer PSK совпали, iPhone import не изменился. Root DB/registry права и API loopback сохранены, активны два исходных peers, pending/missing/unknown0. SSH:3 ошибки/600 секунд →31536000 секунд, DB retention31622400. Первый диагностический assert ожидал plain number вместо pretty text dbpurgeage; исправлен только разбор результата проверки, серверная настройка не менялась.

Root report `/root/ftm-fullstack-reboot-report.json`, private local `fullstack-reboot-report.json`. **Это server autostart/restore proof, не новый физический iPhone/Android/Windows E2E.**

Runtime **4c3d096c037baa98**. Последний ciphertext `/root/ftm-managed-e3336b9bbf.vpnbackup`, SHA256 **dab56a048c677b26e80f487e58824dfbc5f01978efe5628b7f91efd5fd2cf0ca**. Private offsite `manager-enrollment.vpnbackup`:10 metadata devices,2 active peers, public web settings. Остальные устройства/пользователи — отключённая история synthetic проверок.

## Где доступ и доказательства

Локальный закрытый каталог `Downloads/FreeTurn-Test-2026-11-10`: `Панель.txt` и `panel-login.json` содержат адрес/логин/пароль панели; `iPhone-import.txt`/QR — сохранённый рабочий профиль; `backup-recovery.pass` — recovery phrase; ciphertext и отчёты лежат рядом. Секреты в Git не переносились. Браузерные проверочные сессии завершены/logout, старый SSH forward закрыт.

Финальный локальный прогон106 tests:101PASS/5POSIX/OpenSSL skips; WSL106:103PASS/3web dependency skips. После read-only UI изменений дополнительно6 existing boundary cases, production build и реальный browser/API; operator CLI11 cases9PASS/2POSIX skips и реальные status/doctor. Baseline23 files/package verifier PASS. Финальная проверка153 tracked files на секреты из private artifacts дала0 совпадений. Working tree чистый, browser/SSH helpers и forward закрыты; после reboot свежий SSH вход PASS.

Подробные результаты: `PUBLIC_HTTPS_PROGRESS.md`, `HTTPS_RECONCILE_PROGRESS.md`, `STAGE4_PROGRESS.md`, `PROFILE_CONTRACT.md`, `ENROLLMENT_PROGRESS.md`, `EVENTS_PROGRESS.md`, `OPERATIONS.md`.

## Следующая работа

1. Typed client IPC/HTTP auth+throttling, pending/status для client-held credential, per-device config/revision/ETag и отдельный managed envelope. Не добавлять неизвестные поля в upstream share JSON. Admin export только с re-auth.
2. Узкий HTTPS allowlist из VPN, TLS identity/address override и bootstrap TTL/one-time claim/managed transition. Не открывать backend51830.
3. Остальные вкладки MVP: подписки, VPN/транспорт, мониторинг с реальной persistent history, настройки. Сейчас не изображать их готовыми.
4. Реальные Android/Windows клиенты, Direct/Auto, три одновременных устройства, DNS/IPv6 и нагрузка — NOT RUN. Физический iPhone после финального reboot тоже ждёт пользовательской проверки.
5. Clean-host/IP/domain migration и полный installer ещё не готовы. Checkpoint не архивирует ACME account/cache/cert private key; текущий same-host restore регенерирует edge из данных на provisioned host. Следующее фактическое продление сертификата NOT RUN.

Не запускать legacy baseline reinstall поверх managed peers. Не менять root SQLite ownership ради API. Сохранять ключи/профили и текущие Root boundaries; production и GitHub push по-прежнему вне разрешения.
