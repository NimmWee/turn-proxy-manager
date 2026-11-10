# Панель по HTTPS: результат

10.11.2026, отдельный тестовый VPS. Доверенный Let’s Encrypt IP TLS и публичная панель работают; rootless API по-прежнему слушает только 127.0.0.1:8080.

Web config v2 хранит canonical HTTPS origin и требует Secure cookie. Private v1 поддерживается для восстановления старых копий. Проверяются фиксированный Origin, HTTPS scheme, Host allowlist, CSRF и HttpOnly/SameSite=Strict. Forwarded headers принимаются Uvicorn только от loopback Caddy. Public HTTP не обслуживает login, Caddy перенаправляет на HTTPS. Чужие пути показывают нейтральную страницу, secret panel prefix проксируется только через TLS. Request object удалён из error logs, access log и admin interface Caddy выключены.

## Реально проверено

- Root-only enable с matching offsite checkpoint и trusted certificate. Injected post-write readiness failure восстановил private config, login note и нейтральный edge. Повтор enable не перезапускает API. При enable **VPN и SSH не перезапускались**, рабочий профиль не менялся. `/root/ftm-https-enable-report.json`.
- Настоящий HTTPS login/logout, Secure/HttpOnly/Strict flags, unauthorized 401, запрет HTTP/foreign Origin и отсутствующего CSRF. В сервисных журналах plaintext password и secret panel path не обнаружены.
- Браузер на рабочем ПК без TLS bypass: вход, создание «Проверка HTTPS», отключение этого пользователя и настоящие метрики. Desktop1440×1000 и mobile390×844, secure context, без overflow и JS errors. Снимки `logs/panel-https-desktop.png`, `logs/panel-https-mobile.png` (ignored). Это эмуляция браузера, не физический iPhone E2E.
- **Actual restore public → private** убрал публичный proxy, API path возвращал только заглушку. Инъекция ошибки restore в public вернула полный private snapshot. Финальный restore вернул public snapshot, trusted TLS и auth boundary. Caddy config регенерировался доверенным кодом, не загружался из архива. `/root/ftm-https-recovery-report.json`.
- Во время явного restore FreeTurn/API/Caddy перезапускались; SSH и iPhone profile сохранились. Это maintenance, его нельзя смешивать с hot enable/CRUD.
- Свежий SSH вход PASS; Fail2ban maxretry3/bantime31536000, root SQLite UID0 mode0600. Семь служб active, FreeTurn CPUQuota прежний50%. Наблюдавшиеся API33MiB/control11MiB/Caddy11MiB — не нагрузочный benchmark.
- Windows venv95 tests:90PASS/5skips. WSL95:92PASS/3web dependency skips, baseline8 и binary smoke PASS. Добавлены три целевых security/restore cases, без тестов каждого метода/компонента.

## Backup и доступ

Offsite-verified checkpoint v2 `/root/ftm-managed-289a6f6872.vpnbackup`, SHA256 **3ba1222f4c62491857a8762f24edf044489ed1989f2cb26dbf44a24cb1648593**. Private offsite `manager-public-https.vpnbackup` реально расшифрован/staged в WSL: 8 metadata devices, 2 owned peers, web config v2. Финальный live snapshot совпал с архивом после восстановления.

Same-host restore регенерирует edge из web settings и provisioned IP/cert identity. ACME account/cache и certificate key **не входят** в checkpoint; clean-host/IP/domain migration и общий installer ещё впереди. Следующее фактическое продление сертификата NOT RUN.

Адрес и пароль только в `/root/ftm-web-login.json` и приватном локальном `panel-login.json`; в Git отсутствуют. Runtime `b41b929edcd1f2c4`. Следующий серверный этап — subscription tokens, device credentials и enrollment; подписки/новые APK/Windows ещё не реализованы.
