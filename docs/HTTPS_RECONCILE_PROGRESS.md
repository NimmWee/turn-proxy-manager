# Доверенный TLS и фоновое восстановление операций

10.11.2026, отдельный согласованный тестовый VPS. Production и GitHub не затронуты.

## HTTPS

Установлен официальный Caddy 2.11.9 linux/amd64 с SHA512 pin в `caddy.lock.json`. Под отдельным `ftm-caddy`, только CAP_NET_BIND_SERVICE, root-owned binary/config и read-only systemd credential. Данные ACME/certificates находятся в отдельном private StateDirectory. Node и дополнительные базы на сервер не устанавливались.

Получен настоящий **Let’s Encrypt IP certificate**, profile shortlived, issuer YE1, срок текущего сертификата до **16.11.2026 15:08:12 UTC**. Python TLS client проверил публичную chain и IP SAN; HTTPS 200 проверен с VPS и с рабочего ПК без отключения проверки сертификатов. Продление выполняет Caddy, фактическая следующая выдача NOT RUN — срок ещё не наступил.

Публично доступна **только нейтральная страница**, без API и login. Панель пока остаётся по SSH forwarding. Global error log удаляет весь request object, access log не включён; случайный panel path и cookies в Caddy config пока отсутствуют. Admin API Caddy выключен. Перед публичной панелью нужны HTTPS Origin/Host, Secure cookie и согласованный restore edge settings.

Добавлены только собственные accept TCP 80/443 на существующем uplink. Firewall oneshot восстанавливает эти правила при старте HTTPS; чужие правила, backend port, SSH и VPN не меняются. Repeat hook, repeat install, `systemd-analyze verify` и **реальный injected post-start rollback** PASS. После инъекции вернулись прежние конфиги и trusted HTTPS. Caddy UID не читает root SQLite, registry или obf key. Профили/config и MainPID VPN/SSH/API неизменны. Наблюдавшийся MemoryCurrent Caddy около 14 MiB, не нагрузочная гарантия. Дополнительный reboot ради этого шага не выполнялся.

Root report: `/root/ftm-https-probe-report.json`; воспроизводимый сценарий `scripts/verify_https_probe.py` требует явный `--test-vps-apply` и matching offsite checkpoint.

## Постоянный reconcile

В существующем root `ftm-control` worker каждые 30 секунд повторяются durable pending/applying/error операции. Новых endpoints, потоков или прав API нет. Тот же nonblocking lifecycle lock исключает применение во время backup/restore/startup; при busy отложить на пять секунд. Ошибки увеличивают интервал до 60/120/240/300 секунд, успех возвращает 30 секунд. Логи содержат только aggregate counts; исключения и DB rows не печатаются.

На настоящем WG без inline RPC apply проверены pending add, maintenance lock и быстрый unavailable, восстановление прерванного `applying` revoke, отмена устаревшего enable. Synthetic device в конце revoked, user disabled. Остались **два исходных peers**. Config/registry/obf/iPhone profile и MainPID VPN/SSH побайтно/по значениям совпали с исходными. Root report `/root/ftm-reconcile-report.json`; сценарий `scripts/verify_reconcile_loop.py`.

Три целевых retry/security tests и существующие control boundary tests PASS. Windows venv: 92 tests, 87 PASS / 5 skips. WSL native filesystem: 92 tests, 90 PASS / 2 skips web dependencies; baseline 8 tests и binary smoke PASS. Это не физические Android/iPhone/Windows E2E.

## Актуальная копия

После synthetic проверки создан checkpoint v2 `/root/ftm-managed-a4bde6d716.vpnbackup`. SHA256 **332a8c0827382231927cf90564638c85d0ddfc3e43712ec8f54bf6be0f3bc6a1**. Private offsite `manager-with-reconcile.vpnbackup` реально расшифрован и staged в WSL: 8 metadata devices, 2 owned active peers, web settings включены. Секреты и пароль в репозиторий не перенесены.

Копия ещё не включает ACME cache и HTTPS service settings: текущий probe не меняет VPN/web identity. Для полного clean-host восстановления HTTPS нужен следующий installer milestone. Последний установленный runtime на этом шаге: `4bbbbe94efe9e7a5`.
