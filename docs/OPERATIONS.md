# Проверить установленный стенд

Команды выполняются **на установленном тестовом VPS**. Общий installer Manager ещё dry-run; эти команды не устанавливают проект на другой сервер.

```bash
ftm status
ftm doctor
```

`status` читает состояние через ограниченный Unix IPC: службы VPN/Fail2ban, число ожидаемых/фактических/неизвестных peers и согласованность. Возвращает code0 при consistent, code2 при проблеме/недоступном IPC. Ключи, CID и URL панели не показывает.

`doctor` от root дополнительно проверяет API/control/Caddy, root600 SQLite, root700 каталоги, ownership/mode socket, фактический loopback listener8080 через `/proc/net/tcp*` и trusted TLS chain/IP SAN текущего IP-режима. JSON `healthy` относится к этим проверкам, **не к приёмке всего ТЗ/клиентскому E2E**. Команда ничего не чинит: не создаёт БД, не запускает reconcile, install, apt, firewall или restart. TLS проверка — обычное чтение сертификата.

На Windows команды объясняют, что нужен установленный Linux-сервер, и возвращают2. Проверены существующие CLI cases(11,9PASS/2POSIX skips), compile и реальные root `ftm status`/`ftm doctor` на VPS: обаcode0, healthy/consistent true,2peers/0missing/0unknown/0pending. Root DB/mode, socket, loopback и trusted TLS проверки true. Новых автотестов каждой диагностической функции нет — проверен рабочий сценарий.

Credentials панели находятся только в private `panel-login.json` и human-readable `Панель.txt` в закрытом локальном Downloads каталоге. Не копировать их в Git или отчёты. Текущее состояние разработки и ограничений — `PROGRESS.md`, backup scope — `CHECKPOINT.md`, ночная передача — `NIGHT_WORK.md`.
