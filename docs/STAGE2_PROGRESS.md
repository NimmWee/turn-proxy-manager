# Этап 2: результат первого рабочего шага

Дата: 10.11.2026, Asia/Tomsk. Работа выполняется без субагентов. Это работающий фундамент этапа 2; полная приёмка этапа ещё открыта.

## Подтверждение iPhone и восстановление

Пользователь подтвердил успешное подключение Anton48 через VK TURN, открытие сайтов и внешний IP тестового VPS. На сервере перед recovery зафиксированы handshake iPhone возрастом 15 секунд, rx **10839336 байт**, tx **83742984 байт**. Android: handshake отсутствовал; прежний успех Android со слов пользователя не является проверкой этой установки.

`scripts/verify_recovery.py --test-vps-apply` выполнил реальный restore на **том же** VPS: сначала проверил аутентичность и соответствие backup, затем временно убрал исходные конфиги/state и восстановил их из зашифрованной копии. Ключи и обе импортируемые ссылки совпали с исходными.

Затем намеренно вызвана ошибка после записи конфигурации и порчи временного obf-файла. Исходный rollback восстановил прежние файлы и активный VPN. SSH MainPID не изменился, годовая политика Fail2ban сохранилась. После проверки снова наблюдались handshake и трафик iPhone: rx **24736**, tx **35568 байт** (счётчики интерфейса после его восстановления). Профиль переимпортировать не потребовалось.

Это **не** восстановление на втором чистом VPS, не полный reboot и не проверка всех возможных точек отказа. Checkpoint и приватные копии остались root-only на тестовом сервере. Recovery запрещён при наличии manager-owned peers, чтобы legacy renderer не стёр динамическую конфигурацию.

## Реализовано

| Файлы | Поведение |
| --- | --- |
| `ftm/migrations/001_initial.sql`, `ftm/store.py` | Версия схемы и application_id, STRICT tables, WAL/FK/busy_timeout, транзакции BEGIN IMMEDIATE, private DB 0600 и каталог 0700 |
| `ftm/store.py` | CRUD пользователей, создание/список/отзыв новых устройств; разные public keys/IP/CID/PSK; idempotency key hash + request fingerprint, outbox операций, очищенный audit |
| `ftm/store.py` | Импорт двух существующих устройств без изменения source state и профилей; повторный импорт идемпотентен; WG private keys, obf key и VK link в SQLite не копируются |
| `ftm/metadata_cli.py` | Локальный CLI init/import/list/create/revoke/disable/backup; в обычном выводе нет CID/PSK/private keys |
| `ftm/agent.py` | Явный root-only reconcile с фиксированными системными путями; whitelist subprocess argv, валидация ключей/IP/CID/ID, PSK через временный файл 0600, без shell |
| `ftm/agent.py` | Hot `wg set`, атомарные CID/WG config updates с сохранением owner/mode, root ownership registry, подготовленная операция и компенсация ошибок; чужие peers/CID не удаляются |
| `scripts/verify_devices.py` | Реальный add/revoke синтетического peer, сохранность двух исходных и неизвестного sentinel, replay persistent WG config в отдельном network namespace |
| `ftm/baseline_deploy.py` | Повторная legacy-установка явно блокируется, пока registry содержит manager-owned peers |

Таблицы подписок/токенов/bootstrap/метрик созданы как schema foundation; их API и пользовательские сценарии ещё не реализованы. AWG намеренно не принимается до проверки backend.

## Проверки

- **65/65 Manager tests** и исходные **8/8** — всего **73**. Windows: 4 Linux-only проверки пропускаются, остальные 61 проходят.
- На тестовом VPS финальный прогон **65/65 Manager + 8/8 baseline PASS**, без пропусков. Незавершённых операций нет, SQLite integrity check — ok.
- Unit: 20 пользователей / 60 устройств, 10 конкурентных регистраций, один idempotent запрос из 10 потоков, pool exhaustion без частичной записи, дубликаты public key/ID, отключённый пользователь/лимиты, запрет AWG, future schema rejection.
- Unit: unknown live/persisted peer и IP conflicts не перезаписываются; после ошибки сети desired operation остаётся повторяемой; stale create не включает отозванное устройство; PSK не передаётся в argv.
- На VPS: импортированы metadata двух действующих устройств. Новое синтетическое устройство добавилось в реальный kernel WG и clients.json, затем отозвано.
- Точный persistent WG config с тремя peers загружен через `wg setconf` в изолированном network namespace. Это проверка сериализации/persistence-файла, **не** reboot хоста.
- При отзыве сохранились неизвестные sentinel peer/CID. После теста удалены только свои sentinel и новый peer. Исходные `state.json`, iPhone import, WG config и clients.json побайтно совпали с данными до теста.
- MainPID FreeTurn и SSH не изменились во время hot add/revoke. В SQLite остались два активных legacy-устройства и одно отозванное синтетическое; тестовый пользователь выключен.

SQLite содержит CID и PSK, поэтому файл, WAL и backups — чувствительные данные. Приватных WG-ключей и VK URL в этой БД нет. `Store.backup()` использует SQLite Backup API и integrity check, создаёт **незашифрованный** файл 0600. Отдельный зашифрованный SQLite checkpoint создан, скачан вне VPS и проверен локальной расшифровкой и integrity check с существующей recovery phrase. Это зашифрованный raw SQLite (`manager-metadata.sqlite3.enc`), не стандартный legacy state backup и не готовая команда общего Manager restore.

## Команды текущей версии

Из корня checkout, для отдельного тестового VPS:

```bash
python3 -m ftm.metadata_cli init
python3 -m ftm.metadata_cli import-legacy
python3 -m ftm.metadata_cli users list
python3 -m ftm.metadata_cli users create "Семья" --device-limit 5
python3 -m ftm.metadata_cli devices list
```

Добавление ожидает **public key**, private key остаётся у клиента:

```bash
python3 -m ftm.metadata_cli devices add USER_ID "Ноутбук" --platform windows \
  --public-key-file /root/device-public.key --request-id UNIQUE_OPERATION_ID
python3 -m ftm.agent --apply
python3 -m ftm.metadata_cli devices revoke DEVICE_ID
python3 -m ftm.agent --apply
```

Metadata-команда сама сеть не меняет. Agent CLI требует root и работает только с фиксированной `/var/lib/ftm/manager.sqlite3`, `vkvpn0` из валидированного baseline и собственным registry. Root у будущего FastAPI не предполагается; HTTP API пока отсутствует.

## Оставшиеся gates и следующий шаг

1. **Managed startup migration и legacy compatibility.** Отзыв/отключение импортированных старых устройств пока отклоняется до изменения metadata — активный iPhone защищён. Их исходные конфиги/приватные профили остаются в baseline state. Нельзя выдавать это за полный revoke legacy.
2. Legacy `vps-vk status` всё ещё ожидает два peers; при новых активных manager peers это ограничение старого CLI. В проверке третий peer отозван, сейчас исходный status снова здоров. Нужен адаптер динамического status/profiles и управляемой загрузки перед обычным использованием дополнительных устройств.
3. Нет постоянного agent service/Unix IPC, автоматического reconciler timer и web RBAC. Сейчас apply — отдельная root-only команда. Разделение прав DB/API/agent и защита IPC необходимы до FastAPI.
4. CID файл обновлён атомарно, исходник подтверждает polling 10 с. **Live авторизация нового CID через настоящий FreeTurn-клиент не проверена.** Три одновременных реальных устройства также не проверены.
5. Адреса отозванных устройств пока сохраняются в истории и не выдаются повторно. Пул новых устройств `.10–.254`; reuse потребует подтверждённой очистки actual state.
6. Требуется автоматизированный общий encrypted backup/restore metadata + registry + VPN и полный reboot. Raw SQLite checkpoint отдельно не восстанавливает всю систему.

Сначала закрыть managed startup/legacy adapter и полный checkpoint, затем перейти к FastAPI и русской панели. Этап 2 целиком завершённым не объявляется.
