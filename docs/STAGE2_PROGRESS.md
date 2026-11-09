# Этап 2: metadata, управление legacy и подготовка startup

Дата: 10.11.2026, Asia/Tomsk. Работа выполняется без субагентов. Это работающий фундамент этапа 2; полная приёмка этапа ещё открыта.

## Последний результат: startup/recovery

Установлены root-owned runtime и совместимые системные команды. Общий encrypted checkpoint, offsite decode/stage, live same-host restore и отказ с rollback PASS. Проверены pending revoke/enable через реальный network restart и выдача только активных профилей. Выполнен настоящий reboot: auto-start VPN PASS, hashes конфигов/ключей/профилей и metadata совпали; SSH, Fail2ban и scoped firewall здоровы. Это не clean-host restore и не phone E2E после reboot. Следующий блок — ограниченный IPC; SQLite остаётся root-owned. [Детали checkpoint](CHECKPOINT.md), [план IPC](IPC_PLAN.md).

## История managed migration

На тестовом VPS выполнен `scripts/verify_managed.py --test-vps-apply`: root adoption двух исходных устройств с проверкой live public key/PSK/IP/IPv6 и persistent config. Теги ownership добавлены без изменения ключей, CID и выданного iPhone-профиля. Повтор adoption идемпотентен. Metadata-флаг без соответствующего root registry не разрешает legacy-операцию.

Отозван и возвращён неактивный Android peer; iPhone не затрагивался. Синтетический третий WG peer добавлен и удалён. Новый `ftm.compat status` подтвердил состояния с 1/2/3 peers; фильтр профилей исключает отозванный Android. На завершении снова два исходных peer, SSH и FreeTurn MainPID прежние. Это не Android-клиентский E2E и не live тест нового CID.

`ftm.startup --prepare` умеет сохранить pending desired state до поднятия интерфейса, без вызовов WG set и без изменения живого VPN. Он требует root-owned private SQLite и не рассчитан на будущую API-writable DB. Конфликт блокирует startup вместо загрузки старых прав. `scripts/verify_startup.py --test-vps` проверил копию SQLite/registry/config в отдельном namespace: pending revoke → 1 peer, enable + add → 3 peers, revoke → 2 peers через настоящий `wg setconf`. Живые configs/profile/registry и процессы SSH/FreeTurn не изменились.

**Текущая проверка:** 77/77 Manager tests PASS на Ubuntu VPS; Windows 73 PASS и 4 Linux-only skips. Ни systemd hook, ни `/opt/ftm`, ни новый `/usr/local/bin/vps-vk` пока не установлены. Reboot и общий managed encrypted restore ещё NOT RUN. Очередь продолжения: [NIGHT_WORK.md](NIGHT_WORK.md). Следующие разделы сохраняют историю первого checkpoint.

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

1. Managed startup, совместимый system CLI и host reboot уже PASS. Остаётся clean-host restore в будущем installer; исходные private profiles в baseline state являются архивом ключей, а не разрешением доступа.
2. Системный `vps-vk` заменён совместимым wrapper; status/profiles и запрет legacy mutation проверены. Новые возможности не должны обходить root ownership.
3. Нет постоянного agent service/Unix IPC, автоматического reconciler timer и web RBAC. Сейчас apply — отдельная root-only команда. Разделение прав DB/API/agent и защита IPC необходимы до FastAPI.
4. CID файл обновлён атомарно, исходник подтверждает polling 10 с. **Live авторизация нового CID через настоящий FreeTurn-клиент не проверена.** Три одновременных реальных устройства также не проверены.
5. Адреса отозванных устройств пока сохраняются в истории и не выдаются повторно. Пул новых устройств `.10–.254`; reuse потребует подтверждённой очистки actual state.
6. Общий encrypted checkpoint текущего managed VPN и same-host restore/rollback/reboot PASS. Копию потребуется расширить настройками API/Caddy/доменов при их появлении; clean-host restore пока NOT RUN.

Следующий шаг — безопасный IPC для rootless API, затем FastAPI и русская панель. Этап 2 целиком завершённым не объявляется.
