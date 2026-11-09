# Зашифрованная копия managed VPN

Текущий формат объединяет root-owned SQLite (через SQLite Backup API), baseline state с ключами и выданными профилями, persistent WireGuard config, CID config и root ownership registry. **Версия 2** добавляет root web config: password hash, имя администратора и секретный путь панели. Сессии не сохраняются; после restore нужен новый login. Caddy, домен и сертификаты пока отсутствуют — при их появлении копию потребуется расширить. Это ещё не финальный installer/restore всего проекта.

Команды после установки runtime:

```bash
ftm backup /root/family.vpnbackup
ftm restore /root/family.vpnbackup --dry-run
ftm restore /root/family.vpnbackup --apply
```

Recovery phrase запрашивается скрытым вводом; она не передаётся в argv. Новый ciphertext создаётся 0600 без перезаписи существующего файла. Обязательно скачать его вне VPS. `restore` без `--apply` только проверяет и разворачивает данные во временный private каталог, затем удаляет его. Ключи не выводятся.

## Ограничения применения

Сейчас `--apply` поддерживает **только тот же установленный хост с неизменным baseline state**: endpoint, ключи, subnet, порты и uplink должны совпасть. Он восстанавливает managed metadata/registry/WG/CID, obf key из baseline state, web config, синхронизирует существующий kernel WG и контролируемо перезапускает FreeTurn и ранее активный API. Для API проверяется HTTP readiness, credentials обновляются через systemd. SSH, firewall, network.json и сторонние службы не меняются. Сетевая служба должна быть уже установлена, interface должен существовать, а текущая metadata должна позволять создать согласованную rollback-копию.

Старый v1 без web settings можно проверить/stage, но нельзя применить поверх уже provisioned web. Root login note не архивируется: копия сохраняет hash, не исходный пароль; после ручной смены credentials следует хранить действующий пароль отдельно. Root web config остаётся 0600, API получает только read-only systemd credential.

Пустой/повреждённый хост, миграция на другой IP и восстановление сертификатов — будущая работа installer. Этот промежуточный режим не выдаётся за T19 на чистом VPS. До миграции или reboot требуется проверенная offsite-копия и доступное восстановление.

## Защита и согласованность

- Шифрование использует тот же OpenSSL AES-256-CBC/PBKDF2, что закреплённый baseline, и отдельный версионированный контейнер `FTMCP1`. HMAC-SHA256 с отдельно выводимым ключом проверяется **до** расшифровки и разбора JSON/SQLite. Ограничены ciphertext и размеры отдельных разделов. Неверная phrase и изменение ciphertext отклоняются.
- Только четыре фиксированных data-раздела и SQLite. Произвольные пути, unit-файлы, shell hooks, команды firewall и неожиданные SQL schema/trigger/view не принимаются. Схема SQLite сравнивается с доверенной миграцией; проверяются integrity/FK/version и отсутствие незавершённых операций.
- Собственные peer/CID/PSK/IP/IPv6 сопоставляются с metadata и root registry. Отозванный device не должен оставаться в config/CID. Неизвестные peers сохраняются как data, их записи не присваиваются Manager автоматически.
- Root lifecycle flock и SQLite write reservation согласуют захват конфигов и Backup API. Metadata CLI для стандартной БД использует тот же lifecycle flock. SQLite остаётся root-owned; API не получает прямой доступ на запись.
- До live restore создаётся предыдущий согласованный checkpoint. При ошибке после записи он возвращается вместе с kernel peers и запуском FreeTurn. Явное обслуживание сбрасывает счётчик failed/start-limit перед запуском, сохраняя исходный лимит crash loop 4 старта за 5 минут.

## Проверено 10.11.2026

Три целевые проверки безопасности: staged restore, отказ от добавленного пути/SQL trigger, неверная phrase/повреждённый ciphertext. Полного покрытия всех функций не предполагается по уточнению пользователя.

На тестовом VPS создан общий ciphertext и скачан в приватный локальный каталог. В WSL он реально расшифрован, schema/integrity/ownership проверены и stage восстановлен: четыре metadata devices (два старых active и два синтетических revoked), два root-owned peers. SHA256 offsite ciphertext совпал с серверным.

Затем `scripts/verify_checkpoint.py` на тестовом VPS добавил временный настоящий WG peer и metadata, восстановил старый checkpoint и подтвердил их удаление. Инъекция ошибки после записи вернула предыдущее состояние с временным peer; финальное восстановление вернуло исходный snapshot. iPhone import и baseline state побайтно совпали, SSH MainPID прежний. Это same-host recovery, не clean-host restore и не проверка iPhone после recovery человеком.
