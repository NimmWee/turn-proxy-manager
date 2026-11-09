# Защита SSH через Fail2ban

## Политика

По поручению пользователя от 10.11.2026:

| Параметр | Значение |
| --- | --- |
| Служба | SSH, фактические порты из `sshd -T` |
| Порог | 3 ошибки (`maxretry = 3`) |
| Окно подсчёта | 600 секунд / 10 минут |
| Бан | 31536000 секунд / 365 дней |
| Увеличение/случайное продление | Выключены |
| Firewall action | nftables-multiport, только SSH-порты |
| Логи | systemd journal, фильтр sshd normal |
| Хранение банов | `/var/lib/fail2ban/fail2ban.sqlite3` |
| Очистка базы | 31622400 секунд / 366 дней |
| Исключения | Только loopback: `127.0.0.1/8`, `::1`; внешний IP администратора не добавляется в постоянный allowlist |

Фильтр sshd normal распознаёт ошибки SSH, включая неверные пароли; это не счётчик ошибок пароля веб-панели. Бан относится к IP и SSH, а не к отдельной учётной записи и не ко всем портам сервера.

Источник семантики `maxretry`/`findtime`/`bantime`: [официальный jail.conf](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/jail.conf). Persistent DB/retention: [официальный fail2ban.conf](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/fail2ban.conf).

## Установка и применение

Для Ubuntu 24.04, на согласованном сервере, под root:

```bash
apt-get update
apt-get --no-install-recommends install -y fail2ban python3-systemd nftables
cd /path/to/FTM
python3 -m ftm secure-ssh --apply
```

Пароль SSH не передаётся в CLI и не сохраняется в проекте. Модуль определяет порты SSH, сохраняет прежние конфиги в root-only `/etc/fail2ban/ftm-backups/`, пишет `/etc/fail2ban/jail.d/zzzz-ftm-sshd.local` и обновляет `/etc/fail2ban/fail2ban.local`. Перед включением выполняет `fail2ban-client -t`, затем проверяет реальные значения работающей службы. При ошибке восстанавливает содержимое и права прежних файлов, а также прежнее состояние службы.

Содержимое конфигов, SSH auth policy и процесс sshd не меняются. Постоянный IP-allowlist для текущего SSH-клиента не создаётся. Повторное применение той же конфигурации не перезапускает работающую службу Fail2ban.

## Результат на тестовом VPS

Дата проверки: 10.11.2026, Asia/Tomsk. Ubuntu 24.04.4 LTS amd64, 1 vCPU, 961 MiB RAM. Данные входа в репозитории отсутствуют.

- Fail2ban **1.0.2** установлен, включён в автозапуск и активен.
- Runtime-параметры: maxretry **3**, findtime **600**, bantime **31536000**, DB purge age **31622400**.
- Три синтетические строки OpenSSH `Failed password` распознаны установленным фильтром: **3 matched**.
- В отдельной проверке через `fail2ban-client set sshd attempt` для TEST-NET адреса: после 1/2 ошибок ban отсутствовал, после третьей — появился.
- IP присутствовал в nftables; SQLite содержала бан с bantime **31536000**.
- После перезапуска **Fail2ban** ban восстановился в памяти и firewall. Полный reboot VPS не выполнялся.
- Синтетический ban удалён; посторонние баны не удалялись.
- Повторное применение: **changed = false**.
- Процесс sshd сохранил MainPID **712**; SSH не перезапускался. Новый SSH-вход проверен отдельно.
- `MemoryCurrent` Fail2ban после проверки: **20058112 байт**, около **19.1 MiB**. Это одиночный замер, не stress benchmark.

Проверка не выполняла три настоящих неправильных SSH-входа с адреса администратора. Фильтр OpenSSH и порог/длительность/реальное firewall enforcement проверялись отдельно. VPN-трафик, VK TURN и клиенты этим тестом не проверены.

Интеграционный сценарий для отдельного тестового VPS:

```bash
python3 scripts/verify_ssh_protection.py --exercise-restart
```

Он использует только резервный TEST-NET IP `192.0.2.123`, кратковременно перезапускает Fail2ban и удаляет свой тестовый ban. В обычный CI этот сценарий не включён.

## Проверить состояние и снять бан

```bash
fail2ban-client status sshd
fail2ban-client get sshd maxretry
fail2ban-client get sshd findtime
fail2ban-client get sshd bantime
fail2ban-client get dbpurgeage
```

Из SSH-сеанса или консоли хостера, под root:

```bash
fail2ban-client set sshd unbanip АДРЕС_IP
```

## Совместимость с базовым Vps

В неизменяемом baseline прежняя политика — 30 дней и собственная проверка этого значения. Новое требование пользователя имеет приоритет. Будущий установщик должен использовать новый модуль вместо legacy `configure_fail2ban()`. Простое добавление высокоприоритетного jail поверх старого installer приведёт к конфликту его старой проверки. На тестовом VPS исходный VPN-установщик пока не запускался.

При первом применении обнаружена особенность Fail2ban 1.0.2: `get dbpurgeage` возвращает форматированный ответ, а не только число. Откат сработал; парсер исправлен и покрыт тестом на фактический формат ответа.
