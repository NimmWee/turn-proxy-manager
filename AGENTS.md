# Работа над FreeTurn Manager

- Работать без субагентов: явное указание пользователя от 10.11.2026.
- Основные требования: `docs/FreeTurn_Manager_TZ.md` и `docs/IMPLEMENTATION_PLAN.md`.
- Различать реализованный код, локальные тесты, mock и реальные E2E. Состояние — в `docs/PROGRESS.md`.
- `vendor/vps/` — неизменяемый baseline NimmWee/Vps. Не форматировать, не переписывать и не обновлять его автоматически. Контроль — `upstreams.lock.json` и `scripts/verify_baseline.py`.
- Новый control plane размещать в `ftm/`. Не выполнять сетевые изменения, apt, firewall reset или перезапуски существующего VPN из кода чтения/планирования.
- В текущем skeleton допустим только dry-run; запрос применения должен завершаться ненулевым кодом до любых системных изменений.
- Исключение по явному поручению пользователя: отдельная root-only операция `secure-ssh --apply` на согласованном тестовом VPS. Политика SSH: 3 ошибки за 600 секунд, бан 31536000 секунд, persistent DB retention 31622400 секунд. Она не делает доступным основной install/apply VPN.
- Пользователь разрешил развернуть исходный VPN на отдельном тестовом VPS и выдать приватный профиль iPhone для Anton48. Использовать `python -m ftm.baseline_deploy --apply` с годовым Fail2ban hook, не изменяя `vendor/vps/`. VK URL хранить только на сервере 0600; импорт/QR выдавать вне Git. Общий install/apply Manager пока не готов.
- Пользователь подтвердил iPhone E2E и разрешил recovery/rollback и начало этапа 2 на тестовом VPS. Разрешены SQLite metadata import и синтетические hot add/revoke проверки через фиксированный root-only agent; рабочий VPS не затрагивать. Legacy revoke/disable до managed startup migration явно отклоняется. Пакетный baseline reinstall/recovery не запускать при активных manager peers: старый renderer перезапишет их конфигурацию.
- Не выводить private keys, PSK, CID, VK link, obf key и токены в диагностику, исключения или Git.
- Не подключаться к реальному VPS и не развёртывать туда проект без согласованного доступа. Не отправлять изменения на GitHub без поручения пользователя.

Проверки:

```text
python -m unittest discover -s tests -v
python scripts/verify_baseline.py
python vendor/vps/scripts/verify-package.py
```

Полный локальный Linux-прогон из Windows:

```text
wsl -d Ubuntu-24.04 -- python3 /mnt/c/project/FTM/scripts/validate_linux.py
```

WSL-прогон использует временную копию на Linux filesystem: права 0600 на NTFS без metadata могут не исполняться. Никаких production E2E он не подтверждает.
