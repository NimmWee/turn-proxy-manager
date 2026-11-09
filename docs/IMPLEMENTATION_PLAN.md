# План реализации FreeTurn Manager

**Дата:** 10.11.2026. **Источник требований:** [ТЗ](FreeTurn_Manager_TZ.md).

> Для выполнения: superpowers:executing-plans; изменения проверяются через superpowers:test-driven-development. Локальные безопасные работы разрешены пользователем. Развёртывание на действующем VPS требует отдельного согласованного доступа.

**Цель первого шага:** сохранить проверяемую копию Vps, зафиксировать исходные версии и добавить безопасный, исполняемый фундамент установки Manager.

**Архитектура:** неизменяемый `vendor/vps/` содержит исходную серверную установку с лицензиями и закреплёнными артефактами. Отдельный пакет `ftm/` выполняет только анализ и формирование плана. На этапе 1 Manager не меняет службы, firewall, WireGuard или состояние Vps. Установка Manager завершится явной ошибкой до реализации apply/rollback.

**Стек этапа 1:** Python 3.10+ (на Ubuntu 24.04 — 3.12), стандартная библиотека, Bash, unittest. Внешних Python-зависимостей пока нет. Контейнеры не используются.

## Этап 1: baseline и безопасный skeleton

### 1. Зафиксировать исходники

- [x] Изучить все шесть репозиториев, записать commit SHA, лицензии и ограничения в `docs/BASELINE.md`, `upstreams.lock.json`; зафиксировать CLI, форматы профилей и системные службы.
- [x] Скопировать отслеживаемые файлы Vps без изменения содержимого в `vendor/vps/`; сохранить README, LICENSE, NOTICE, исходники, тесты, manifest, готовые бинарники и архив.
- [x] Добавить `scripts/verify_baseline.py`: проверка SHA256 каждого сохранённого файла, транспортных бинарников и архива; отказ при отсутствии, подмене или небезопасном пути. Файлы берутся по allowlist из lock, без исполнения скачанного кода.
- [x] Проверить исходные 8 тестов: `python3 -m unittest discover -s vendor/vps/tests -v` и исходный verifier `python3 vendor/vps/scripts/verify-package.py`.

### 2. Добавить проверяемый анализ установки

Файлы: `ftm/installer.py`, `ftm/cli.py`, `ftm/__main__.py`, `install.sh`, `tests/test_installer.py`, `tests/test_cli.py`.

Дополнительно: `ftm/preflight.py`, `tests/test_preflight.py` — чтение ОС/root/systemd, CPU/RAM/диска, TCP/UDP-портов и наличия инструментов; DNS/TLS/firewall/службы не объявлять проверенными.

- [x] Сначала написать тесты валидации конфигурации: домен/IP, TLS policy, типы, отсутствие неизвестных полей, subnet/port separation; выполнить и зафиксировать падение из-за отсутствующей реализации.
- [x] Реализовать строгий JSON config (как содержимое файла `--config`, без shell source/eval), ограничение размера, запрет symlink и требование режима 0600 на POSIX.
- [x] Реализовать чистую функцию плана `build_plan(config, existing_state=None)`: существующая установка требует migration, сохраняет endpoint VPN, порты и subnet, не содержит секретов. Проверять legacy state исходным валидатором, не изменять его.
- [x] Добавить интерактивный мастер без обязательного `--domain`: домен/IP, режим, TLS/access, подтверждение; при EOF/SIGINT — отмена без записи и изменения системы.
- [x] CLI `python -m ftm install --dry-run`, `--non-interactive --config FILE --dry-run`, `python -m ftm inspect --state FILE` и Bash entrypoint с необязательным совместимым `--manager`. Диагностика выводит только allowlist полей, не исходное состояние/исключения с секретами.
- [x] Без `--dry-run` возвращать ненулевой код и понятное объяснение, что apply не реализован. Не вызывать apt/systemctl/wg/iptables и не объявлять установку успешной.
- [x] Проверить команды на Windows и Ubuntu WSL, включая subprocess CLI, неверный конфиг, отказ без dry-run и неизменность входного state.

### 3. Автономный smoke и проверка поставки

Файлы: `scripts/smoke_baseline.py`, `tests/test_baseline.py`, `.github/workflows/verify.yml`.

- [x] Linux amd64 smoke: проверить binary SHA, версию по startup log (флага `-version` нет), `-h`, команды `clients add/list/remove` на временном файле, не поднимая VPN и не меняя системных файлов. Проверить формат и независимость сгенерированных профилей на синтетических ключах.
- [x] Описать границы: smoke не доказывает передачу VPN-трафика, wire-совместимость Android 5.3.2 и сервера 4.1.2, прохождение VK/CAPTCHA и подключение Anton48.
- [x] CI Ubuntu 24.04: baseline verifier, обе группы unittest, bash syntax, binary smoke. Не запускать установку и не требовать секреты.
- [x] Обновить README, `docs/DECISIONS.md`, `docs/PROGRESS.md`: команды, PASS/FAIL/NOT RUN, rollback и следующий шаг.

**Gate этапа 1:** локальные unit/CLI/smoke должны проходить. Полная приёмка требует отдельного чистого Ubuntu VPS 1 vCPU/1 GiB, Android и iPhone, реального `vps-vk status`, `vps-vk profiles`, подключения через VK и проверки профилей. До этого этап 1 отмечается «локальная часть выполнена, E2E не подтверждено»; к реализации этапа 2 не переходить.

**Контракт миграции:** до любых системных изменений — зашифрованный бэкап вне VPS и подтверждённое восстановление. Сохраняются WG private/public/PSK, CID, VK link, obf key, профили iPhone/Android, endpoint/порты/subnet, firewall, Fail2ban и SSH. Незнакомые peers и чужие службы не удаляются. Отчёт плана не содержит значений секретов. Это требования будущего apply, а не уже выполненная миграция.

## Последующие этапы

2. SQLite WAL, версия схемы, импорт старых устройств без изменения ключей, транзакционное выделение IP/CID, ограниченный agent и reconciler. Тесты конкуренции/идемпотентности/отзыва; сохранение неизвестных peers. E2E: три одновременных устройства.
3. FastAPI и статический React/Tailwind, Caddy, защищённая сессия, RU UI и настоящие метрики. Сборка вне production. Тесты доступа, CSRF, маршрутов, TLS и памяти.
4. Подписка и device credential, revocation/rotation, revision/ETag, bootstrap→managed через VPN с проверкой TLS. JSON Schema и round-trip из реальных парсеров. Контрактный клиент явно помечается mock.
5. Android: выделенный GPL-совместимый fork, импорт/обновления, Connection Manager, защищённое хранилище, миграция подписи. APK и испытания на устройствах.
6. Windows: spike реального системного туннеля, выбор драйвера/лицензии, service/IPC ACL, UI, reconnect, installer/uninstaller, sleep и leak tests.
7. Матрица нагрузки и скорости, сбои, backup/restore/rollback, DNS/IPv6, совместимость Anton48, реальные сети. CPUQuota менять только по измерениям.
8. Закреплённые release artifacts, интерактивный install/upgrade/repair/migrate/restore/uninstall, финальная проверка всех T01–T27 на чистых системах.

Перед каждым следующим этапом план уточняется по результатам предыдущего. Выполненные unit/mocks не заменяют E2E.
