# Этап 2: SQLite и независимые устройства

Дата: 10.11.2026. Выполнение одним агентом по указанию пользователя. Применяются writing-plans, test-driven-development и verification-before-completion. Пользователь подтвердил рабочий iPhone и разрешил следующие проверки на тестовом VPS. Android остаётся NOT RUN; это не блокирует доступные серверные работы по текущему поручению и не считается Android E2E.

## Порядок

- [ ] Зафиксировать handshake/rx/tx iPhone без вывода public keys/CID/секретов.
- [ ] Проверить реальный restore: перед отключением служб аутентифицировать offsite backup, сопоставить его ключи с live state, сохранить checkpoint. На том же тестовом VPS с временно отсутствующим state выполнить restore через baseline с годовым Fail2ban hook, сверить ключи/импорт. Это не второй чистый VPS.
- [ ] Инъекцией отказа после записи конфигурации проверить rollback в исходном install: после ошибки вернуть прежние конфиги и активный VPN; SSH/Fail2ban сохранить. Создать root-only страховочный checkpoint и восстановление в finally. Не менять пользовательский импорт.
- [ ] `ftm/store.py`, `ftm/migrations/001_initial.sql`: SQLite WAL/FK/busy timeout, версионирование, strict constraints; private DB folder/files; transactions BEGIN IMMEDIATE. Без постоянного root у metadata layer.
- [ ] `ftm/devices.py`: пользователи/устройства, конкурентное выделение /32 из /24 начиная с .10, резерв .1/.2/.3, уникальные WG public keys/CID/IP, idempotency key + request fingerprint; отдельный PSK на устройство, никаких общих private keys. Сначала только WG; AWG отклоняется до проверки backend.
- [ ] Безопасный импорт metadata старых iPhone/Android с прежними public keys/CID/IP/PSK без копирования private keys в БД. Идемпотентность и конфликтный повтор. Старое состояние и профили не перезаписываются.
- [ ] `ftm/agent.py`: allowlist add_peer/revoke_peer/status, проверка интерфейса, ключа, IP/CID, только subprocess argv; PSK через временный файл 0600. Защищённая root-only операция, фиксированные системные пути, без произвольных shell команд/пути из API. Безопасный старт: дополнительные peers добавляются hot, но незнакомые и baseline peers не удаляются.
- [ ] Reconciliation через persisted operation state: metadata pending/applying/active/error/revoked, отдельный root-side lookup по ID, атомарный clients.json merge с сохранением неизвестных записей. Отключение одного peer не пересоздаёт интерфейс. Удаление CID + wg peer, отдельный тест hot reload и existing-session revocation.
- [ ] CLI CRUD/list/import/backup для metadata, без секретов в обычном выводе; CLI root-agent отдельно. SQLite Backup API, integrity check и permission checks. Никакой записи SQL из API.
- [ ] Unit: 20 users/60 devices, concurrent enroll, idempotency/conflicts, bad public key/IP/CID, лимиты, rollback транзакции, backup/restore DB, отсутствие секретов в audit/CLI. Агент: parser/argv/PSK file/atomic merge/unknown peer preservation, failure compensation.
- [ ] На тестовом VPS импортировать только metadata действующих двух peers, убедиться в неизменности baseline/profile и services. Создать/применить/отозвать синтетическое третье устройство, проверить реальные wg/CID, сохранить двух старых. Не заявлять одновременный E2E трёх телефонов по этому тесту.
- [ ] Документировать результат, остаточные gates, откат и следующий шаг; commit без push.

## Границы

Данные пользователя и устройства меняются без перезапуска VPN. До завершения reconciler не включать автоматический apply на действующие устройства. Legacy CLI продолжает обслуживать baseline; операции legacy install/network-up пока считают только двух peers — не использовать их после включения динамических peers до решения startup persistence. Не объявлять этап 2 полностью завершённым без persistence/reboot и одновременных реальных устройств.
