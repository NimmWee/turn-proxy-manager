# Этап 4: первый серверный блок

10.11.2026. Это credential foundation, **не готовые подписки, enrollment или client E2E**. Публичных client routes, кнопок экспорта в UI и новых секретных IPC операций пока нет.

`ftm.credentials.Credentials` выпускает независимые 256-bit opaque user/device tokens; scope prefixes различаются, в SQLite только domain-separated SHA256. User token rotation сохраняет subscription identity и увеличивает version. Смена/отзыв ссылки не меняет WG/CID и существующий device credential; отключение устройств — отдельная операция. Disabled user не проходит credential lookup. Device credentials выдаются только enabled/active non-iOS устройству; Anton48 остаётся ручным импортом.

Device revoke и user disable в Store транзакционно отзывают device tokens. Re-enable не оживляет старые credentials. Device credential rotation отзывает предыдущий. Аудит содержит только action/subject, обычные списки и ошибки не раскрывают plaintext/hash. Пять целевых тестов покрывают hash-only persistence, scope, конкурентную rotation, revoke/enable и rollback при ошибке private delivery.

Root-only `python -m ftm.credentials` имеет операции `user-link`/`device-access`, `issue`/`revoke`. Выпуск требует `--id` и новый `--output` в private root directory; файл0600 с O_EXCL/O_NOFOLLOW, токен не печатается и не принимается через argv. Существующий output отвергается **до** rotation. Доставка/fsync выполняется до commit транзакции: обычная ошибка записи оставляет прежний токен действующим. Это private credential artifact, ещё не импортируемый VPN профиль. Revoke здесь отзывает credential, VPN peer остаётся — для полного отзыва использовать существующий user/device disable.

## Реальная проверка на VPS

`scripts/verify_credentials.py --test-vps-apply` создал временный настоящий WG peer. Выпуск и смена user/device credentials, URL revoke, private root CLI и отказ от существующего output PASS. Настоящий control RPC revoke удалил peer и credential, последующий enable не оживил старый токен; user disable отозвал новый. SQLite Backup API copy не содержала plaintext. В конце synthetic user/device отключены, исходные два peers/config/registry/obf/iPhone profile и PID VPN/SSH/API/Caddy совпали. Root report `/root/ftm-credentials-report.json`.

Windows venv:100 tests,95PASS/5skips. WSL результаты фиксируются отдельно; они не доказывают физический клиент. Schema migration не потребовалась: используются исходные version1 tables. DB остаётся root600, секретных операций в API/IPC не добавлено.

Runtime `486619c38bbddd4c`. Последний checkpoint `/root/ftm-managed-d8c6d0fb43.vpnbackup`, SHA256 **9b9b35a07d80fabbca16741d286d1ee770f30baeb7d4add88f4e1a0182d66a90**. Private offsite `manager-credentials.vpnbackup` после завершения скачивания проверен SHA256 и реально staged в WSL:9 metadata devices,2 peers,public web settings. Первая попытка decode ещё не докачанного файла правильно отказала по HMAC; окончательная копия PASS. Тестовые token artifacts удалены private temporary directory; в Git секретов нет.

Восстановление старого backup возвращает прежнее состояние авторизации, включая действовавшие тогда tokens/peers. После отзывов нужна свежая offsite копия. Публичный enrollment требует проверки user-token+device limit+idempotency в одной транзакции, безопасной передачи device credential, admin re-auth для экспорта и проверенного wire/schema контракта. Bootstrap/internal HTTPS и Android/Windows E2E остаются NOT RUN/NOT IMPLEMENTED.
