# Персональный bootstrap и claim

Продолжение этапа4 по поручению пользователя. Без субагентов/production/GitHub. Общий installer остаётся dry-run. Нативные приложения ещё не поддерживают новый envelope; не добавлять неизвестные поля в upstream freeturn JSON.

Выбран отдельный `ftm-bootstrap` envelope v1: существующий native share, device/public identity, внутренний HTTPS address, одноразовый nonce и TTL. Root-only CLI создаёт индивидуальную WG пару и новый peer в одной metadata transaction с hash-only nonce; private key только в новом root0600 артефакте. Delivery fsync до commit, ошибка откатывает metadata/nonce. Активация peer — существующий reconciler, профиль может быть pending до применения.

Claim: HTTPS POST `/api/client/v1/bootstrap/claim`, nonce в Authorization Bearer, body только device_id/device_token_hash. Клиент генерирует device token локально до claim. API передаёт фактический trusted-proxy client IP через allowlisted IPC. Root сверяет собственный peer/IP/active registry, enabled user/device, subscription identity и TTL. Один BEGIN IMMEDIATE потребляет nonce и вставляет hash токена. Повтор допускается только для того же ещё активного hash, в пределах TTL; другой hash/отозванный credential не восстанавливается. Disable истекает незавершённые nonce, enable не оживляет их. Ни WG keys/CID, ни профиль при claim не меняются.

Nonce TTL ограничивает управление, не срок работы VPN peer; peer отключается явным device/user disable. Сохраняемый bootstrap остаётся секретным recovery artifact. Root private key не записывается в SQLite, logs, public JSON или Git. User URL rotation сохраняет bootstrap identity; revoke subscription URL запрещает незавершённый claim, не меняя WG peer.

- [x] Core issuance/claim и отдельный private artifact writer/CLI, managed manifest builder переиспользовать без обхода active проверки публичного API.
- [x] Ограниченный IPC/HTTPS endpoint, throttling10/IP/nonce,410 expired/used,403 wrong source/disabled; Caddy route и reference caller contract.
- [x] Целевые проверки rollback delivery, nonce TTL/replay/concurrency/disable и client source isolation. Ordinary wiring — сценарий.
- [x] Fresh checkpoint/offsite, test VPS deploy, настоящий WG namespace claim→managed/304, внешний spoofed XFF отказ, исходные профили/ключи/PID сохранить; временные peers убрать.
- [x] Docs/backup/local commit. Panel re-auth/export и native integration — следующие отдельные блоки.

Namespace proof обходит TURN. T10 (реальный native VK bootstrap при заблокированном внешнем443) до интеграции приложения NOT RUN.

