# Атомарная регистрация: серверное ядро

Продолжение этапа4, без субагентов. Client HTTP endpoints и enrollment UI пока не включать.

Выбран клиентский CSPRNG device credential вместе с WG private key, CID и UUID request_id. До запроса клиент сохраняет их в secure storage. Сервер получает только WG public key, client CID и domain-separated credential hash; user token авторизует enrollment. Plaintext device credential не нужно возвращать повторно и хранить на сервере. Это устраняет проблему потерянного ответа при hash-only persistence; server-generated one-time credential потребовал бы дополнительного защищённого delivery protocol.

- [x] Выделить существующий create-device transaction body в приватный Store helper, сохранив старые admin fingerprints и поведение. Для enrollment добавить CID/credential-hash request binding.
- [x] Одна write transaction: user-token lookup + enabled/limit + IP/CID/public-key uniqueness + device outbox + credential hash. Повтор возвращает тот же device; изменённый binding, revoked/rotated credential и отозванный device не воскрешаются.
- [x] Целевые проверки concurrent retry, limit race, rollback при credential collision и запрет reuse после revoke. WG private key и raw device token никогда не принимаются этим серверным методом.
- [x] Настоящий test-VPS сценарий с synthetic client-generated keys/CID/token: repeat, loss-of-response recovery по client-held credential после reconcile, revoke и сохранность исходных peer/profile/PID. Fresh offsite backup, docs/local commit.

Отдельно впереди: public auth/throttling/typed IPC, pending status, per-device config+ETag, admin re-auth export, bootstrap claim/internal HTTPS, клиентское secure storage и реальные Android/Windows E2E. Никакой новой публичной регистрации до этих границ.

