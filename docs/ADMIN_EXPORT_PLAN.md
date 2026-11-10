# Защищённая выдача из панели

Продолжение после BOOTSTRAP.md по действующему поручению пользователя. Без субагентов/GitHub/production. Password/секреты никогда не сохранять в repo или logs.

Каждая выдача требует existing session + Origin + CSRF и повторный password. Root дополнительно сверяет password с собственным web.json; API UID не получает экспорт по одному лишь внутреннему вызову. Root global bad-password budget5/600s, без доверия к переданному API IP. Нет общего долговечного re-auth grant.

Для retry используется UUID запроса и root-only delivery cache `/var/lib/ftm/exports`700/files600, max64, retention600s. Secret cache — временная доставка, не источник восстановления и не часть checkpoint. UUID tombstone хранится атомарно вместе с credential/peer: повтор после истечения cache возвращает410, не создаёт новый peer и не вращает ссылку снова. Bootstrap использует existing bootstraps.id; user enrollment export — settings запись без secret. Root проверяет соответствие cache текущим DB nonce/token identity, enabled state и request fingerprint. Restore старого snapshot не должен позволить выдать orphan cache.

В панели — «Подписка» (новый файл с user credential, rotation сохраняет peers) и «Стартовый профиль» для пользователя. Пароль очищается после запроса, secret response скачивается как JSON через Blob и не рендерится/не пишется в browser storage. Native import пока не готов: показать понятное ограничение совместимости. QR — после согласованного native import contract.

- [x] Root re-auth/export service, bounded private delivery cache, durable idempotency; schema и SQLite ownership без изменений.
- [x] Typed IPC и POST admin routes, session/CSRF/Origin; RU modal/actions/download.
- [x] Targeted re-auth bypass/retry/rotation/cache scope tests, frontend build и рабочий сценарий.
- [x] Fresh checkpoint/offsite, test VPS deploy; реальный HTTPS login→password denial→export/retry→no duplicate/rotation, cache inaccessible API UID, secrets absent logs. Browser download outside Git.
- [x] Backup/progress/docs/local commit. Нативные приложения и VK T10 остаются NOT RUN.

