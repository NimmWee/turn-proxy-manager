# Клиентский API этапа 4

Новое поручение пользователя 10.11.2026 возобновляет разработку после ночного cutoff. Один агент, без GitHub push/production. Продолжение согласованных ENROLLMENT_PLAN/STAGE4_PLAN.

- [x] Root client service: typed enrollment/status/subscription, bearer user/device scope, pending без секретов, active ownership/spec verification. Stable per-device manifest v1 без WG private key и admin/user tokens; content ETag после авторизации, включая проверку отзыва перед304.
- [x] Root IPC allowlist и безопасные machine-readable client errors. Чужой UID и произвольные поля по-прежнему отвергаются. API не читает root DB/config непосредственно.
- [x] HTTPS-only client routes enroll/status/subscription под `/api/client/v1/`. Cookie не авторизует client API, token не принимается в query/body/URL. Бounded IP/token/global throttling и concurrency, ошибки RU/code/correlation без echo input. Public routes только при public web config; private restore их закрывает через Caddy.
- [x] Отдельный managed envelope/JSON Schema; reference client собирает существующий freeturn share с **локальным** private key. Это контрактный caller, не Android/Windows VPN. IPv6 policy явно block до реальной клиентской проверки.
- [x] Целевые проверки disclosure/auth/revocation/304/pending/throttling. Обычные wiring изменения — рабочий сценарий. Никакого теста каждой функции.
- [x] Свежий encrypted checkpoint + offsite stage, runtime/API/control deploy на согласованный VPS; Caddy config validation/rollback и только нужные HTTPS paths. Реальный HTTPS synthetic enroll→kernel peer→own config→304→revoke, исходный iPhone/profile/keys/PID VPN/SSH сохранить. Docs/local commit.

Admin выпуск user links/UI/export требует re-auth и остаётся следующим блоком. Bootstrap/internal VPN access и настоящие Android/Windows E2E отдельно. Общий installer остаётся dry-run. Автоматизацию ночного окна не возобновлять.

ETag следует HTTP conditional semantics: [RFC9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2). Но валидатор никогда не заменяет device authentication. User URL rotation не меняет manifest существующего устройства; root transport/config changes меняют content hash.

