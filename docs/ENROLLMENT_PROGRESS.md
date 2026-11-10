# Атомарное ядро enrollment

10.11.2026, серверный блок этапа4. **Публичного enrollment HTTP/IPC ещё нет.** Выполненный сценарий — synthetic in-process caller и настоящий WG, не Android/Windows client E2E.

`ftm.enrollment.Enrollment.register` проверяет действующий user-token, enabled user и device limit, выделяет уникальные IP/CID/public key, пишет durable operation и client credential hash **в одной SQLite write transaction**. Существующий Store create-device body вынесен в private helper, admin fingerprints/поведение сохранены. Старые ключи и схема БД не меняются.

Официальный клиент должен заранее сохранить в secure storage WG private key, случайный CID, UUID request_id и 256-bit device token. Сервер получает public key/CID/hash, но не private key или plaintext device token. Хеш: lowercase hex SHA256 от UTF-8 строки `ftm/credential/device/` + token; token имеет prefix `ftmd1_` и43 символа unpadded base64url от32 CSPRNG bytes. User-token проходит отдельную auth проверку в той же transaction.

Request fingerprint связывает имя/platform/public key/CID/credential hash. Concurrent retry создаёт один device/credential/outbox и возвращает те же identity/IP. Смена параметров под тем же request_id конфликтует. Повтор после device revoke или credential rotation не может восстановить доступ. Credential-hash collision откатывает device, IP allocator и operation. Pending credential не авторизует конфиг до actual active state; публичный pending/status protocol предстоит добавить отдельно.

Четыре целевых concurrency/access tests PASS вместе с существующими Store/agent/credential checks. Windows106:101PASS/5skips; WSL106:103PASS/3web skips, baseline8 и binary smoke PASS.

## Настоящий test VPS

`scripts/verify_enrollment.py` создал synthetic client-held keys/CID/token и повторил register. После этого **периодический control worker сам применил kernel WG peer**. Игнорирование первого результата моделировало потерю metadata response: caller смог проверить device credential, которым уже владел. Это не инъекция потери HTTP-пакета и не реальное клиентское приложение.

Client CID сохранился, user URL rotation сохранила device identity/credential. Настоящий revoke через control RPC убрал peer/token; retry не оживил доступ. SQLite Backup API copy не содержала client private key/plaintext token. В конце user/device отключены, два исходных peers и config/registry/obf/iPhone profile совпали; PID VPN/SSH/API/Caddy не менялись. `/root/ftm-enrollment-report.json`.

Runtime `ba506629de5988da`. Checkpoint `/root/ftm-managed-e3336b9bbf.vpnbackup`, SHA256 **dab56a048c677b26e80f487e58824dfbc5f01978efe5628b7f91efd5fd2cf0ca**. Private offsite `manager-enrollment.vpnbackup` реально расшифрован/staged в WSL:10metadata/2peers/public web settings, SHA256 совпал.

Дальше typed IPC/public auth+throttling, pending/status и per-device config/ETag, re-auth export, bootstrap/internal HTTPS, реальные клиенты. До этого нельзя называть enrollment/subscription готовой пользовательской функцией.
