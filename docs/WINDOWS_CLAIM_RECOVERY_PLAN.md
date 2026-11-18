# Windows0.19: восстановление потерянного bootstrap claim

17.11.2026. Продолжение согласованного ТЗ. Без субагентов, реальных VPN/SCM/VPS изменений и GitHub. Пользователь тестирует0.18; новые binaries собирать в отдельный `artifacts/package-0.19`, common package0.18/installed services не трогать.

## Дизайн

Текущий клиент проверяет expiry до HTTP и повторяет POST claim. Сервер может уже сохранить device token, даже если ответ клиенту не дошёл. Server GET `/api/client/v1/status` принимает этот token без bootstrap nonce; Go saved-profile validator проверяет формат expiry, identity и derived key, не требует неистёкший nonce. Менять сервер/API/Go validation не нужно.

Выбран status-first workflow для manual activation. Альтернативы: только повторять nonce POST (не восстанавливает после expiry) либо выпускать новый token/устройство (ломает identity/ключи и создаёт дубли). Оба не подходят.

- До любого HTTP: connected gate, valid metadata и локальная проверка share/derived public key/origin. HTTP только через прежний internal10.77.43.1:443 с origin/default TLS validation; no proxy/redirect/public fallback.
- GET status использует только device bearer.200 с exact matching device/revision/state/ready подтверждает уже принятое устройство и очищает nonce в atomic DPAPI. Expired nonce не мешает этому. Pending/error не объявляются active и не вызывают POST.
- Только401 неизвестного device token разрешает перейти к POST claim, и только пока expiry ещё впереди.403/429/503/network/malformed/oversized/redirect не вызывают новый claim. Повторный POST использует прежний device token hash и nonce, не выпускает credentials/keys/CID/device.
- Сохранять профиль/токен/expiry/selection при ошибке, при expiry+401 явно требовать администратора. Catalog expected metadata/share guard запрещает stale commit. Проверять authenticated runtime lease до HTTP/commit/POST и после await; смена profile/attempt/path/cancel запрещает запись/nonce POST.
- UI manual activation после expiry остаётся доступной как «Проверить восстановление», без обещания восстановления ещё не принятого запроса. Без фоновых HTTP/автоподключения.

## Выполнение

- [x] Targeted failing checks: потерянный ответ→перезапуск→expired nonce→status active; token/key/selection preservation, wrong device/invalid reply/pending/401/403/rate-limit/network/stale/session guards.
- [x] Обновить Claim/status parser и manual UI; server/API/SQLite ownership не менять.
- [x] Разделить build/offline output directories для параллельной проверки0.18 пользователем.
- [x] Go/C# targeted+actual key bridge, server-contract interoperability, build/native/offline/package hashes; docs update.

Real internal HTTPS/VPN/claim recovery/CAPTCHA/device authorization/leaks E2E — NOT RUN. Синтетические HTTP сценарии не объявлять серверной приёмкой.

## Результат17.11.2026

- Регрессионный сценарий на прежнем коде завершался `MANAGED_BOOTSTRAP_EXPIRED` после потерянного POST→backup/restart→expiry. Теперь GET status подтверждает прежний token; POST не повторяется, nonce очищается только после подтверждения. Share/derived WG key/device token/selection сохранены.
- C# targeted checks PASS: новая активация401→один POST; lost response/expired recovery; expiry до/во время GET;403/429/503/302/network, malformed/duplicate/oversized/wrong-device/inconsistent-ready и pending/error; четыре runtime guard checkpoints, удаление профиля во время HTTP и wrong derived key до HTTP. Refusal не меняет профиль/выбор и не создаёт credentials/device. DPAPI backup/restore действительно выполнены локально; HTTP синтетический.
- Actual C#→Go managed/expired bootstrap verification, enrollment, settings renderer, LKG и Python↔Go v1 manifest/ETag/Unicode/key contract PASS. Production server/API/schema не менялись.
- Новый серверный regression в `tests/test_bootstrap.py` проверяет: committed token→expired nonce POST410→status active с тем же token hash→revoked token401. WSL Linux temporary copy:8 server logic checks PASS;4 HTTP wrapper checks SKIPPED из-за отсутствующих web development dependencies. Это не live HTTPS/agent/VPS проверка.
- Go test/vet/build и WPF publish PASS. Final native single-window/nested/busy/editor/close/WebView checks PASS с synthetic catalog/fake callbacks; services=false/networkChanged=false. Экран expired recovery осмотрен, кнопка и пояснение видны. Pure previews не подтверждают CAPTCHA/VPN.
- Offline checks нового package: state digest маршрутов/адаптеров/служб не изменился; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK, другие VPN не отключались. Baseline23/vendor package verifier PASS.
- Изолированная сборка `clients/windows/artifacts/package-0.19`; build/collect_licenses/offline/contract scripts принимают отдельный output/engine path. Проверены15 payload SHA и189 bundled sources. ZIP 86.2MiB,16 entries; SHA256 `bf9c200a796ab0fe5ba126e2871dfa93143bd8ee643e044c41ac3a78a2b9ca71`. Проверенные EXE совпадают после финального source bundle refresh. Все16 файлов common package0.18 и ZIP0.18 остались побайтно прежними.
- Installed services, пользовательские каталоги/ключи/iPhone-профиль, VPS и GitHub не менялись. Real internal TLS/VPN/claim recovery/revocation/CAPTCHA/leaks E2E — **NOT RUN**.
