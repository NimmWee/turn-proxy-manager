# Windows0.26: bounded AWG2/3 compatibility

Ночное продолжение18.11: до08:00Томск, без subagents/реального VPN/VPS/UAC/изменения установленных служб.0.25/Setup0.25 сохраняются frozen. Цель — отдельно проверенный и собранный0.26 с расширенным parser→уже закреплённым amneziawg-go3.1.20260814, без собственной криптографии и без утверждения о полном AWG E2E.

Primary evidence: [официальные параметры AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/), pinned local device/uapi.go, noise-types.go, obf*.go, timers.go и upstream FreeTurn internal/tunnel/config.go/wgconf. Наш pinned backend имеет H ranges/S3/S4/I chains/HeaderProtectionKey/ContentPaddingAddition/timers/RandomTrailers/DisableCookies. WGNT эти параметры не исполняет.

План:

- [x] Строгие bounded H1–H4 ranges с проверкой пересечений, S3/S4, I1–I5 с полной проверкой грамматики/ресурсов. I tags b/r/rc/rd/t,≤12 tags/chain,≤1280 выходных байт/packet,≤4096 chars/chain; d/ds/dz/неизвестные tags отклонять (на пустом pre-handshake payload они не проверены). Исходный WG текст сохраняется, UAPI canonical.
- [x] AWG3: strict32-byte base64 HeaderProtectionKey→hex UAPI, все S≥12 при ключе; bounded CPA и timer ranges, явные boolean aliases. Не менять параметры автоматически/не ослаблять WG crypto. Timers: zero/default или rekey30..150s, reject60..180s, retry3..15s, keepalive3..30s, attempts1..20; reject lower должен быть выше rekey upper и keepalive+retry upper. S4+CPA upper≤64; S1–S3≤512. Это поддерживаемое подмножество, не все возможные upstream configs.
- [x] Версия required AWG family1/2/3 в safe effective metadata, capability/UI без вывода ключа/CPS; прежние explicit system backend/pre-SCM/managed WG-only/recovery guards сохраняются. Peer PersistentKeepalive range пока не поддерживается и отклоняется.
- [x] Настоящие encrypted loopback TCP/UDP/handshake для AWG2 и AWG3 + отказ wrong header key, большой UDP payload и применение параметров. Parser/resource/privacy/нет downgrade/recovery tests целевые. Новая C# edit/DPAPI/backup/actual Go inspection проверка AWG3.
- [x] Full Go/vet/build/WPF/C#/offline/source/hash, isolated package0.26. Real TUN/Direct/VK/AWG-server/sleep/leak/timer longevity/cookie-under-load E2E — NOT RUN. Не менять pinned upstream/module cache/установленную0.24.

Файлы: расширить awg_memory_config_windows.go и вынести bounded value/CPS parsing в awg_parameters_windows.go; public whitelist/profile effective/capability/UI, targeted tests/pair fixture; README+version0.26. До сборки завершить все bundled source изменения.

## Результат локального блока

Реализованы перечисленные parser/UAPI/capability/UI/backup изменения. Red→PASS targeted bounds/profile tests; реальные encrypted TCP/UDP loopback для AWG2/3 и базовых WG/AWG1,1252-byte UDP payload (1280B innerIPv4+UDP), wrong HeaderProtectionKey handshake refusal PASS. Header key и CPS остаются только в private config/IpcGet; effective/health inspection —safe metadata. Timer ranges/booleans приняты устройством; длительное поведение timers/cookies под нагрузкой не проверено. Protocol enum —группа настроенных extensions, не negotiated version: I-only legacy1.5 относится к совместимой группе2.

Full Go/vet/build/WPF PASS; C# edit→DPAPI→AES-GCM backup→actual Go AWG3 protocol inspection PASS; managed/enrollment actual builders и system routing preview regressions PASS. Core UDP budget2048B в pinned listener/loop достаточен для наших bounded datagram sizes; это анализ размеров, **не combined FreeTurn+AWG E2E**. Offline routes/adapters/services digest unchanged; другой VPN обнаружен preflight и не трогался.

ZIP0.26:90.45MiB,16 entries/15 payloads,213 corresponding source files,81 notices. SHA256 `792af1c7384d887704ccaebce9c6d4cc9d7a22b1badeb113647e24a8bcfb3787`. Setup0.26:79.54MiB, SHA256 `e96aea99c527a5cfcb172b145f14e3ec7da0045d587643494520d4e02d7683f0`; sources SHA256 `4483e3cb7537396a2d3c1ddb931448995a5239e19e70310747e4392754ad7446`. Source/hash checks и historical frozen0.23/0.24/0.25 payloads/Setup0.25 PASS. Python test-sign→Go verifier на Setup0.26 bytes PASS; test key только в памяти, **Setup unsigned и не исполнялся**.

Остаток: реальный AWG сервер с совместимыми параметрами, TUN+FreeTurn Direct/VK/egress/leaks/сеть/сон, длительные timers/rekey/cookies и телефоны. Все эти E2E NOT RUN. Не поддерживаются d/ds/dz/неизвестные CPS tags, выходящие за bounds значения и range Peer PersistentKeepalive; автоматического изменения таких конфигураций нет. Установленная0.24/рабочие ключи/iPhone/VPS не менялись.
