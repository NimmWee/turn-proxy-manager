# Ночная работа18.11.2026

Итог ночного окна до 08:00 Asia/Tomsk (01:00 UTC) 18.11.2026. Работа выполнялась без субагентов, реального VPN/VPS/UAC и установки. Окончательная отметка остановки и автоматизации приведена ниже.

## Что реализовано

1. Настоящий loopback core transport benchmark: Direct/TURN TCP/UDP, DTLS+rtpopus3,1/2/4/6/8 streams, throughput/RTT/loss/CPU/alloc.90 paced фаз:562440/562440 echo без потерь;36 overload фаз выявили потери. CPU/alloc profiles и временный Pion single-copy A/B:7.79% меньше alloc всего стенда при matched100Mbps, устойчивое ускорение интернета **не доказано**. Поставляемый pinned core не менялся. [Измерения/ограничения](CORE_LOCAL_BENCHMARKS.md).
2. Windows0.25→0.26/0.27: bounded AWG1–3 parser→существующий userspace backend, H ranges/S3/S4/CPS/header protection/CPA/timers/booleans. Explicit system-routing opt-in, запрет WGNT downgrade, strict managed WG-only/recovery/privacy guards, UI protocol и DPAPI/encrypted backup сохранность. Настоящие encrypted loopback TCP/UDP/handshake и1252B UDP, wrong header key refusal PASS. Это не живой FreeTurn+AWG сервер/TUN/VK E2E. [Поддерживаемое подмножество](WINDOWS_AWG_26.md).
3. Русский Windows Setup: icon/shortcuts/uninstall, fixed protected directories/marker/DACL, проверка closed UI/idle owned services, сохранение всех профилей.0.27 усиливает own partial uninstall и query-first/exact startup cleanup. Новый root install guard запрещает передать retained SYSTEM-DPAPI data другому Windows SID после удаления служб; unknown unowned data не усыновляются. [Поставка](WINDOWS_INSTALLER_PLAN.md), [security hardening](WINDOWS_SETUP_HARDENING_27.md).
4. Отдельный offline Ed25519 release/artifact verifier и CLI: out-of-band public key, canonical/channel/origin/version/sequence/TTL и exact size/SHA/MZ. Python test-sign→actual Go CLI на байтах Setup PASS; test private key только в памяти, установщик не запускался. **Это не подключённый updater**: production trust/feed/downloader/staging/durable fence/UI/install flow отсутствуют. [Протокол/остаток](WINDOWS_UPDATE_PROTOCOL.md).

## Готовая локальная поставка

- Latest: `clients/windows/artifacts/FreeTurn-Setup-0.27.0-preview-win-x64.exe`,79.54MiB, **unsigned preview**, SHA256 `003c9b0512bfc3e1f2f60ed633c98f785319c38e19d8f84d300950f379e6d9c4`.
- Portable ZIP: `FreeTurn-Windows-0.27.0-preview-win-x64.zip`,90.45MiB, SHA256 `39916251412f85cf85dbd63b7cb6c2c5d99adf5dddfb65ae06f880b7b0cfec73`.
- Corresponding app sources215files/81notices и отдельные Setup sources10files+license включены. Source/hash verifiers PASS. Frozen0.23–0.26 ZIP/Setup сохранены. Ничего не публиковалось/не отправлялось в GitHub.

## Что проверено и что не запускалось

Full Go test/vet/release build/WPF publish, C#→actual Go metadata/builders/routing regressions, DPAPI/encrypted backup, targeted ownership/CPS/crypto/ordering/ACL guards PASS. Isolated temporary HKCU test-key проверил preserve foreign/delete exact own; настоящий Run key не использовался, fixture удалена. Query-only actual SCM guard READY, cache mutation refused17, routes/adapters/services digest unchanged. Baseline23files и runtime package checksums PASS.

**Не запускались:** Setup/UAC/настоящие install/upgrade/uninstall/reinstall/VM, реальный Connect/переключение/отключение других VPN, SSH/VPS/deploy/reboot, новые Android/iPhone/Windows egress/leak/sleep/long timers E2E. Установленное ядро осталось0.24, tunnel Stopped; рабочие ключи/iPhone/данные сохранялись. Локальные проверки не заменяют эти gates.

## Остаток после ночи

- Пользовательская/clean VM приёмка Windows и installer: WG+FreeTurn, совместимый AWG-сервер, Direct/VK/TUN/egress/DNS/IPv6/leaks/recovery/sleep/crash, смена владельца/partial install/uninstall/repair. Не все upstream AWG params поддерживаются; managed v1 пока WG.
- Доверенный updater: настоящий public key/feed/channel, protected trust+revision persistence, bounded downloader/staging/UI согласие/запуск/rollback, подпись издателя при наличии сертификата. Remote updater не включён.
- Большие этапы ТЗ: native managed Android/APK, оставшиеся dashboard subscriptions/VPN/settings/history monitoring, общий Manager clean-host install/upgrade/repair/migrate/uninstall/restore/web wizard, multi-client/resource/fault проверки. Управление VPS из Windows, QR/hotspot/дополнительные исключённые функции и постоянная блокировка сети не возвращаются.
- Скорость: настоящие Direct/VK/WGNT/system/VPS benchmarks и интеграция только подтверждённых оптимизаций; полный редизайн остаётся отдельным согласованием.

Новые данные/внешние проверки спящему пользователю не запрашивались. Подробный текущий остаток — [REMAINING_WORK.md](REMAINING_WORK.md).

## Финальная передача

В последнем heartbeat повторно проверены Setup 0.27 SHA/source correspondence/frozen payload и SHA256 portable ZIP — PASS; Setup не исполнялся. Незавершённых процессов сборки или verifier для этого workspace не обнаружено. Служба FreeTurnManager работает, WireGuardTunnel$FTM остановлена; их состояние не менялось.

Добавлен [порядок ручной приёмки Windows 0.27](WINDOWS_ACCEPTANCE_0_27.md): сохранность профилей, реальное подключение и применение настроек, установка/удаление и проверка владельца на VM. Все эти реальные сценарии по-прежнему NOT RUN. Новые версии и функции в финальном heartbeat не начинались.

Работа остановлена 18.11.2026 в 07:43 Asia/Tomsk (00:43 UTC), до установленного предела 08:00. Ночная автоматизация `freeturn-manager` удалена через Codex Automations; инструмент подтвердил `deleteStatus: deleted` в 07:42:38. Дальнейшее продолжение — по новому поручению пользователя.
