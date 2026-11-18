# Windows routing: первый исполняемый блок

16.11.2026. Продолжение по поручению пользователя; без субагентов, live VPN/служб/VPS/GitHub. Применяются brainstorming/writing-plans/executing-plans; уже согласованные требования и разрешение продолжать не требуют повторного согласования. Текущая ветка сохраняется вместе с незакоммиченными изменениями.

## Решение

Полный системный per-flow router требует TUN/netstack или WFP backend. Простые WG AllowedIPs/одноразовые IP routes по DNS не различают домены на shared CDN; ослабление штатного firewall ради такого обхода не принимается. Отдельный системный backend остаётся следующим этапом.

Доступный независимый блок — доменная политика для существующего authenticated loopback SOCKS5 TCP/IPv4. Пользователь добавляет домены с действием VPN/DIRECT/BLOCK и флагом поддоменов, проверяет решение локально; default VPN. Это явно SOCKS scope, не маршрутизация всей системы. Presets RU/LAN/YouTube/push/BitTorrent/GeoIP пока не включаются без исполнителя и проверенных списков.

Граница: BLOCK до DNS; наиболее специфичное domain-boundary exact/suffix правило, любой совпавший BLOCK выше разрешений. IDNA/PSL, до300 правил, конфликт/дубли/ошибки до сохранения; IP literals не получают доменный DIRECT. DNS и TCP выполняются только выбранным dialer, без межмаршрутного fallback. VPN dialer привязан к WG LUID+source; DIRECT — к physical LUID+source и его DNS, с отказом при смене/удалении. Private/LAN/metadata destinations запрещены на обоих путях. При потере подтверждённого VPN закрывается весь SOCKS, включая DIRECT. Логи доменов не ведутся.

Проверка исходного firewall выявила обязательную поправку: `permitWireGuardService` привязан к SID именно tunnel service, не ко всем SYSTEM-процессам того же EXE. Поэтому DIRECT dial выполняется внутри tunnel process; broker передаёт только bounded hostname:port через отдельный SYSTEM/admin-only pipe. Оба конца сверяют PID/session0/SCM fixed binary/account/state. Impersonation=Anonymous. Без ослабления firewall/расширения исключений для broker. Physical LUID/source/DNS снимаются до VPN из уже выбранного underlay. Message-mode pipe сохраняет TCP half-close. Недоступность DIRECT relay не ломает прежний full VPN.

Политика — отдельная v1 модель внутри DPAPI proxy settings/encrypted backup, не изменение portable URI или server managed-v1. IPC capability `socks-domain-routing-v1`, проверка политики службой до listener, старые службы не должны молча игнорировать правила. Offline engine command для authoritative validation/preview не читает профили и не обращается к сети.

## Исполнение

- [x] Engine `routing_windows.go` + targeted tests: IDNA/PSL/precedence/conflicts/limits, blocked-before-dial и отсутствие VPN→DIRECT fallback. Сначала подтверждён RED (undefined types/functions), затем PASS.
- [x] Разделить interface-bound SOCKS dialer, добавить physical path с pin LUID/source/DNS и узкий внутренний relay в tunnel process. Routes/firewall не меняются; реальный egress NOT RUN.
- [x] Интегрировать policy snapshot в fixed `socks-start`, capability и offline `--check-routing`. Старый default VPN сохранён.
- [x] C# policy/checker + Russian domain editor, save отдельно от start, отказ на старой службе при правилах. DPAPI/backup roundtrip и key preservation PASS на synthetic catalog.
- [x] Build/Go test+vet/catalog checks, offline route digest/native read-only IPC, renders PASS. Пакет0.6,13 hashes/76 source files проверены; реальный egress/DNS/firewall NOT RUN. [Результаты](WINDOWS_ROUTING.md).

Целевые тесты — только routing/data/правовые границы; обычный UI — сборка/сценарий. Неподтверждённый live DIRECT egress не объявлять рабочим лишь по существованию кода.
