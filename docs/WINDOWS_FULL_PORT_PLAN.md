# Полный перенос FreeTurn Android на Windows

**Актуальное сокращение объёма17.11.2026:** по прямому решению пользователя Windows больше не требует hotspot/LAN sharing, UDP/IPv6 для SOCKS, измерителя задержки, дополнительных языков и полного переноса дополнительных Android-настроек. Администрирование VPS/пользователей/доступов выполняется в веб-dashboard; server management из Windows исключён. Уже реализованные функции сохраняются. Основной VPN/managed/routing/DNS/защита, installer/updater и реальные проверки остаются обязательными. Это уточнение приоритетнее формулировок «весь функционал» и исторических оценок ниже; требования Android не изменяются.

15.11.2026. Новое направление пользователя: сохранить весь функционал Android-приложения, адаптировать его к Windows. Ограниченный MVP0.1.1 — промежуточный стенд, не конечный клиент. Этот документ фиксирует проверенный исходник и объём переноса, не объявляет функции реализованными.

Пользователь затем подтвердил начало реализации и перенос самого дизайна. В0.2 начаты каталог серверов, первые Material-экраны и штатный experimental CAPTCHA path; [фактический объём и проверки](history/windows/WINDOWS_CAPTCHA_AND_DESIGN.md). Матрица0.1.1 ниже остаётся исходным сравнением, не текущей суммарной готовностью.

## Закреплённый исходник

Repository: https://github.com/hackdiaz-dev/turn-proxy-android

Commit: `bab60c5fb620cbea2570eeeb5a0697dc355071f4`, Android version **5.3.4**. Проверен после `git fetch origin main`. Старый локальный checkout `be516f1122ac38523203dbffde8603a8b3e755fc` имеет version5.3.2: для матрицы ниже читался именно новый commit через `git show`, не старое рабочее дерево. Дальнейшие upstream updates — отдельное решение, без автоматической подмены эталона.

Проверенные источники: README, `ui/navigation/Routes.kt`, `data/server/Server.kt`, `data/config/ClientConfig.kt`, `data/config/CoreConfigJson.kt`; дерево `data/`, `domain/`, `ui/screens/`. Лицензия Android GPL-3.0: при переносе его кода сохранять copyright/license notices и включать соответствующий исходный код; не приписывать себе авторство исходника. Серверный `vendor/vps/` не менять.

## Подход

Сохраняются модель приложения, пользовательские сценарии, значения и формат совместимых настроек. Переиспользовать исходную бизнес-логику/модели/ресурсы, где возможно; адаптацию платформенных зависимостей отделять от неё. Текущий исправленный Windows engine/IPC/DPAPI остаётся опорой системной части, пока конкретный режим не требует другого backend. Не переписывать VK auth и CAPTCHA отдельно от штатного core. Одна подписанная WireGuardNT DLL сама по себе не даёт AmneziaWG, per-app routing или tethering.

Сравнены три пути: запуск APK через эмулятор не даёт нативного системного VPN Windows; урезанное WPF-окно уже не соответствует запросу; выбран полный перенос сценариев/логики с отдельными Windows adapters. Простое отображение Android-переключателей без Windows-исполнителя не считается переносом.

Сохранять навигационную структуру Android: Соединение, Логи, Поделиться, Добавление, Настройки; дочерние экраны выбора режима/клиентской конфигурации/серверов/SSH/управления сервером/продвинутых параметров/о приложении. Desktop layout адаптируется к размеру окна; функциональные настройки не исчезают.

## Матрица полного переноса

Актуализация0.6.0: custom domain DIRECT/VPN/BLOCK и DNS path intent реализованы для **SOCKS5 TCP/IPv4**, c IDNA/PSL/precedence, DPAPI/backup и отдельным внутренним DIRECT relay в tunnel-service SID. Code/local tests PASS, live egress/system flow routing **NOT RUN**. Это не системный SplitTunnelSheet backend и не закрытие presets/T29–T31. [Проверки и границы](WINDOWS_ROUTING.md).

Актуализация0.5.0 от16.11.2026: пользователь исключил Windows QR/камеру. QR controls, codec и ZXing удалены из новой сборки, текстовые URI/файл/буфер и backup сохранены. Это согласованное сокращение Windows scope, а не незавершённая задача. Переработаны главная, server sheet, четыре категории настроек/дочерние страницы, формы/списки/переключатели; добавлен встроенный Roboto и исходные векторные иконки. [Результат, реальные локальные проверки и остаток](history/windows/WINDOWS_DESIGN_PARITY.md). Исторические оценки0.1–0.4 ниже не являются состоянием0.5.

Актуализация0.4.0: добавлены QR image/clipboard/PNG, encrypted backup/restore и Android v4 payload import с сохранением исходника; Direct/Relay transport/obf и loopback TCP/UDP/KCP/Bond, SOCKS5 TCP/IPv4 через подтверждённый WG; SSH settings/host pin/auth check, tray/opt-in UI autostart/retry, traffic rates и light/dark. Код и локальные проверки описаны в `WINDOWS_OFFLINE_COMPLETION.md`. Это не подтверждение реального транспорта/egress. AWG, native routing/split DNS/BitTorrent, server installation/access control, camera/hotspot/updater/полный preferences parity ещё не реализованы. Таблица0.1.1 ниже — исторический baseline, не актуальная оценка0.4.

Актуализация0.3.0: каталог/clone/select/rename/delete уже есть в0.2; добавлен вертикальный редактор поддерживаемого профиля с engine validation и сохранением исходных секретов. DNS resolver теперь редактируется. Нижняя навигация/безопасный журнал/экспорт собственной ссылки также реализованы. Таблица ниже сохраняет исходную оценку0.1.1; актуальные код/локальные сценарии/NOT RUN — в `PROGRESS.md`, `WINDOWS_PROFILE_EDITOR.md` и `WINDOWS_BOTTOM_NAVIGATION.md`. Полный формат остальных режимов, QR/backup/SSH и Windows VPN E2E ещё не завершены.

| Блок исходника | Windows-результат | Состояние0.1.1 |
| --- | --- | --- |
| Server/ServersSnapshot/ServerJson | Несколько именованных серверов, выбор активного, сохранение после перезапуска | Один профиль |
| ServersList/ServerDetail | Добавить, редактировать, клонировать, удалить; отмена не меняет сохранённое | Нет |
| FreeturnLink/ImportViewModel | Совместимый полный формат ссылок и редактирование импортируемой конфигурации | Только текущий VK/UDP/rtpopus3/WG subset |
| QR scanner/share result | QR и камера исключены из Windows scope16.11.2026; передача текстовой ссылкой/файлом сохранена | Исторически нет; QR больше не требуется |
| ClientConfig/ConnectionMode | Relay/Direct, параметры соединения/потоков/transport/local listener | Фиксированный Relay/TCP/UDP listener |
| ProxyOrchestrator/ProxyEngine | Управление жизненным циклом, отмена, reconnect, явные ошибки, реальное состояние | Первый WG path, VPN E2E NOT RUN |
| WireGuard | Настоящий Windows VPN, DNS/IPv6, cleanup и штатная диагностика | Код есть, live E2E NOT RUN |
| AmneziaWG/config keys | Native backend, сохраняющий поддерживаемые AWG extensions и wire-совместимость | Нет; WGNT не подменяет AWG |
| SOCKS5/локальный proxy | Сохранить существующий TCP/IPv4 proxy; UDP/IPv6-расширение исключено пользователем17.11 | Исторически нет отдельного пользовательского режима |
| DNS config | Carrier/custom DNS, plain/DoH/auto и сохранение выбора | Только импортируемые параметры core |
| SplitTunnelSheet/SplitTunnelRule | Include/exclude по Windows-программам, общие и серверные правила | Нет; нужны реальные per-flow Windows adapters |
| SettingsBackup/BackupCrypto | Совместимость формата, пароль, import/export и откат при плохом файле | Нет клиентского backup; SYSTEM DPAPI не является экспортом |
| TrafficMeter/PingMeter | Сохранить показатели соединения/трафика/скорости; PingMeter исключён пользователем17.11 | WG bytes, статусы handshake/egress |
| LogsScreen/ProxyLog/SshLog | Просмотр/фильтр/очистка/экспорт диагностик с редакцией секретов | Raw core logs намеренно не выдаются |
| ShareRepository/ServerControl | Локальная передача своего профиля сохраняется; администраторская выдача/список/отзыв — веб-dashboard, Windows-перенос исключён17.11 | Исторически нет |
| SSHManager/SSH host key trust | SSH-учётные данные в защищённом хранилище, host key pin, понятные ошибки | Нет |
| ServerSetup/ServerSetupRepository | Исключён из Windows17.11: администрирование VPS через веб-dashboard | Исторически нет; legacy installer не запускать поверх FTM |
| AppPreferences/Theme/Language/Privacy | Сохранить имеющиеся настройки и защиту секретов; дополнительные языки/полный набор Android preferences исключены17.11 | Русское окно, без полного набора |
| CAPTCHA | Штатная автоматика, manual fallback, отмена и корректное закрытие | WebView2 code есть; live CAPTCHA NOT RUN |
| AppUpdater/About | Собственные Windows updates, версия/лицензии/ссылки, сохранение данных | Версия/лицензии есть; updater нет |
| ExternalControl/quick actions | Windows tray/control, безопасное подключение/отключение, автозапуск по выбору | Только главное окно/служба |
| HotspotOptions | Исключён из Windows scope и приёмки пользователем17.11 | Исторически нет |

Функции Android, относящиеся к мобильной ОС (VpnService permission, package IDs, foreground notification, Quick Settings tile, battery optimization, haptics), заменяются конкретными Windows equivalents. Это не причина скрыто выбросить соответствующий пользовательский сценарий. Различия tethering, per-app routing и AWG документировать до выбора backend; не объявлять паритет по одному внешнему сходству.

## Последовательность реализации

1. Перенос моделей/сериализации и совместимости импортов; защищённый каталог серверов, CRUD/clone/select и миграция уже сохранённого0.1.1 профиля без смены ключей. Не хранить secret server/SSH config в открытом UI JSON.
2. Навигация и настоящие экраны Соединение/Серверы/Добавление/Настройки на этой модели. Неподдерживаемый backend выдаёт конкретную причину, не фиктивный успех.
3. Полная конфигурация core, Relay/Direct/proxy, статистика/диагностика, штатная CAPTCHA. Закрытый IPC расширять фиксированными операциями; нельзя принимать команды, произвольные системные пути или hooks от UI.
4. Windows WG/AWG/network lifecycle, per-app routing, DNS/IPv6; целевые реальные проверки на выделенном профиле. Существующие рабочие телефонные ключи и чужие VPN не менять.
5. Text share, клиентский backup/restore, сохранение имеющихся SSH/tray/autostart/тем и защиты секретов, Windows installer/updater. QR, server management, hotspot, UDP/IPv6 для SOCKS, latency meter и полный перенос дополнительных preferences/языков исключены пользователем из Windows scope. Стандартный Android server installer не запускать поверх FTM managed peers.
6. Пройти матрицу на Windows, отмечая код/локальную проверку/реальный сценарий отдельно; исправить ошибки, затем выпускать полную сборку. Ни сборка UI, ни обещание переноса не закрывают VPN E2E.

Автотесты только для существенных рисков: сохранность ключей при миграции/клонировании/backup, права IPC, отмена сетевых изменений и cleanup. Для обычных экранов — сборка и рабочий сценарий. Без субагентов, без публикации GitHub. На текущем ПК установку/переключение туннеля пользователь оставил себе; исследование полного переноса этого решения не меняет.

## Условия готовности

Каждая строка матрицы получает рабочую Windows-реализацию либо явно согласованную платформенную замену. Скрытое исключение строк не допускается. Полный перенос нельзя объявлять завершённым, пока WG/AWG/Direct/Relay/proxy, импорт/backup, права и маршрутизация имеют только UI или mock. Новые возможности FTM из ТЗ (управляемые подписки, bootstrap, доменные presets) учитываются отдельно: они не возникают автоматически при копировании Android5.3.4.
