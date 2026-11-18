# Windows0.5: дизайн Android и исключение QR

16.11.2026, Asia/Tomsk. Выполнено по новому поручению пользователя: QR на ПК не нужен, интерфейс должен быть похож на исходный проект. Без субагентов, подключения VPN, установки/обновления служб, VPS и GitHub. Реальное подключение пользователь проверяет сам.

## Что изменено

Эталон — FreeTurn Android5.3.4, commit `bab60c5fb620cbea2570eeeb5a0697dc355071f4`. Сверены исходные `ConnectionHero`, `ConnectionStatsCard`, `ServersSheet`, `SettingsScreen/SettingsRows`, `AddServerScreen`, `Color/Type/Spacing`, vectors. Старый локальный checkout5.3.2 эталоном не использован.

| Экран/компонент | Реализация Windows0.5 |
| --- | --- |
| Главная | Отдельная expressive-кнопка148DIP, статус под ней, streams/uptime pill, самостоятельная статистика и нижний блок сервера. Убрана большая внешняя карточка вокруг кнопки |
| Состояния | Idle scalloped/play, busy/spinner, connected circle/check и error. Вращение в busy с учётом системного разрешения анимации. Snapshot-состояния синтетические, не результаты VPN |
| Навигация | Вертикальное окно480×860 с подстройкой по экрану, минимум420; пять исходных вкладок снизу, filled/outlined vectors, desktop focus/hover и Ctrl+1…5 |
| Настройки | Четыре категории Серверы/Приложение/Продвинутые/О проекте. Отдельные дочерние страницы с возвратом. Backup/оформление/Windows — в Приложении, CAPTCHA/SOCKS/службы — в Продвинутых |
| Формы и списки | Группы с общими внешними и малыми внутренними скруглениями,40DIP icon tiles, switch rows, единые inputs/dropdowns. Переработаны Добавить/Поделиться/Логи, список серверов и редактор |
| Типографика/ресурсы | Встроенные Roboto Regular/Medium/Bold с кириллицей, исходные29 Android vectors и логотип. Fonts не устанавливаются в ОС, SHA256 закреплены в dependencies.json, Apache2 license в пакете |
| QR | Удалены controls генерации/PNG/импорта, codec, NuGet ZXing и его notice/проверки. Text URI/файл/буфер и encrypted backup сохранены. QR/камера исключены только из Windows scope, не телефонного/серверного |

Изменены `MainWindow`, `ConnectionPages`, `ServersWindow`, `ProfileEditor`, `Theme.xaml`, `UiTheme`, `BottomNavigation`, `App`; добавлены `AndroidSkin`, `ExpressivePower`, `DisplayConverters` и fonts. IPC/engine/DPAPI-контракт и криптография backup этим изменением не переписывались. Не добавлялись декоративные кнопки для ещё не реализованных серверных действий.

Это перенос композиции и компонентов, не заявление о пиксельном совпадении Android Compose: контуры Cookie/Sunny адаптированы WPF geometry, точный Android morph-движок не перенесён; titlebar, file/message dialogs остаются Windows. Полный набор prefs/languages и отсутствующие backend не объявляются реализованными ради внешнего сходства.

## Реальные проверки

- `build.ps1 -GoExecutable C:/VPNN/.toolchains/go/bin/go.exe -SkipPrepare`: PASS. Go test/vet, подпись WireGuardNT, pinned font SHA256, locked self-contained Release publish;61 dependency notices.
- `dotnet run --project clients/windows/catalog-check/CatalogCheck.csproj -c Release`: PASS. Неправильный пароль/подмена AES-GCM, merge/retry restore, DPAPI, сохранность ключей при clone/edit, дубли, selection invalidation, изоляция удаления и отказ при порче. QR checks удалены по scope.
-19 offline renders:480 main/settings обеих тем;420 main/settings обеих тем, add/share/logs/app/advanced/about/connected/busy/servers/editor и editor-light. Просмотрены ключевые экраны. Это собственные синтетические профили, без чтения private catalog/службы и запуска туннеля.
- Native editor: открыт dropdown VK Relay/Direct, выбор Direct отключил VK/TURN-поля; текст/список читается в тёмной теме. Отмена закрыла форму без сохранения.
- `--check-desktop-ui`: PASS, tray register/dispose, hide/show и фактический embedded Roboto с Cyrillic glyph. ServicesUsed=false, NetworkChanged=false.
- `verify_offline.ps1`: PASS, synthetic import/guards, route+adapter+service digest неизменён. Preflight безопасно отказал из-за другого VPN/nonphysical uplink; этот VPN не отключался.
- `verify_service.ps1`: PASS, обычный непривилегированный процесс аутентифицировал существующий SYSTEM broker и прочитал только status; stopped/HasProfile=true. Установленная служба0.1.1 не заменялась.
- `verify_baseline.py`:23 SHA PASS; vendor package verifier PASS. Baseline не изменён.

Архив `clients/windows/artifacts/FreeTurn-Windows-0.5.0-preview-win-x64.zip`:77.22MiB,14 entries/13 проверенных SHA256,69 исходных файлов совпадают с workspace; ZXing, QR codec, preview-изображения и приватные файлы не включены. SHA256 `ac617295f77a25fca3a0bbde1b3eae012456127a49eaf0b2dcc9bd65381f670d`. Собственные EXE пока без подписи; WireGuardNT официальный подписанный. Сборка лежит отдельно, установленное пользователем приложение не заменялось.

## Что осталось

1. Windows per-flow routing: домены/программы, RU/LAN direct, YouTube/push VPN, connectivity direct, split DNS и BitTorrent enforcement. Android-настройки или DNS-поле сами не дают эти правила Windows.
2. Native AmneziaWG backend: WireGuardNT не поддерживает его расширения.
3. Managed enrollment/bootstrap/subscription updates и безопасный автоматический Direct↔Relay fallback. Ручные режимы и bounded retry уже есть, managed-интеграции ещё нет.
4. Установка/управление VPS, список доступов и выдача/отзыв из Windows. SSH settings/pin/auth check уже есть; проверка входа не является серверным installer.
5. LAN/hotspot, UDP/IPv6 для SOCKS, latency meter, полный набор языков/privacy/system-theme prefs, подписанный установщик/updater.
6. Реальные Windows VPN/CAPTCHA/egress/DNS+IPv6 leaks, reconnect при смене сети/sleep-resume, cleanup/uninstall и чистые Windows10/11: **NOT RUN**, остаются самостоятельной проверкой пользователя. Android/iPhone E2E новой версии также **NOT RUN**.

QR/камера больше не входят в оставшийся Windows scope. Серверные этапы общего проекта не закрываются этим UI-релизом; их статус остаётся в PROGRESS.md. Следующий независимый большой блок — проектирование Windows routing backend, затем реальная проверка его правил; это отдельная работа, не скрытая часть визуального переноса.
