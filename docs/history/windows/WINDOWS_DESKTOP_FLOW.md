# Windows 0.8: одно окно и подготовка при подключении

16.11.2026, Asia/Tomsk. По поручению пользователя сохранены вертикальное окно и пять нижних вкладок. Убраны ручной переход к update службы из обычного подключения и отдельные окна встроенных разделов. Это локальная preview сборка, не подтверждение VPN E2E.

## Что изменено

Основной путь: добавить профиль → автоматически выбрать и вернуться домой → нажать подписанную кнопку «Подключить» → проверить authenticated SYSTEM broker и версию → только при необходимости вызвать прежний guarded setup с UAC → повторно проверить broker/версию → импортировать выбранный профиль → подключить. Актуальное ядро пропускает setup. Кнопка в трее использует этот же сценарий; Ctrl+Enter выполняет основное действие.

Отмена UAC, ошибочный/откаченный setup, недоверенный IPC, неизвестная версия и более новое установленное ядро прекращают цепочку до передачи профиля/подключения. Активный tunnel не обновляется и не отключается ради обновления. Фоновый retry не запрашивает UAC, прекращает повтор при необходимости ручной подготовки. Обновление берётся из текущего распакованного пакета, не скачивается из интернета. Привилегированный произвольный updater или обход UAC не добавлены.

Импорт и выбор сервера больше не требуют работающей службы. Сохранение при активном соединении добавляет запись без изменения выбранного сервера. При подключении используются данные локального выбранного профиля; профиль, известный только SYSTEM службе, не заменяется новыми ключами. Собственные guarded setup/owner checks и rollback сохранены. Ручное восстановление ядра остаётся в продвинутых настройках для ремонта.

Серверы, редактор профиля, SSH, резервные копии, выбор исходного Android backup, SOCKS5 и вложенная маршрутизация открываются в одном контейнере. Нижняя навигация остаётся доступной; «Назад»/Alt+← возвращает к предыдущей форме. Пока идут сохраняющие/проверяющие операции, уход и закрытие главного окна блокируются. Скрытые адаптеры Window не показываются и освобождаются при закрытии страницы; SOCKS timer останавливается.

CAPTCHA переведена на WebView2CompositionControl в основном визуальном дереве: автоматическая проверка загружена, но невидима/не принимает ввод; manual показывает тот же контрол внутри окна, отмена отключает текущую попытку. InPrivate/cookie cleanup и allowlist localhost:8765 сохранены; popups/downloads/permissions запрещены. Системные file pickers, UAC и подтверждения остаются штатными диалогами. [Microsoft о WPF Composition](https://learn.microsoft.com/en-us/microsoft-edge/webview2/platforms/wpf).

Для Composition понадобилась Windows SDK .NET runtime projection, отсутствовавшая при прежнем generic Windows target: переход на net8.0-windows10.0.17763.0 и фиксированный WindowsSdkPackageVersion10.0.17763.57. Сначала native local scenario выявил missing SDK assembly, затем блокировку NavigateToString строгим URI guard. Проверка использует разрешённый about:blank + локальный DOM/JavaScript; allowlist не ослаблялся. Лицензия SDK с официального URL включена в пакет, notice collector учитывает текущий TFM/SDK. Windows10 x64 1809+ / Windows11; чистая машина ещё не проверена.

## Основание UX

[Proton Windows](https://protonvpn.com/support/protonvpn-windows-vpn-application) документирует quick connect, сохранённые/недавние подключения и трей. [Mullvad desktop](https://mullvad.net/en/help/using-mullvad-vpn-app) отделяет основные действия подключения и выбора сервера от настроек. Применён этот принцип сценария; внешний вид оставлен компактным по явному выбору пользователя. Исходные иконки, шрифты, палитра и нижние вкладки сохранены. [План](WINDOWS_DESKTOP_FLOW_PLAN.md).

## Проверено

- Go test/vet, Release build/publish: PASS,0 warnings/errors.
-11 targeted synthetic callback scenarios: актуальная/старая/отсутствующая служба, отмена/ошибка UAC setup, newer/untrusted/active/retry, неверная версия после setup, SYSTEM-only профиль — PASS. Это проверка порядка вызовов/отказов, **не настоящий SCM upgrade**.
- Native WPF `--check-single-window` из опубликованного self-contained EXE: шесть встроенных форм, вложенный переход/result/back и busy refusal — PASS. Ровно одно видимое Window, закрытые адаптеры удалены из Application.Windows; bottom navigation доступна hit-test. Синтетические catalog/key fixtures, не пользовательские профили.
- В том же native сценарии реальный WebView2CompositionControl: инициализация InPrivate в отдельной временной папке, about:blank, изменение DOM и crypto.getRandomValues, opacity/input auto→manual, dispose без дополнительного окна — PASS. Это **не VK CAPTCHA/PoW E2E**.
- Просмотрены synthetic renders сервера/маршрутизации/главной. Полосы прокрутки не возвращались; нижние вкладки сохранены.
- Catalog/DPAPI/AES-GCM/backup/key-isolation checks: PASS.
- Published offline import/routing/foreground guards и digest маршрутов/адаптеров/служб: PASS/unchanged. Read-only authenticated IPC установленного broker: PASS, stopped/HasProfile=true. Нынешний preflight видит другой VPN, который агент не отключал.
- Baseline23 SHA и vendor package: PASS, vendor не изменён.

**NOT RUN:** настоящее повышение прав/UAC setup→connect, actual SCM upgrade/rollback0.8, VPN/TURN/WG/egress, VK CAPTCHA/PoW, чистые Windows10/11 и аппаратные leak/sleep/network-switch сценарии. Пользователь оставил подключение себе. Установленные службы, реальные профили/ключи, другие VPN и VPS не менялись; GitHub push и субагенты не использовались.

Архив `clients/windows/artifacts/FreeTurn-Windows-0.8.0-preview-win-x64.zip`:83.45MiB,15 entries/14 payload SHA256 и91 corresponding source files проверены;62 notices и SDK license включены. SHA256 `7667aabd8f980f747d0c3a2252f867b74404e0162683fbb1e6c12b6f36b06fa3`. Пользователю достаточно закрыть старый FreeTurn, распаковать полный0.8 пакет и нажать «Подключить» с прежним профилем: при необходимости появится UAC, ручного поиска update в настройках больше нет.
