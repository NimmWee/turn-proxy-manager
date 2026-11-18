# Windows0.9: журнал, отзывчивость и закрытие окна

16.11.2026. Пользователь подтвердил: **VPN0.8 подключился и интернет работает**. Это user-confirmed E2E базового Windows-подключения, не приёмка routing/CAPTCHA/leaks/Direct failover. Затем сообщил о самопроизвольном запросе отключения/закрытия и попросил подробный журнал, иконку, более отзывчивый интерфейс и уборку проекта. Разрешил полностью менять будущий дизайн/навигацию; прежнее ограничение portrait/bottom для будущего редизайна отменено. Новые примеры пользователь ещё подбирает.

## Закрытие и причина проблемы

В коде этот вопрос показывался только в Window.Closing. Источник исходного события на компьютере пользователя **не установлен и не воспроизведён**; нельзя объявлять виноватым CAPTCHA или обновление без свидетельства. Добавлен native SC_CLOSE tracker и фиксированные записи источника: tray exit / крестик или Alt+F4 / программный или внешний запрос.

Новая политика: пока идут операции сохранения/подготовки, закрытие блокируется. При активном соединении неожиданный программный запрос игнорируется и журналируется, соединение продолжается. Крестик/Alt+F4 скрывает окно при доступном трее; явный «Выйти» из трея запрашивает отключение. Если трея нет, явный пользовательский close сохраняет возможность выхода с подтверждением. Идентификация SC_CLOSE не устанавливает личность отправителя Windows message; это UX-граница, не security authentication. Native synthetic Close() при simulated connecting больше не вызывает dialog и не закрывает окно — PASS; фактическая новая попытка пользователя NOT RUN.

## Подробные безопасные события

Изучены pinned upstream Android ProxyLog/LogFile/LogsScreen и core mobile.EventSink: Android получает OnLog, объединяет публикации120мс, держит200 строк экрана и отдельный файл. Windows раньше отбрасывал большинство сообщений и показывал смены состояний.

Теперь OnLog/OnState дают bounded journal: время до миллисекунд, INFO/WARN/ERROR, номер потока, фиксированные коды/описания DNS, авторизации VK, CAPTCHA, TURN и изменения числа потоков. Sequence/session устраняют дубли. Последние128 событий сохраняются в SYSTEM DPAPI runtime и доступны после закрытия UI/остановки службы; UI удерживает1000 строк. Поиск, фильтр уровня, автопрокрутка с объединением layout и экспорт добавлены. Очистка экрана не удаляет runtime history. Это не точная копия raw Android file logger: raw URL/tokens/keys/CID/обфускация в журнал не попадают; неизвестные шаблоны представлены безопасным warning/error. Это сознательная граница AGENTS.md.

Privacy regression:180 событий с synthetic secret/URL и разными stream IDs, ограничение128 и allowlist/IPC budget PASS. C# неизвестный secret-like code не отображает; номер потока проверен. Секреты текущего профиля не читались для сравнения логов и не менялись.

## Отзывчивость и идентичность

Вместо постоянного2с polling:250мс connecting,500мс connected,3с idle. Часы UI обновляются локально250мс. Core snapshot проверяется250мс, но DPAPI writes объединяются: неизменённые данные не переписываются4 раза/с. IPC reader читает блоками1024 символа, а не по одному; limit64KiB остаётся. Это улучшение задержки отображения и локальной обработки, **не измеренное ускорение VPN**. Transport/MTU/keys не менялись, bandwidth benchmark NOT RUN.

Добавлена9-size ICO16–256 из существующего FreeTurn vector logo: Win32 EXE resource, WPF window и tray вместо стандартной системной иконки. Generator включён в соответствующий исходный архив; авторство исходного Android mark и лицензия сохранены. Полная переработка дизайна ещё не выполнена: требования записаны в ТЗ/план, ждём пользовательских примеров. Ориентиры: [Proton desktop](https://protonvpn.com/support/protonvpn-windows-vpn-application), [Mullvad desktop](https://mullvad.net/en/help/using-mullvad-vpn-app), [Microsoft icon guidelines](https://learn.microsoft.com/en-us/windows/apps/design/iconography/app-icon-design).

## Проверки

Go test/vet, native privacy journal/SCM/сохранность ключей, C# preparation/close-policy/formatter/catalog/DPAPI/AES-GCM checks PASS. Release build/publish0 warnings/errors. Published `--check-single-window`: unsolicited Close() при synthetic connecting, единое окно/вложенный back/busy guard/cleanup, локальный WebView composition PASS. `--check-desktop-ui`: tray registration/dispose/hide-show/font PASS. Это local/synthetic, не управление реальным соединением. Published offline route/service digest unchanged, read-only установленный SYSTEM IPC PASS. Baseline23 SHA/vendor package PASS. Windows0.9 VPN/UAC/CAPTCHA/leak/sleep/network-switch E2E — **NOT RUN**; установленная служба и другие VPN не менялись. Нет VPS/GitHub/subagents.

Пакет `FreeTurn-Windows-0.9.0-preview-win-x64.zip`:83.50MiB,15 entries/14 payload hashes/98 corresponding source files проверены,62 dependency notices. SHA256 `5343a0dd36c33b21560bd270d8adcf520792e6a39b9f2f92546f808872636777`.

## Уборка

14 исторических Windows отчётов перенесены в docs/history/windows, добавлены два индекса; относительные ссылки обновлены, broken local links0. Старые release ZIP, лицензии, lockfiles, исходники, vendor и рабочие приватные данные сохранены. QA previews/reports сгруппированы в logs/windows-0.9;4 неиспользуемых staging файла (старый QR notice и XML documentation) архивированы отдельно, release manifest не менялся.

Удаление generated bin/obj было **дважды отклонено автоматической проверкой**: сначала пакетные вычисляемые цели, затем4 явных проверенных literal paths без reparse points. Ответ: `blocked by policy`, дополнительной причины инструмент не сообщил. Удаление не выполнено и другим shell/API не обходилось. Более безопасная обратимая операция разрешена:394.13MiB build outputs перенесены из ui/catalog-check в игнорируемую `.local-cache/windows-build`. **Место на диске этим не освобождено.** Web dependencies/venv и нужные upstream checkouts не удалялись.

Следующий основной блок по ТЗ после стабилизации — общесистемный domain/app routing и DNS. Нынешние domain rules продолжают действовать только для SOCKS5; общесистемная маршрутизация этим релизом не объявлена реализованной.
