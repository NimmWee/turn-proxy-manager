# Windows: исходный дизайн и новая CAPTCHA

15.11.2026. Пользователь подтвердил реализацию полного переноса, включая дизайн Android, и попросил глубже проверить экспериментальную автоматику CAPTCHA. Работа без субагентов; действующая копия0.1.1 и установленные службы не заменялись автоматически.

## Что обнаружено в исходниках

Android5.3.4, commit `bab60c5fb620cbea2570eeeb5a0697dc355071f4`:

- `AppPreferences.advancedCaptchaFlow`: глобальная настройка, default **false**.
- `SettingsScreen.AdvancedScreen`: «Продвинутое решение CAPTCHA». В описании — новый способ, который может стать основным в будущем. При manual CAPTCHA UI его не включает.
- `CoreConfigJson`: передаёт `autoCaptcha=true`, `advancedCaptcha=advancedCaptchaEnabled && !manualCaptcha`.
- Тема: `Color.kt`, `Shape.kt`, `Spacing.kt`, `Theme.kt`; тёмная palette: background `#111318`, surfaceContainerLow `#191C20`, primary `#AAC7FF`, onPrimary `#0A305F`, primaryContainer `#284777`. Доминирующий экран — центральная кнопка соединения, скруглённые карточки, отдельный выбор серверов и навигация.

В уже закреплённом FreeTurn core4.1.5 (`f6b1f25767755d9bf34cbf78818b74c5062d7d0c`) новое решение **уже присутствует**:

1. `vkauth/auto_solver.go`, `defaultAutoSolve`: при advanced flag получает актуальный браузерный PoW envelope через `powCapture`/`manual.CapturePowViaProxy`. На захват выделено30секунд.
2. Вызывает `captcha.SolveWithBrowserPow`. Отмена по context не превращается в бесконечный retry.
3. Ошибка захвата или решения приводит к прежнему `solveLegacyCaptcha`; это не обещание успешного решения любой проверки VK.
4. Штатная стратегия core выбирает автоматическое или ручное решение; `token_call.go` содержит bounded manual solver с timeout3минуты. Windows сохраняет эту логику и EventSink/WebView2, а не пишет отдельный solver.
5. Релиз4.1.5 также исправляет загрузку relative JS chunks manual CAPTCHA page. Успех на настоящем VK/Windows пока **NOT RUN**; upstream tests и feature flag не равны нашему E2E.

Главный найденный пробел0.1.1: Windows renderer всегда задавал `advancedCaptcha=false`. Недостаточно обновить подпись переключателя: нужны root options, новый service capability и реальная передача в mobile.Start.

Дополнительно изучен CHANGELOG: экспериментальный режим появился в Android5.3.0 (21.10.2026), вместе с background solving, очисткой cookies и созданием automatic WebView в VPN service. Android5.3.4 обновляет core до4.1.5. `ProxyService` создаёт отдельный временный WebView для automatic событий и освобождает его по завершении проверки/teardown. Это важная часть переноса: автоматический challenge не должен показываться как лишнее ручное окно.

## Что реализовано в0.2 development

- Go IPC: bounded boolean `advancedCaptcha` разрешён только для `connect`; на других операциях отвергается до обращения к системе. `status` объявляет `advanced-captcha-v1`.
- Root пишет выбранную опцию в отдельный SYSTEM DPAPI file; portable share URI, private key, PSK, CID и WG config от этого не меняются. Runtime применяет её к core JSON, manual всегда имеет приоритет. Штатный fallback остаётся в оригинальном core.
- UI показывает экспериментальную настройку с defaultfalse и сохраняет выбор в зашифрованном пользовательском каталоге. Старой службе новое поле не отправляется; UI сообщает о необходимой новой версии. Доступен сброс ранее сохранённой опции даже при откате службы на старую версию.
- Windows automatic WebView2 получает временное неактивируемое окно вне экрана, без taskbar; manual событие переводит его в видимое окно. На завершении challenge controller уничтожается; используется InPrivate. Это реализация background path, а её реальная работоспособность/тайминги браузерного PoW пока NOT RUN.
- Как в Android AutomaticCaptchaWebViewHostController, добавлен отдельный challenge ID: обычный status polling не перезагружает браузер; новая проверка с тем же URL получает новый controller. ID начинается с session epoch, cookies очищаются перед загрузкой challenge и при закрытии. Это не доказательство полного VK concurrency E2E.
- Начат перенос Material palette/layout: центральная кнопка, pill navigation, скруглённые surfaces, отдельные экраны Соединение/Добавить/Настройки и окно Серверов. Это первая часть дизайна; исходные Логи/Поделиться/SSH/QR и остальные экраны ещё впереди.
- Перенесены модели ClientConfig/Server/ServersSnapshot и их исходные defaults; эти модели ещё не означают поддержку всех transports/backend.
- Реальный локальный каталог нескольких подключений: CurrentUser DPAPI, Windows ACL, атомарная запись и previous ciphertext, выбор/переименование/clone/delete. Клон копирует параметры того же подключения и сохраняет ключи; он не выпускает отдельный доступ другого устройства. Удаление локальной записи не отзывает peer и не удаляет профиль службы.
- Импорт по-прежнему проходит настоящую проверку engine и authenticated SYSTEM IPC; после успешного импорта копия сохраняется в пользовательский каталог. Старый root-only профиль нельзя прочитать обратно в UI: он остаётся рабочим, а в каталог добавляется явным импортом исходной ссылки. Автоматического извлечения private keys из SYSTEM нет.
- Android GPL attribution/license включены; в пакет входит corresponding `Windows-Client-Sources.zip`, исходники и dependency locks.

## Реальные проверки

- Go: **8 целевых tests PASS**, включая конфликт manual/advanced, сохранность остальных полей core, отказ недопустимой IPC option и жизненный цикл challenge ID; Go vet PASS.
- Windows DPAPI catalog executable check: **PASS** round-trip, selection/settings persistence, clone key preservation, delete isolation, отсутствие plaintext в ciphertext, отказ перезаписывать повреждённое хранилище. Использован только временный synthetic каталог.
- WPF build/publish: **PASS**,0warnings/errors. Главный экран визуально просмотрен через собственный offline render (`--snapshot`); он не обращается к службе и не включает сеть.
- Реальный read-only ServiceClient к уже установленному broker0.1.1: **PASS**, `Elevated=false`, `HasProfile=true`, `State=stopped`. Это проверка обратной совместимости status, не deployment нового engine.
- Новая0.2 служба, browser PoW/manual CAPTCHA, настоящий выбранный профиль каталога через UI, WG handshake/egress: **NOT RUN**. Пользователь оставил переключение своего VPN себе; тестовый VPS и установленная копия на Desktop не менялись.

## Следующие части полного переноса

Полный ClientConfig editor и portable codec, ручная настройка/QR/share/backup, безопасное обновление собственных служб, полный набор Logs/Settings, поддержка Direct/proxy/AWG и настоящая per-app маршрутизация. Они не считаются готовыми из-за появления моделей или похожих кнопок. Живой CAPTCHA E2E — отдельно после обновления службы пользователем и разрешённого запуска туннеля.

Источники: [Android5.3.4](https://github.com/hackdiaz-dev/turn-proxy-android/tree/bab60c5fb620cbea2570eeeb5a0697dc355071f4), [auto solver](https://github.com/hackdiaz-dev/free-turn-proxy/blob/f6b1f25767755d9bf34cbf78818b74c5062d7d0c/internal/provider/vk/internal/vkauth/auto_solver.go), [core4.1.5 release](https://github.com/hackdiaz-dev/free-turn-proxy/releases/tag/v4.1.5).
