# Windows0.19.1: падение браузера CAPTCHA

17.11.2026, Asia/Tomsk. Без субагентов, подключения VPN, обновления установленных служб, VPS и GitHub. Применяются systematic-debugging, targeted regression и проверка результата; план фиксируется до исправления.

## Подтверждённое наблюдение

Пользовательский экспорт создан22:23, содержит последние128 событий старой сессии до22:07:47 (32 потока, CAPTCHA и сетевые таймауты). Windows Application Error1000 и .NET Runtime1026 в22:08:21 фиксируют FreeTurn.Windows0.18.0, exception e0434352: System.ObjectDisposedException → WinRT.IObjectReference.ThrowIfDisposed → ABI.System.IDisposable.Dispose → Microsoft.Web.WebView2.Wpf.GraphicsItemD3DImage.ReleaseDevices → Dispose(false) → Finalize. Это необработанное исключение finalizer thread, не установленная причина отказа TURN/сервера. Дамп сохранён ОС; его содержимое не публикуется/не переносится в Git. Конкретный триггер внутри SDK (display change/частичная инициализация/освобождение) пока не доказан.

## Решение

Удалить из CAPTCHA путь WebView2CompositionControl/GraphicsItemD3DImage: использовать штатный WPF WebView2, в том же MainWindow. Reflection-патчи внутренних ресурсов SDK, отключение GC/finalizers и глобальное подавление фатальных исключений не подходят. Пакет WebView2 не обновлять без доказанного исправления.

Классический HWND-контрол не подчиняется WPF opacity: автоматический браузер явно Hidden, ручной Visible. JavaScript, crypto и navigation должны работать в скрытом браузере. Оставить private profile, cookie clear, отсутствие сохранения паролей/autofill, блокировку новых окон/download/permissions и ограничение навигации локальным8765/about:blank. Инициализацию coalesce; после каждого await проверять закрытие. Dispose один раз до удаления из visual tree; late initialization не должна создавать закрытый browser заново.

## Шаги

- [x] Добавить native child-process stress: local about:blank/crypto, repeated init→close→GC/finalizers, ранняя отмена и двойное закрытие. Проверить baseline, не объявлять невоспроизведённый crash воспроизведённым.
- [x] Заменить host/presentation/lifetime; проверить скрытый JS и ручной интерфейс в одном окне.
- [x] Собрать отдельный package-0.19.1, проверить native stress/single-window и сборку; прежние0.18/0.19 packages оставить неизменными.
- [x] Зафиксировать причины, реальные результаты и границы. Live VK/CAPTCHA/VPN soak — NOT RUN.

## Источники

Основное доказательство — локальные события1000/1026. Локально изучена зафиксированная Microsoft.Web.WebView2.Wpf1.0.4314.35: GraphicsItemD3DImage finalizer вызывает Dispose(false), ReleaseDevices освобождает WinRT device. Decompiled SDK остаётся только в ignored .local-cache.

[Microsoft: WebView2 composition lifetime](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.wpf.webview2compositioncontrol?view=webview2-dotnet-1.0.4314.35), [Microsoft: controller visibility](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2controller.isvisible?view=webview2-dotnet-1.0.4314.35). Публичные похожие issue не доказывают исправление именно этого crash.

## Результат

В0.19.1 CaptchaWindow создаёт стандартный WPF WebView2. D3DImage/composition host не создаются. Automatic HWND явно Hidden; manual Visible в прежнем MainWindow. Инициализация single-flight; после environment/controller/cookie await проверяется disposed, Dispose до detach, повторный Close не повторяет отмену. Private mode и прежние local navigation/permissions/download/new-window/password ограничения сохранены. Глобального подавления finalizer exception, отключения GC или reflection-патчей в продукте нет.

**Реальные проверки:**

- Исходный composition host прошёл12 local cycles с GC: конкретный crash в коротком baseline прогоне **NOT REPRODUCED**. Подтверждение падения пользователя — события Windows1000/1026; конкретный триггер SDK остаётся неизвестным. Исправление убирает сам зафиксированный аварийный путь, без заявления о воспроизведении длительной VK-сессии.
- Новый host: native local12 cycles PASS (8 complete +4 early cancel), about:blank DOM/crypto, таймер в скрытом браузере, manual visibility, double close, exactly-once cancellation, forced GC/WaitForPendingFinalizers между циклами. Отмена pending controller возвращает ожидаемый E_ABORT; native check допускает его только после явного cancel. Это не доказательство работоспособности реальной VK CAPTCHA или её скорости в скрытом режиме.
- Final packaged0.19.1 native lifetime и single-window/nested/busy/editor/close checks PASS, services=false/networkChanged=false. Такой же локальный прогон выполнен до упаковки. MainWindow остаётся единственным видимым WPF-окном; это не тест live URL.
- Go test/vet/build, WPF publish, C# crypto/catalog/settings/claim/sync/LKG fake checks, Python→Go managed/enrollment contract PASS. В ходе сборки обнаружен независимый сбой DNS test fixture: TCP ephemeral495xx попадал в UDP exclusion49482–49581. Дважды воспроизведён bind отказ. Fixture теперь выделяет TCP/UDP отдельно и сохраняет прежние проверки logical DNS target/path; focused check и полный Go checks PASS. Резервации/настройки ОС не менялись, runtime DNS code не изменён.
- Offline route/adapter/service digest unchanged; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK. Baseline23/vendor verifier PASS. Службы/пользовательские профили/ключи/VPS не менялись, реальное подключение не запускалось.
- ZIP 86.21MiB/16 entries/15 payload SHA/190 bundled sources/81 notices; SHA256 `74565368b8c3728ce2f8415c1fc30ae9d638e363d4a6a147cd5375cc24b86d7d`. Payload hashes/source correspondence PASS.0.18 и0.19 ZIP и все их payloads побайтно сохранены. Новый output: `clients/windows/artifacts/package-0.19.1`.

**Открыто:** длительный VK/VPN/CAPTCHA/32 streams/sleep/display change E2E — NOT RUN. Конкретное условие, приведшее к SDK finalizer crash, не установлено. При повторном падении нужны новые события Windows и журнал соответствующей сессии; не выводить дампы/секреты.
