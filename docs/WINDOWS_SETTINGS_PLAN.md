# Windows0.18: применение сохранённых параметров

17.11.2026. Поручение: исправить сохранённые настройки, которые не доходят до подключения, проверить аналогичные случаи; продолжать техническую работу без субагентов и реальных VPN/SCM/VPS изменений.

## Причины и решение

1. `ProfileCatalog.Replace` сбрасывал ActiveId при редактировании выбранного профиля. `MainWindow.Apply` при пустом ActiveId передавал null в ServicePreparation, которая оставляла старый SYSTEM profile. Поэтому n/spc/DNS/transport и другие изменения оставались только в каталоге. Сохранить выбор при edit; другой профиль не выбирать автоматически. При существующем каталоге без выбора запретить неявный fallback на старую службу, открыть выбор сервера. Legacy service-only профиль допустим только при пустом каталоге.
2. Проверка остальных настроек: global checkbox автоматической CAPTCHA управлял только доступностью advanced solver, не передавал manual choice в core и не сохранялся. Добавить ForceManualCaptcha preference/connection option, передавать только через connect, применять при старте/path restart/config recovery. Manual из профиля имеет приоритет. Default false сохраняет прежнее поведение.
3. Direct в auto path намеренно использует1 поток; Relay должен использовать сохранённый n. Различать requested/effective/runtime ready counts. Передавать в status только безопасные числовые/enumerated параметры фактически подготовленного core, показывать их в UI. Не выдавать ключи/CID/ссылку/конфиг через диагностику.
4. DNS полей редактора относится к control-plane resolver FreeTurn, а DNS трафика VPN находится в WG Interface. Пояснить различие; SOCKS/routing требуют собственного stop/start/reconnect, theme — restart UI. Не обещать hot apply при сохранении.
5. Защитить сохранение после async validation от изменения исходного share другой операцией. Рабочую сессию не перестраивать, секреты/неизвестные поля не терять.

## Выполнение

- [x] Воспроизвести selected edit → null import в синтетической цепочке; исправить каталог/выбор/тексты и stale edit guard.
- [x] Передать/сохранить manual CAPTCHA preference, проверить default/profile/manual/advanced/direct и запрет постороннего IPC.
- [x] Safe effective settings snapshot/inspect, actual C#→Go pipeline: n/spc/transport/DNS/flags и сохранность ключей. Добавить понятное отображение фактических параметров и pending reconnect.
- [x] Проверить остальные существующие настройки, сборку/targeted checks/interop/native/offline/package hashes;0.17 сохранить.
- [x] ТЗ/PROGRESS/REMAINING, ограничения реальной проверки. Дальнейшие системные routing/AWG/installer задачи остаются отдельными; исключённые Windows extras не возвращать.

## Фактический результат

Root cause подтверждён кодом и failing regression: старый тест намеренно ожидал снятия ActiveId; новое ожидаемое поведение упало на прежней реализации, затем PASS после исправления. Это не исправление числом потоков по умолчанию: приложение теперь выбирает обновлённый share, сохраняя keys/CID/PSK/opaque fields. Изменение другого профиля не переключает active selection. Состояние службы не изменяется при Save; применяется следующий manual Connect. При уже потерянном выборе из0.17 пользователь выбирает профиль один раз, система не угадывает его по старому service blob.

| Параметры | Вывод аудита |
| --- | --- |
| n/SPC/TURN transport/DNS/manual profile | Совместно терялись из Connect после ActiveId reset. C# edited10/4/UDP/DoH/manual → DPAPI → synthetic import/connect → actual Go inspect PASS |
| OBF/key/timing/peer/proxy/listener/KCP/WG | Прослежена та же цепочка ShareDocument.Build→Replace→import→Go parse; сохранение WG bytes и непрозрачных полей проверено. Новые live transport tests не выполнялись |
| Global auto/manual CAPTCHA | Был только UI gate для advanced. Теперь preference/backup/connection option, protected IPC scope, initial/path restart/recovery; профильная manual имеет приоритет, Direct не использует CAPTCHA |
| Advanced CAPTCHA | Сохраняется/передаётся как ранее; force manual нормализует advanced=false. WebView/VK E2E NOT RUN |
| DNS | Редактор задаёт resolver служебных запросов FreeTurn. WG Interface DNS задаёт DNS VPN; текст уточнён, системный DNS этим патчем не менялся |
| Routing/SOCKS/theme | По коду используют сохранённые policies при Connect/новом SOCKS start; theme после UI restart. Тексты не обещают hot apply. Новая сетевая приёмка не выполнялась |

- Go full tests/vet/build PASS. Actual configureCaptcha/coreForPath checked global manual/advanced/direct/relay + whitelist fields без конфигов/секретов. Effective snapshot строится из подготовленного core и WG MTU, status публикует его только при валидной runtime identity.
- C# catalog/selection/ServicePreparation/key/stale edit/backup checks PASS. Actual Go inspector10/4/UDP/DoH/manual/WG MTU1280 PASS; это подтверждение renderer input/output, не live stream allocation. Actual managed/enrollment/LKG bridges и Python schema/Unicode ETag/share interop PASS.
- Native GUI scenario открывает Servers→Параметры, вводит64 (отказ/no write/видимая ошибка), затем10→Save и проверяет выбранную новую запись/неизменный WG. Validator/SCM callbacks синтетические, real UI/control events настоящие. Single-window/nested/busy/close/WebView PASS, ServicesUsed=false/NetworkChanged=false. Dark/light compact editor и connected effective display renders осмотрены.
- Offline StateDigestUnchanged=true; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK. Baseline23 SHA/vendor package PASS. Полный серверный Linux suite не повторялся: ftm/API/schema/SQLite/vendor не менялись.
- ZIP `clients/windows/artifacts/FreeTurn-Windows-0.18.0-preview-win-x64.zip`: 86.2MiB/16 entries/15 payload SHA/188 source files/81 notices. SHA256 `de33c669fe947d3b5a921fd9b42c8ceed0e04bcf8b52a06792308caed452ae2f`; payload/source correspondence PASS,0.17 неизменён.

Real VPN с изменёнными params, live stream allocation/CAPTCHA/egress/leak E2E — **NOT RUN**. Installed services не обновлялись, реальные профили/ключи/VPS/GitHub не тронуты. Самопроверка без субагентов. Следующие routing/AWG/installer/bootstrap recovery блоки остаются отдельными задачами; этот патч приоритетно устраняет сообщённый дефект и аналогичные ошибки settings flow.
