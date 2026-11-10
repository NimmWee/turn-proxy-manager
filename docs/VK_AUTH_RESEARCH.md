# VK Calls и повторная CAPTCHA: решение для будущей интеграции

10.11.2026, Asia/Tomsk. Выполнено **только исследование и изменение требований** по поручению пользователя. Код клиентов/FTM/VPNN, бинарники, профили и VPS не изменялись; live VK-запросы не выполнялись. Реализацию начинать только по отдельному поручению.

## Наблюдение и гипотеза

Пользователь подтвердил импорт Android-профиля и сообщил о двух CAPTCHA. Это не подтверждает сквозной Android VPN-трафик. Версия установленного APK/embedded core пока неизвестна.

В выданном профиле `n=6`, `spc=3`, `mcap=true`. Проверенный Android parser читает их как число соединений, streamsPerCred и manualCaptcha. В pinned Go core CacheID=(streamID-1)/streamsPerCache: шесть соединений дают две группы реквизитов. Старый путь использует `calls.getAnonymousToken`. **Две независимые legacy-авторизации — обоснованная гипотеза, не установленная причина конкретного APK.** Также надо различить повторные callbacks/UI, истечение реквизитов и повторный запуск core.

`mcap=true` задаёт ручную обработку возникшей CAPTCHA. Отключение флага/включение solver не добавляет новый путь авторизации и не является выбранным исправлением. Повышать spc/уменьшать n без проверки квоты и качества транспорта нельзя.

## Подтверждённые источники

В [iOS GetVKCreds](https://github.com/anton48/vk-turn-proxy-ios/blob/a41bd5628a8bdbdc6ff7e3d794fb76d97ea08871/pkg/proxy/creds.go) свежий fetch сначала пробует [VK Calls chain](https://github.com/anton48/vk-turn-proxy-ios/blob/a41bd5628a8bdbdc6ff7e3d794fb76d97ea08871/pkg/proxy/creds_vkcalls.go), при неуспехе остаётся legacy fallback. [Документация iOS](https://github.com/anton48/vk-turn-proxy-ios/blob/a41bd5628a8bdbdc6ff7e3d794fb76d97ea08871/docs/setup.md) описывает также автоматическую CAPTCHA и ручной WebView. Поэтому отсутствие окна не означает отсутствие CAPTCHA-кода и не гарантируется для любого ответа VK.

При уже начатом legacy challenge исходник продолжает ту же сессию: сохранённые token/client identity и ответ CAPTCHA нельзя смешивать с новым anonymous Calls token. Это существенно для устранения повторных окон и потери ручного ответа.

В `C:\VPNN/engine/go.mod` реально подключён `../transports/freeturn`. В нём найдены:

- `internal/provider/vk/internal/vkauth/calls.go`: новая Calls chain через существующий TLS/dialer; общий deadline35с, проверка сертификатов, запрет redirect, предел ответа1МиБ, безопасные ошибки.
- `.../client.go`: Calls до legacy; context cancel, terminal invalid link/anonymous blocked/call full без перебора; rate limit → backoff.
- `.../calls.go:credentialExpiry`: истечение из TURN username минус60с, максимум8часов; если формат неизвестен — прежние10минут минус60с. Уже истёкшие реквизиты отвергаются.
- `.../cache.go`, `.../reconnect_cache.go`: mutex на fetch группы, повторное использование пригодных credentials в одном процессе, максимум32 scope. Scope включает fingerprint seed, звонок, platform, state paths, credentials и policy/число потоков. Secrets только в памяти; invalidation/освобождение allocation сохраняются.
- `C:\VPNN/docs/PERFORMANCE-0.1.4.md`, `docs/FIX-0.1.2-WINDOWS-VK.md`: исторические live проверки без ручной CAPTCHA. Это отчёты другого проекта, **не новый FTM E2E**. TCP bond из той же доработки не переносить автоматически в наш WG/UDP тракт.

В VPNN autoCaptcha/advancedCaptcha выключены, ручной fallback сохранён (`engine/config.go`). Новый anonymous Calls путь не требует личного VK account/cookies администратора. Runtime/private state, дампы challenge и секреты из VPNN в FTM не переносились.

## Версии и воспроизводимость

Локально изучены iOS HEAD `a41bd5628a8bdbdc6ff7e3d794fb76d97ea08871`, FTM reference Android `be516f1122ac38523203dbffde8603a8b3e755fc`, core `21dca376ca26d2b6d0e2d84d107b9314b5041146`. Они подтверждают source mapping, не версию APK на телефоне.

`C:\VPNN` целиком не Git checkout. Вложенный freeturn HEAD `562cfb4ba18b3d4a001e3bd3c2a19896c2a254a0`, но нужная доработка **незакоммичена**: calls/reconnect_cache новые, client.go изменён. Поэтому для переноса недостаточно одного HEAD. SHA256 прочитанных рабочих файлов:

| Файл vkauth | SHA256 |
| --- | --- |
| calls.go | `4ff98fde9b3a67b5f5d25d178b72725750ce70b91381fae450c728a6cd1e3ff8` |
| client.go | `cf25fa1c3233db99a35762830138b535ad50421c97a3f36b897f8c1d845e0212` |
| reconnect_cache.go | `027123bf9c73091f2355db12da0f3763122b69c9d11fea262e1b8ed7966a81f4` |
| cache.go | `3f33524e89469277327c91164427c4e132b4a6dfec0ced681d34a6f54baea4a8` |

## Выбранное решение — НЕ РЕАЛИЗОВАНО

1. При будущей Android/Windows интеграции перенести узкий адаптер в общий Go VK provider, сохранив TLS/HTTP и socket protection от попадания auth внутрь собственного VPN. Исследованная цепочка: `api.vk.me/method/auth.getAnonymToken` → `/method/messages.getCallPreview` → `/method/messages.getAnonymCallToken` → OK Calls anonymous session/join (`calls.okcdn.ru/fb.do`) → TURN. Публичные app/API identifiers исходника перепроверить при реализации; реальные tokens в код не фиксировать.
2. Для свежего fetch сначала Calls, независимо от режима ручного fallback. Успешная штатная Calls chain не открывает CAPTCHA WebView и не требует VK-аккаунта. Гарантию «CAPTCHA никогда не будет» не давать.
3. Перенести ограниченный memory cache, реальные TTL, scope isolation и invalidation. Reconnect/смена режима не должны создавать новый fetch, если credentials ещё пригодны и их allocation quota позволяет повторное использование. Не делить secrets между устройствами/звонками/аккаунтами. После restart процесса cache может быть пустым; disk persistence TURN secrets этим изменением не добавлять.
4. Один auth coordinator владеет попыткой/challenge. Потоки одной группы ожидают один fetch; UI не открывает дубли для одного challenge. CAPTCHA retry продолжает ту же legacy session, не запускает новую цепочку. Cancel останавливает ожидание/повторы. Разные необходимые credential groups не объединять вопреки квоте: убрать технические дубли, а не скрывать самостоятельные challenges.
5. Calls unavailable → ограниченный legacy/manual fallback. Invalid link, call full, anonymous blocked, rate limit → безопасная ошибка/backoff без account/client-id churn. В фоне не открывать интерактивное окно и не запускать busy loop; сообщать о необходимом действии. Истечение TTL может потребовать новой авторизации.
6. WG keys/PSK/CID, профиль iPhone, backend, число потоков и wire protocol не менять ради этого исправления. `vendor/vps/` не обновлять. Переносить только нужные client auth/cache части с pinned SHA/проверкой лицензий/NOTICE, без полного копирования VPNN, его настроек/private state и solver.
7. Диагностика: только путь `calls/legacy/cache`, номер группы, безопасный код ошибки и срок cache. Никаких VK URLs, token/session/challenge keys, TURN username/password, HTTP query/body/полных ответов. Подробные upstream logs не переносить автоматически.

## Приёмка будущей реализации (T28)

- Android и Windows отдельно: fresh Calls success → настоящий WG handshake/HTTPS через VK без вызова ручной CAPTCHA; требуемый VK challenge честно уходит в fallback.
- `n=6/spc=3`: проверить две группы, отсутствие дублей UI одного challenge и соблюдение allocation quota. До диагностики APK не объявлять нынешнюю причину установленной.
- Reconnect до TTL использует пригодный cache; expiry/revoke/scope change не возвращают старые secrets. Auth sockets не уходят внутрь собственного туннеля.
- Calls unavailable → согласованный manual flow; cancel/rate limit/invalid link не создают шторм запросов. Успешный ручной ответ не теряется из-за повторного core/UI launch.
- Проверить остальные устройства/iPhone и отсутствие secrets в logs/exports; измерить auth latency/cache hit без обещания скорости.

Автотесты — только критические scope/TTL/invalidation/single-fetch/cancel/error-redaction случаи; остальное сборкой и рабочим сценарием. Все перечисленные FTM runtime проверки **NOT RUN**.
