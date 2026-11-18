# Windows0.7: видимые этапы и guarded update службы

**Дополнение0.7.1:** защищённые журналы прочитаны; найден и воспроизведён блокирующий отказ Protect на неподключённых Winsock-сокетах. Исправление и SCM диагностика собраны, VPN E2E после исправления ещё NOT RUN. [Подробности](WINDOWS_SOCKET_FIX.md). Ниже сохранён отчёт предыдущего этапа0.7.0.

16.11.2026. Пользователь сообщил о минутном ожидании подключения и возврате без понятной причины; подтвердил, что при той попытке Amnezia была отключена. Попросил подробные состояния. **Причина именно той сетевой ошибки пока не установлена.** Новая диагностика не является доказательством её устранения.

Read-only наблюдение перед изменениями: Desktop UI0.6.1, SYSTEM broker без capabilities (старый установленный бинарник), profile есть, tunnel stopped, handshake=false, CAPTCHA отсутствует. Нынешняя Amnezia имеет default routes и вызывает ожидаемый preflight `OTHER_VPN_OR_NONPHYSICAL_UPLINK`; это не объяснение прошлой попытки, которую пользователь делал без неё. Содержимое private профиля/ключей не выводилось, VPS не посещался. Текст elevated окна через UIA не прочитан; пользователь описал поведение словами.

## Что исправлено

1. **Диагностика прогресса.** Реальные core events/allowlisted log markers дают transport/VK/CAPTCHA/подтверждённый TURN; SCM — запуск службы, WG handshake — следующий этап, отдельный HTTPS probe — проверку интернета. Для Direct добавлен polling stock `mobile.GetState`, поскольку push OnState у upstream есть только для Relay. Между событиями не выдумывается процент/новый этап. Не все внутренние VK/TURN операции upstream имеют отдельные markers: показывается последняя известная фаза.
2. **Ошибка не теряется.** Safe codes вместо raw error/log/URL. В runtime сохраняются stage/stageSince/lastProgress/error; при fatal startup — отдельный SYSTEM DPAPI failure с attempt ID. Broker возвращает только отказ текущей попытки; новая попытка имеет новый ID, explicit disconnect/import очищает failure. Если служба остановлена после сбоя, кнопка позволяет Retry. Работающая, но неуспешная служба сначала отключается. Сохранённый профиль не пересоздаётся.
3. **UI.** Название этапа на главной, elapsed/streams, после30с без новых событий явное время тишины и возможность отменить; manual CAPTCHA объясняет нужное действие. Ошибка показывает последний известный этап/безопасную причину. Переходы и безопасные причины идут в ограниченный журнал без доменов/секретов. Старый broker получает явное уведомление об ограниченной диагностике, а возврат к stopped не выглядит успехом. Исправленная UI-кнопка обновления остаётся доступной и для последующих версий.
4. **Настоящая операция обновления.** Было: UI «Обновить» всегда передавал `--install`, который возвращал ALREADY_INSTALLED. Теперь fixed `--setup SID` выбирает fresh install либо отдельный upgrade. UAC остаётся явным действием пользователя. До остановки проверяются обе собственные службы/конфигурации, прежний owner, tunnel Stopped, stable broker state, пути и driver SHA. Профиль/options/owner не переписываются. Старые бинарники сохраняются в защищённом install dir, broker останавливается с ожиданием process exit; заменяются EXE/DLL и запускается только broker. При ошибке замены/старта — попытка rollback binaries и прежнего broker state. Код сообщает отдельные safe setup exit codes для active tunnel/owner mismatch/rollback/incomplete install. Повтор с теми же бинарниками и работающим broker — без рестарта. Никакого автозапуска VPN и расширения firewall.

## Проверки и пределы

- Go test/vet PASS: privacy allowlist runtime events, upgrade active/transition/owner refusal и injected binary-replace/start failure rollback ordering; прежние профиль/IPC/SOCKS проверки сохранены. Это synthetic callbacks, **не реальный rollback SCM**.
- Native catalog/DPAPI/backup PASS; UI diagnostic mapping не выводит неизвестный secret-like code, сохраняет safe TURN stage. Профили/ключи проверяются прежними targeted cases.
- Release build/publish PASS,0 warnings/errors. Synthetic renders420 показывают долгую попытку и terminal error без scrollbar/overflow; это mock states, не подключение.
- Offline import/routing/foreground/setup-argument guards и digest routes+adapters+services PASS, неизменён. Read-only authentication/status существующего SYSTEM broker PASS, stopped/HasProfile=true. Установленный broker не заменялся.
- Baseline23 SHA и vendor package PASS, vendor не изменён. Никаких субагентов/GitHub/VPS.

Итоговый пакет `FreeTurn-Windows-0.7.0-preview-win-x64.zip`:77.34MiB,14 entries/13 payload SHA256 проверены,81 corresponding source file побайтово совпадает с workspace. SHA256 `c23020b08592b0e702f7cbc50340ed1d3b4013200c356a1543f2f7c48cc420b1`.61 dependency notices; preview/private artifacts не включены. Собственные EXE unsigned, драйвер официальный подписанный. Пакет отдельный; установленный Desktop/службы автоматически не заменены.

**NOT RUN:** фактическое UAC setup/upgrade/SCM rollback, новая Windows VPN/CAPTCHA/TURN/WG/egress попытка, hardware sleep/network switch/leak tests. Известный отказ запуска текущей среды при другом VPN не объявляется причиной предыдущего сбоя пользователя. Его следующая попытка на обновлённой службе должна показать конкретную фазу и безопасный код.

## Как проверить пользователю

Распаковать полный0.7 архив в отдельную папку; закрыть старое окно, запустить новое. При отключённом FreeTurn открыть Настройки → Продвинутые → Обновить службы и подтвердить UAC. Один новый EXE окна не обновляет SYSTEM broker. Существующий Windows-профиль сохраняется, повторный выпуск ключей/профиля не нужен. Затем самостоятельно отключить другой VPN и повторить подключение; при сбое проверить последнюю фазу/сообщение в Логах. Сырые core logs, private URI и ключи для диагностики не нужны.
