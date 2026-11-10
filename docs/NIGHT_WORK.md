# Ночное продолжение разработки

Поручение пользователя от 10.11.2026: пока его нет около семи часов, заканчивать текущую работу и переходить к следующим этапам ТЗ без повторных подтверждений. Работать без субагентов.

В приложении создана активная задача **«Ночная разработка FreeTurn Manager»**, ID `freeturn-manager`: каждый час в этом чате, до 10.11.2026 08:20 Asia/Tomsk (01:20 UTC). Это запуски разработки. Компьютер должен оставаться включённым, приложение открытым; доступность сети и лимиты модели могут ограничить выполнение. После окончания окна не начинать новые ночные изменения; оставить результат пользователю.

## Исходное состояние

- Отдельный тестовый VPS согласован; production не трогать. GitHub push не разрешён. Чувствительные данные только в закрытом контексте чата, root-файлах и приватных локальных artifacts; не переносить их сюда.
- На тестовом VPS установлен и проверен FreeTurn, пользователь подтвердил iPhone. SSH Fail2ban: три ошибки за десять минут → бан на 365 дней, persistent retention 366 дней.
- Metadata SQLite, отдельные устройства и root agent работают. Legacy adoption на тестовом VPS выполнен: два исходных устройства теперь имеют подтверждённые root ownership-записи. Реальный revoke/enable неактивного Android peer и dynamic status с 1/2/3 peers PASS. Это не Android E2E. Профиль iPhone и baseline state не изменились; SSH/FreeTurn не перезапускались.
- Установлен runtime `/opt/ftm/current` (release `3f4f173a5aeae479`), wrappers ftm/vps-vk/ftm-startup и startup drop-in. Реальный network restart с pending revoke/enable, profiles filtering/regeneration и фактический reboot PASS. Снимки ключей/config/profile/registry/metadata совпали после reboot. SQLite и root registry остаются root-owned. API и IPC ещё не установлены.
- Подробности проверок: `STAGE2_PROGRESS.md`. Старый baseline renderer нельзя запускать поверх adopted state. `baseline_deploy` и recovery verifier имеют защиту; системный CLI заменён совместимым wrapper, legacy install/restore поверх adopted state блокируется.
- Текущий SSH helper может оставаться в PTY session 7174; если сессия завершилась, использовать ignored `.references/ssh_test_session.py` и секрет из закрытого контекста. Пароль не записывать в код, аргументы процессов или Git. Не пробовать неверные пароли.

## Очередь выполнения

1. Завершить managed startup: проверить pending add/revoke/enable до поднятия интерфейса, неизвестные peers, восстановление прерванных операций и безопасный отказ при конфликте. `ftm.startup` сейчас рассчитан исключительно на root-owned SQLite; перед API эта модель должна измениться.
2. Общий encrypted checkpoint metadata + root registry + baseline state + WG/CID config. SQLite Backup API, проверка целостности/версии/схемы и согласованности; HMAC до расшифровки/разбора, фиксированные data sections и ограничения размеров. Не принимать исполняемые unit-файлы, скрипты, произвольные пути или network.json с командами из backup. Проверить restore во временный каталог, затем реальный rollback/recovery на тестовом VPS. Скачать ciphertext вне VPS и проверить его. Существующий raw SQLite ciphertext не является общим Manager backup.
3. Установить root-owned runtime в `/opt/ftm`, совместимый status/profiles wrapper и фиксированный startup hook. Проверить systemd ordering и отказ на ошибке. Reboot только после проверенного восстановления и offsite backup; SSH/firewall не сбрасывать. Старые ключи/профиль iPhone сохранить.
4. Ограниченный Unix IPC/ACL и разделение прав для API: root не должен открывать SQLite, доступный на запись будущему веб-процессу. Никаких shell/arbitrary paths endpoints. Проверить spoofed identity, конфликты ownership, повтор/параллельность, revoke и восстановление после отказа.
5. Следующие доступные этапы ТЗ: FastAPI, сессии/CSRF, русская React/Tailwind панель, реальные метрики и безопасный Caddy; далее подписки/bootstrap/device tokens и доступные работы клиентов. Публичную панель без доверенного TLS не открывать. Сборка вне минимального VPS.
6. При необходимости нового домена, реального устройства, лицензии или недоступного внешнего доступа записать ограничение и перейти к независимой доступной работе. Android/Windows E2E, три реальных клиента, Direct/Auto и нагрузку нельзя объявлять проверенными по unit/namespace/mock.

После каждого законченного блока: профильные тесты, обновление плана/прогресса, локальный коммит без секретов. Не менять `vendor/vps` — все 23 файла должны совпадать с SHA256 lock. Не завершать всю приёмку ТЗ только потому, что окончилось ночное окно.

Уточнение пользователя: не стремиться к полному автотестовому покрытию всего проекта. Целевые проверки потери ключей/данных/доступа/прав обязательны по смыслу риска; обычные изменения проверять сборкой и рабочим сценарием. В ночном поручении местное время и UTC расходились; выбран ранний предел 08:20 по Томску (01:20 UTC), задача обновлена.

Checkpoint завершён: root /root/ftm-managed-188041447e.vpnbackup и приватная offsite-копия manager-preboot.vpnbackup в Downloads/FreeTurn-Test-2026-11-10; SHA256 c211eb355afae572194aab5d3a27627cec14dbea7d1cffa6b55d50d9fdc9f6f3. Phrase в существующем private recovery файле, её не печатать. Root reboot report /root/ftm-reboot-report.json PASS. Следующая работа — docs/IPC_PLAN.md; выбрать root-owned metadata + typed Unix RPC, не chown DB на API. Подробности и ограничения текущего same-host restore — docs/CHECKPOINT.md.

## Обновление: private панель проверена

На VPS установлен restricted ftm-control и rootless ftm-api (127.0.0.1:8080), root SQLite остаётся 0600 root:root. GUI login/logout/CSRF, создание пользователя/device и revoke/enable прошли через настоящий API и WG; synthetic доступ убран, исходные два peers/profile сохранены. Light/dark и mobile390x844 просмотрены в браузере. Сборка Node только на рабочем ПК. Подробности docs/STAGE3_PROGRESS.md и docs/UI_QA.md.

Текущий runtime release 017deeda76bf421f. Последний полный checkpoint v2 с web config: /root/ftm-managed-90023dbb01.vpnbackup, SHA256 a0c3776a9ae3ce0c93945ebd743818fcf6c639956ae49542f897ab8b87ca980e; offsite manager-with-panel.vpnbackup проверен WSL decode/stage. Реальные restore и injected rollback с изменением admin username PASS; после них login снова PASS. Web config /etc/ftm/web.json 0600 root, передаётся API через systemd LoadCredential. Пароль и secret URL не копировать в repo/вывод: private note /root/ftm-web-login.json и локально в Downloads/FreeTurn-Test-2026-11-10/panel-login.json.

SSH helper session7174; отдельный SSH forward session98838: локальный 127.0.0.1:18080 к серверному127.0.0.1:8080. Browser Node REPL через createRequire(playwright), headless shell установлен на ПК; page/context/browser и mobilePage/mobileContext используются для QA. Не печатать panelNote/targetUrl/cookies. Старые утверждения очереди выше являются историей: managed startup/checkpoint/IPC и private UI уже выполнены. Дальше Caddy/trusted TLS, постоянный reconcile и этап4 registration/subscription/bootstrap. Публичные80/443 пока не открывались, Caddy нет. Android/Windows/client E2E остаются NOT RUN. Master installer dry-run; GitHub push не делать.

## Обновление 07:17 Томск: TLS probe и retry

Caddy 2.11.9 с настоящим trusted Let’s Encrypt IP certificate установлен, TCP80/443 открыты только scoped rules и fixed boot hook. Публично только нейтральная страница, API по-прежнему private. Repeat install/hook и injected rollback PASS; исходные профили и VPN/SSH/API PID сохранены. Постоянный reconcile в control service установлен: durable add, interrupted revoke, obsolete enable и maintenance lock PASS. Подробности `HTTPS_RECONCILE_PROGRESS.md`.

Runtime `4bbbbe94efe9e7a5`. Последний offsite-verified checkpoint `/root/ftm-managed-a4bde6d716.vpnbackup`, SHA256 332a8c0827382231927cf90564638c85d0ddfc3e43712ec8f54bf6be0f3bc6a1; локально `manager-with-reconcile.vpnbackup`, 8 metadata / 2 peers / web settings. ACME cache и HTTPS settings пока вне checkpoint. Дальше безопасное включение публичной панели с HTTPS origin/Secure cookie и restore edge settings; затем этап4. Ночной cutoff 08:20 Томск / 01:20 UTC остаётся в силе.

## Обновление 07:29 Томск: public HTTPS

Панель уже доступна по trusted IP HTTPS; localhost API остаётся закрыт снаружи. Secure cookie, фиксированный HTTPS Origin, Host/CSRF, Caddy secret route, injected enable rollback и настоящий private/public restore/rollback PASS. Browser desktop/mobile login и HTTPS create/disable user PASS, после restore повторный login PASS. Профиль сохранён; enable не перезапускал VPN/SSH, отдельный restore перезапускал VPN/API/Caddy по назначению. `PUBLIC_HTTPS_PROGRESS.md` — текущий результат, более ранние private/probe записи выше исторические.

Runtime b41b929edcd1f2c4. Checkpoint `/root/ftm-managed-289a6f6872.vpnbackup`, SHA256 3ba1222f4c62491857a8762f24edf044489ed1989f2cb26dbf44a24cb1648593; local private `manager-public-https.vpnbackup`, offsite stage PASS. Root `panel-login.json` скачан заново, в нём public_url; секреты не печатать. Следующий этап — subscription/device credentials/enrollment. Нет clean-host/ACME cache restore, domain migration и phone/client E2E; не объявлять всё ТЗ принятым.

## Обновление 07:40 Томск: credential foundation

Stage4 hash-only lifecycle реализован и реально проверен с временным WG peer/RPC/root CLI; `STAGE4_PROGRESS.md`. Root SQLite права не менялись, iPhone профиль и четыре service PID сохранены. Тестовый peer отозван; активных исходных2. Публичных client routes/секретных IPC пока нет.

Runtime486619c38bbddd4c. Новая offsite копия `/root/ftm-managed-d8c6d0fb43.vpnbackup`, SHA2569b9b35a07d80fabbca16741d286d1ee770f30baeb7d4add88f4e1a0182d66a90; local private `manager-credentials.vpnbackup`, decode/stage PASS(9metadata/2peers/public web config). Следующий доступный блок — pinned Go/Android parsers и совместимый profile contract; refs core21dca376... и androidbe516f112... HEAD совпадают с lock. Go на рабочем ПК1.26.2 windows/386, kotlinc пока отсутствует; компиляцию на VPS не выполнять.

## Обновление 07:49 Томск: wire contract

Codec/schema и source pins готовы. Три synthetic профиля прошли actual pinned Go Parse/String и обратно Python, без key/CID/VK/obf изменений; Android source verified, runtime NOT RUN. `PROFILE_CONTRACT.md`. Windows102 tests97PASS/5skips, WSL102 tests99PASS/3web skips. Два новых codec cases — только round-trip/unsafe-input boundary. RootCLI parent-directory fsync проверен без peer changes.

Runtime41768b222d0f96cc. Последний offsite `/root/ftm-managed-bde749470a.vpnbackup`, SHA256af42934ae523012aae80513234ec46c905c444b6b12b567c47b8d7842d4e4f0f; private `manager-profile-contract.vpnbackup` decode/stage PASS(9metadata/2peers). В закрытом Downloads есть human-readable `Панель.txt`; URL/password не печатать. User-token/device credential foundation и codec не являются client subscription/enrollment: следующие этапы требуют отдельного envelope, atomic enrollment/idempotency/credential delivery и внутреннего HTTPS/bootstrap. До cutoff осталось около30мин; начать только законченный доступный блок, не оставлять live server в промежуточном режиме.

## Обновление 07:55 Томск: atomic enrollment core

`ENROLLMENT_PROGRESS.md`: одна transaction для user auth/limit/IP/CID/device/outbox/credential hash, client-generated CID/token/private key. Real synthetic caller → periodic worker → kernel WG PASS; repeat/revoke/URL rotation не меняют другие peers. Сетевую потерю HTTP не инъецировали: проверен caller-held token при игнорировании metadata result. Публичного client API нет. Runtimeba506629de5988da, Windows106 tests101PASS/5skips, WSL106 tests103PASS/3web skips.

Offsite `/root/ftm-managed-e3336b9bbf.vpnbackup`, SHA256dab56a048c677b26e80f487e58824dfbc5f01978efe5628b7f91efd5fd2cf0ca; local private `manager-enrollment.vpnbackup`, decode/stage PASS(10metadata/2peers/public web). Синтетические10 rows — история проверок, active только2 исходных. Ночное окно ещё до08:20Томск; закончить только независимый безопасный UI/read block, затем сверить итоговое состояние и не начинать новые изменения после cutoff.

## Обновление 08:00 Томск: журнал

Read-only RU журнал в панели установлен и проверен HTTPS браузером desktop/mobile/dark:92 реальных событий, поиск/empty, no overflow/JS errors. Auth401/200, response allowlist и IPC limit guards PASS. Без новых UI автотестов, production build и6 существующих boundary checks. `EVENTS_PROGRESS.md`.

Runtime **46acba450725bbf4** (проверен readlink). API/control перезапущены, VPN/SSH/Caddy PID сохранены. Root metadata не менялась; последний актуальный offsite остаётся e3336b9bbf/dab56a048c677b26e80f487e58824dfbc5f01978efe5628b7f91efd5fd2cf0ca. Клиентских публичных endpoints/secret IPC нет. До08:20 завершить финальную проверку/передачу; послеcutoff новые изменения не начинать. GitHub не отправлять.

## Финальная передача

`ftm status`/`ftm doctor` установлены и реально PASS. Current runtime **4c3d096c037baa98**. После actual restore последнего e3336b9bbf checkpoint выполнен финальный **full-stack reboot**: новыйboot_id, прежнийSSHhostkey, автоматические8служб, kernel WG keys/PSK/profile, snapshot equality и HTTPS login/events/logout PASS. `/root/ftm-fullstack-reboot-report.json` и private local copy. Первичный assert dbpurgeage исправлен с pretty text на numeric extraction; Rootполитика не менялась.

Текущая передача — **NIGHT_HANDOFF.md**, более ранние milestones выше исторические. Новые features после08:20Томск/01:20UTC не начинать. Проверочные browser sessions/logout и прежний SSH forward закрыты; последний SSH helper после скачивания отчёта закрывается. Секреты только в private Downloads/root files, GitHub push не делался. Следующие конкретные задачи и NOT RUN перечислены в handoff.
