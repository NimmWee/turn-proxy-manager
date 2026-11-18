# Совместимый AWG backend Windows — план18.11.2026

**Следующий checkpoint0.26 выполнен:** bounded AWG2/3 range/CPS/header-key/timers parser, public backend gates, UI/DPAPI/backup и настоящий local encrypted traffic проверены; ZIP и Setup0.26 собраны. Всё ещё NOT RUN real AWG-server/TUN/FreeTurn/VK/leaks/long timers.0.25-описание ниже — предыдущий checkpoint. [Подробности0.26](WINDOWS_AWG_26.md).

**Текущее состояние:0.25 собран локально.** БлокиA–C реализованы для bounded AWG1. Профиль теперь импортируется с явным требованием системного userspace backend; WGNT downgrade запрещён до SCM. Локальные encrypted traffic/Go/C#/backup/поставка/offline проверки PASS. AWG2/3, реальный сервер/TUN/VK и E2E ещё не приняты. Установленная0.24 не обновлялась.

По текущему ТЗ AWG требует отдельной реализации и реальной приёмки. Ordinary WireGuardNT не исполняет AWG extensions. Ночное поручение позволяет локальную разработку без подключения/смены профилей/служб. Новые протокольные настройки нельзя молча отбрасывать или считать совместимыми с WG.

## Выбранная граница

Переиспользовать уже закреплённый amneziawg-go/v3 userspace backend и loopbackWGBind: внешний транспорт принадлежит FreeTurn, encrypted WG/AWG side остаётся127.0.0.1. Сохраняются криптография, peer keys, bounded queues и временная защита активного туннеля. Другие варианты — новый AWG kernel driver или отдельный исполняемый daemon — добавили бы driver/install/IPC поверхность без готовой локальной приёмки, поэтому сейчас не выбраны. Постоянная блокировка сети не возвращается.

## Блоки и критерии

- [x] **A. Локальный backend proof, без изменения формата профиля/UI.** Отдельный bounded parser допустимых AWG1 полей Jc/Jmin/Jmax/S1/S2/H1–H4 в Interface; детерминированный UAPI до первого peer, запрет duplicate/section confusion/newline/oversized values/overlap. Unsupported newer AWG fields не отбрасывать: parser отказывает. Подключён только к startMemoryWG. Настоящий handshake + TCP/UDP двух синтетических netstack peers с нестандартными headers/padding PASS; обычный WG сценарий сохранён. Без TUN/SCM/маршрутов. Это отдельный законченный proof, **не готовая импортируемая AWG-функция**.
- [x] **B. Общий профильный контракт и явный backend gate.** Единый parsing helper base WG+AWG extensions для safeWG/effective/health/recovery/systemDNS; WGNT ветка никогда не получает AWG. AWG допускается только с явно выбранным совместимым backend; без него AWG_SYSTEM_BACKEND_REQUIRED до SCM/записи и до user-mode подготовки. Protocol сохраняется при transport switch; recovery сравнивает канонические extensions. Managed v1 WG manifest явно отказывает AWG, нового AWG managed contract пока нет.
- [x] **C. UI/storage/import/settings.** Исходные поля в DPAPI/backup/editor сохраняются; протокол/ограничения показаны после импорта, в карточке сервера и effective settings. Никакого auto-enable system routing. Импорт → правка потоков → DPAPI/encrypted backup → actual Go protocol inspection PASS. Current0.24 и установленные профили не заменялись.
- [ ] **D. AWG2/3 compatibility.** На основе реально закреплённого backend и формата Android ограниченно проверить range headers/S3/S4/I1–I5/новые поля с контролем размеров/нагрузки. Непроверенные поля отклонять. Не обещать поддержку всех AWG-версий из одного AWG1 handshake.
- [ ] **E. Сборка/приёмка.** Отдельная версия preview и source notices; локальные gate/crypto tests, WG regressions, build/offline nonmutation. Реальный AWG сервер+FreeTurn Direct/Relay, egress/rollback/leaks/reconnect и совместимость Android/Windows — NOT RUN до согласованного живого сценария. Не обновлять реальные серверы/службы ради доказательства.

Файлы первого блока: новый `clients/windows/engine/awg_memory_config_windows.go`, `awg_memory_config_windows_test.go`; минимальное подключение в `system_memory_wg_windows.go` и расширение synthetic pair helper в `system_memory_wg_windows_test.go`. Следующие блоки затронут profile/runtime/recovery/system options/managed guards и UI; перед ними проверить все прямые conf.FromWgQuick callsites, чтобы не появился скрытый downgrade или неожиданная попытка запуска WGNT.

Проверки целевые: parser/UAPI — security boundary для секретной конфигурации; настоящий encrypted TCP/UDP loopback — работоспособность backend. Полное автотестовое покрытие не требуется. Профили/ключи в диагностике не печатать, parser/upstream errors наружу только fixed code.

## Фактический результат блокаA

Реализованы перечисленные файлы. Limits: Jc≤16,Jmin/Jmax≤1280,S1/S2≤512,H1–H4 непересекающиеся uint32>0; строки не могут вносить произвольный UAPI. Поддерживается только проверенный AWG1 subset; range headers/S3/S4/I пока отвергаются. На первом checkpoint блокаA публичный validator ещё отвергал AWG. После реализацииB–C импорт открыт с backend guards; прежний закрытый gate ниже не является текущим состоянием.

`TestMemoryAmneziaWGEncryptedTCPAndUDP` PASS: синтетические X25519 peers, Jc3,Jmin40,Jmax70,S1=15,S2=30,H1–H4=101/102/103/104, настоящий TCP/UDP echo и handshake/Rx/Tx. Private IpcGet используется внутри теста только для проверки применения extensions и нигде не печатается. Parser bounds/unsupported и обычный WG encrypted scenario PASS. Полный `go test -mod=readonly -tags with_gvisor ./...`, `go vet` и standalone build в ignored `.local-cache/windows-build/AWG-proof.Engine.exe` PASS. Установленное приложение/сборка0.24 не обновлялись.

## РезультатB–C и локальная поставка

Red→PASS новых targeted profile/backend/recovery tests; safeWG и common parsing сохраняют strict section/duplicate/unknown-field guards. При отсутствии явного Enabled systemPolicy AWG получает fixed error до сетевых действий; тот же guard вызывается broker и tunnel runtime. Обычный WGNT остаётся default для WG. AWG не подменяется WG при automatic return, custom headers не теряются при Direct/Relay switch. Capability `awg1-userspace-ipv4-v1` выдаётся только сборкой with_gvisor. Managed bootstrap/update v1 явно отклоняют AWG.

Full Go test/vet/build и WPF publish PASS. C#→DPAPI→AES-GCM backup→actual Go import/inspection с изменёнными8 streams: AWG1 protocol/MTU и весь исходный WG/AWG текст сохранены; backend сам не включается. Existing managed/enrollment actual builder regressions и system routing actual preview PASS. Offline routes/adapters/services digest unchanged; preflight отказывает OTHER_VPN_OR_NONPHYSICAL_UPLINK, другой VPN не затрагивался. Никаких actual service IPC/driver/network mutations этой версии не выполнялось.

`clients/windows/artifacts/FreeTurn-Windows-0.25.0-preview-win-x64.zip`,90.44MiB,16 entries/15 payloads,211 файлов corresponding sources,81 notice files. SHA256 `437440a9e1ed3d7192dc34dfe6b1bf1a1a482bbcd3bfb82e0100ae1f60137b3e`. Manifest/ZIP/current sources correspondence PASS; frozen0.23/0.24 ZIP+payloads неизменны. JSON evidence ignored `.local-cache/windows-build/package-0.25.json`.

Остаток: блокD; live частьE и принятие AWG1 на настоящем совместимом сервере. Даже подготовленная0.25 не подтверждает работоспособность AWG на текущем обычном WG сервере; сервер не переустанавливался и профили пользователя не преобразовывались.
