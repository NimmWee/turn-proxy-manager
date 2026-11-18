# Windows installer и обновления —18.11.2026

**Последняя поставка0.27:** включает bounded AWG1–3 и усиленные retained-owner/partial-owned-uninstall/registry guards. ZIP+Setup/source/hash/offline PASS, real install/UAC/VM acceptance NOT RUN.0.25/0.26 ниже — frozen предыдущие checkpoints. [Hardening0.27](WINDOWS_SETUP_HARDENING_27.md), [AWG](WINDOWS_AWG_26.md).

## Договорённости и граница

Ночное поручение разрешает подготовку и локальные проверки без настоящей установки, UAC, запуска VPN или изменения установленных служб. Frozen payload0.25 остаётся неизменным. Первое завершённое изменение — отдельный стандартный Windows Setup.exe поверх этого payload, без удалённого автоскачивания.

Выбран machine-wide Inno Setup: бинарники GUI и проверочный helper в фиксированном Program Files/FreeTurn, отдельном от существующего protected core Program Files/FreeTurnManager. Установка требует стандартного разрешения Windows, но не подменяет user profile/ProgramData, не ставит/не запускает VPN и не меняет сеть. Уже существующий flow Connect сам готовит/обновляет idle core от имени выбранного пользователя. Профили UI остаются в прежнем LocalAppData; protected service data и телефонные ключи не затрагиваются.

MSIX потребовал бы новую certificate/package identity/trust установку; собственный копировщик добавил бы rollback/registry/shortcut обязанности. Inno даёт обычный installer/uninstaller и версионирование. Используется только официальный закреплённый компилятор с SHA256+Authenticode; compiler portable в ignored tools, без глобальной установки. Источник: [Inno downloads](https://jrsoftware.org/inno-setup/downloads), [portable mode](https://jrsoftware.org/inno-setup/documentation/topic_technotes.htm), [AppMutex](https://jrsoftware.org/inno-setup/documentation/topic_setup_appmutex.htm), [CloseApplications](https://jrsoftware.org/inno-setup/documentation/topic_setup_closeapplications.htm).

## Последовательность

- [x] Маленький отдельный Go SetupGuard: read-only preflight SCM query-only ownership/state, отказ при открытом FreeTurn в любой сессии/активном VPN; RestartManager/force-close не используются. Fixed install directory, marker, reparse и protected owner/DACL guards. Downgrade проверяет Inno по версии установленного EXE.
- [x] Uninstall-only операция guard, доступная только из protected установленного app path и с elevation: повторная проверка, вызов только fixed protected core --uninstall, подтверждение исчезновения собственных служб, удаление только четырёх fixed owned code artifacts. Директории/файлы должны быть BA/SYSTEM-owned без writable nonadmin ACE, reparse запрещены; core ownership metadata сохраняется. Не рекурсивное удаление; profile/ProgramData файлы не удаляются. Startup entries — только точное совпадение owned path/command в загруженных пользовательских hive; незагруженные hive не монтируются.
- [x] Русский Inno Setup: fixed path, marker, shortcuts/uninstall entry/icon, без shell-команд/скачиваний, без automatic launch/VPN/reboot/force-close. Prepare и InitializeUninstall checks выполняются до изменения поставки. Mutating cleanup — после стандартного подтверждения, до PerformUninstall; ошибка здесь fatal в закреплённом Inno7.1.1, GUI-файлы сохраняются. Обновление повторным Setup, downgrade не допускается, same-version repair допустим. Per-user settings сохраняются.
- [x] Build wrapper проверяет frozen ZIP/manifest и133 закреплённых компонентов компилятора, создаёт отдельные sources/license/hash evidence, не меняя0.25 ZIP. **Не заявлена bit-identical воспроизводимость Setup.exe**; воспроизводимы шаги/inputs и проверяемая связь source archives. Unsigned preview, SHA256 — целостность, не происхождение.
- [x] Локальные risk tests: неизвестные/чужие/частичные службы, активный туннель, foreign marker/path, permissive DACL, последовательность удаления и exact startup matching. Go test/vet/build и Inno compile PASS; actual query-only SCM check READY и отказ --remove-services из build-cache PASS, state digest unchanged. Настоящие install/upgrade/uninstall/UAC/clean VM E2E — **NOT RUN** ночью; reparse/downgrade/power-loss сценарии настоящего мастера не проверялись в VM.
- [ ] Remote updater: нужен доверенный feed и ключ/подпись издателя. Не выдумывать key/feed и не загружать неподписанное обновление. Возможны локальный verifier/протокол позже; публикация/подпись/remote acceptance остаются отдельным gate.

Файлы: clients/windows/installer/guard (отдельный Go module), FreeTurn.iss, build_setup.ps1, toolchain.lock.json, README.md, compiler license; scripts/verify_windows_setup.py при необходимости для read-only проверки поставки. Не добавлять изменённые файлы внутрь frozen0.25 sources.zip, installer sources поставляются отдельно.

Реализован Python `build_setup.py` вместо предполагавшегося ps1: проверка ZIP/компилятора, вызовы Go/ISCC без shell, отдельная неизменяемая поставка. Компилятор получен из official immutable release, GitHub asset SHA256 `8a5a6711c3766a6e5fb74f280ba0e3551e719ce94538d901fdbd1f8f9920b3f0`, Authenticode Valid/Pyrsys B.V.; portable tools находятся только в ignored cache, глобальный compiler не устанавливался.

## Фактическая поставка

- `clients/windows/artifacts/FreeTurn-Setup-0.25.0-preview-win-x64.exe`,79.51MiB, SHA256 `efbbb850a99fdfb42b69e70e8d3d3a35f3866e3eb5d6cb99e592259cfad68390`.
- Отдельные `FreeTurn-Setup-0.25.0-Sources.zip` и `.sha256`;10 соответствующих текущим файлам исходников/инструкций+GPL license. SHA256 sources `0bb00c05ac8f63219bf7a3cb1a67d49020fd0591e54bf380b212da4d20d5431c`.
- Frozen0.25 ZIP по-прежнему `437440a9e1ed3d7192dc34dfe6b1bf1a1a482bbcd3bfb82e0100ae1f60137b3e`. Installer содержит этот проверенный payload, его notices/source bundle и отдельный SetupGuard/source bundle/license. Исходники самого приложения0.25 не менялись.
- `python scripts/verify_windows_setup.py` PASS; source correspondence, installer/hash/frozen payload проверены **без исполнения Setup**. Локальные evidence: ignored `.local-cache/windows-setup/0.25.0/build-report.json`, `.local-cache/windows-build/setup-guard-offline.json`, build log.

Открытые ограничения: подпись издателя/доверенный remote feed отсутствуют; unattended updater не включён. Реальная установка/обновление/удаление и ремонт после обрыва питания должны пройти отдельную clean VM приёмку. При прерывании до установки marker неизвестная непустая папка намеренно не усыновляется автоматически. Старые portable autorun entries с другим путём не переписываются без явного migration flow. При uninstall незагруженные Windows hives не очищаются. Существующая installed0.24/профили/сеть/VPS ночью не менялись.
