# Ход работ

**Обновлено:** 10.11.2026, Asia/Tomsk.

Ночная передача: [NIGHT_HANDOFF.md](NIGHT_HANDOFF.md). Финальный full-stack reboot после actual latest restore PASS: VPN/API/Caddy/Fail2ban стартовали сами, HTTPS login и сохранность ключей/profile/checkpoint подтверждены. После08:20Томск продолжение только по новому поручению.

## Текущий этап

**Разработка возобновлена новым поручением после ночного cutoff.** Client HTTPS API enroll/status/subscription уже установлен и реально проверен через restricted IPC к kernel WG. Per-device config без private key, pending/ETag304, revoke-before304 и bearer scope isolation PASS. Это серверный контракт с reference caller, не готовое Android/Windows приложение. [Протокол и проверки](CLIENT_API.md).

**HTTPS внутри VPN проверен.** Узкое INPUT разрешение TCP443, проверка публичной TLS identity при внутреннем TCP адресе, настоящий WG namespace config/304 и запрет22/8080. Private/public restore и rollback синхронизируют исключение; network restart восстановил правильный порядок. Финальная offsite копия14 metadata/2 peers расшифрована в WSL; ключи/iPhone сохранены. [Подробности](INTERNAL_HTTPS.md). Следующий серверный блок — bootstrap/claim и admin re-auth/export.

**Lifecycle токенов этапа4 проверен.** Hash-only user/device credentials, rotation и отзыв, без возрождения старого credential при re-enable. Реальная проверка с WG/RPC/root CLI PASS, ключи и профиль сохранены. [Подробности foundation](STAGE4_PROGRESS.md); HTTPS endpoints добавлены следующим блоком выше.

Существующий share codec/JSON Schema проверен настоящим pinned Go parser на трёх synthetic profiles. Android source mapping/SHA проверены, runtime NOT RUN. [Контракт](PROFILE_CONTRACT.md). Реальный клиентский secure storage ещё не интегрирован; неизвестные managed поля нельзя добавлять в upstream share JSON.

Атомарное enrollment core сохраняет WG private key/device token на стороне caller и принимает только public key/CID/hash. Concurrent retry/limit/collision/revoke PASS; на VPS periodic worker применил настоящий synthetic peer. [Границы core проверки](ENROLLMENT_PROGRESS.md); публичный API/config добавлен отдельным блоком выше.

**Русская панель доступна по доверенному HTTPS.** Caddy с Let’s Encrypt IP certificate, Secure cookie, фиксированный Origin/Host, rootless API через Unix IPC. В браузере проверены вход и создание/отключение пользователя. Реальные private/public restore и injected rollback сохраняют границу доступа; offsite копия проверена. [Результаты и ограничения](PUBLIC_HTTPS_PROGRESS.md).

Добавлен read-only «Журнал» с реальными audit events, RU action names, поиском и мобильным layout. Auth401/200, bounded allowlisted IPC/API и браузерный сценарий PASS; новых UI автотестов не добавлено. [Проверки](EVENTS_PROGRESS.md).

`ftm status`/`ftm doctor` доступны на установленном стенде и реально проверены без изменений сервера. [Команды](OPERATIONS.md).

**Фоновый reconciler установлен.** Durable pending/applying add/revoke, отмена устаревшей операции и lock contention проверены на WG без VPN/SSH restart; профили сохранены. [Проверки](HTTPS_RECONCILE_PROGRESS.md). История private UI: [STAGE3_PROGRESS.md](STAGE3_PROGRESS.md). Выдача новых клиентских профилей, подписки и полный installer ещё не готовы.


**Managed startup и recovery проверены на тестовом VPS.** Установлены root-owned `/opt/ftm` runtime, совместимый `vps-vk` и systemd startup hook. Общий encrypted checkpoint скачан и реально проверен в WSL; same-host restore и injected rollback PASS. Pending revoke/enable пережили настоящий restart сети. После фактического reboot VPN стартовал автоматически; ключи, профили, registry и metadata совпали. SSH, годовой Fail2ban и scoped firewall проверены. Phone E2E после reboot NOT RUN. IPC и первая private панель уже выполнены; далее trusted TLS и этап 4. Подробнее: [CHECKPOINT.md](CHECKPOINT.md), [IPC_PLAN.md](IPC_PLAN.md).

По поручению пользователя включены почасовые запуски разработки в этом чате до **10.11.2026 08:20 Asia/Tomsk**. Очередь и точное состояние передачи: [NIGHT_WORK.md](NIGHT_WORK.md). Это не обещание завершения всего ТЗ за ночное окно.

**iPhone E2E подтверждён, recovery/rollback проверены; реализована первая рабочая часть этапа 2.** Пользователь подтвердил интернет и IP через Anton48; сервер подтвердил handshake/rx/tx. На тестовом VPS работают SQLite metadata и отдельный root-only hot peer agent. После синтетической проверки остаются два исходных активных устройства, профиль iPhone не менялся. Android для этой установки NOT RUN. [Подробный результат этапа 2 и оставшиеся gates](STAGE2_PROGRESS.md).

## Что реализовано

| Файлы | Результат |
| --- | --- |
| `vendor/vps/`, `upstreams.lock.json`, `NOTICE.md` | Все 23 исходных файла Vps сохранены без изменения содержимого, с лицензиями и готовыми артефактами; SHA шести upstream репозиториев |
| `ftm/legacy.py`, `ftm/installer.py` | Валидация старого состояния, строгого JSON и чистый план установки/миграции; сохранение сетевых параметров и исключение секретов из вывода |
| `ftm/cli.py`, `ftm/__main__.py`, `install.sh` | CLI inspect/preflight/install dry-run, интерактивный выбор домен/IP, закрытый или публичный TLS policy, необязательный `--manager`, отказ от apply |
| `ftm/preflight.py` | Чтение ресурсов/ОС/root/systemd/портов, список недостающих инструментов и непроверенных условий |
| `scripts/verify_baseline.py` | Проверка всех сохранённых файлов по SHA256; отказ при подмене, отсутствии, symlink и выходе пути из baseline |
| `scripts/smoke_baseline.py` | Linux runtime help, CID add/list/remove во временной базе, loopback startup/version/shutdown; не VPN-тест |
| `scripts/validate_linux.py` | Полный прогон в изолированной временной Linux-копии, без установки пакетов или служб |
| `tests/`, `.github/workflows/verify.yml` | Unit/CLI/PTY/файловые проверки; workflow подготовлен, но на GitHub ещё не запускался |
| `docs/BASELINE.md`, `docs/DECISIONS.md`, `docs/IMPLEMENTATION_PLAN.md` | Проверенные контракты, ограничения, решения, требования миграции и последовательный план |
| `ftm/ssh_protection.py`, `scripts/verify_ssh_protection.py` | Применение годовой защиты SSH с бэкапом/откатом; реальная проверка фильтра, порога, nftables и persistence на тестовом VPS |
| `ftm/baseline_deploy.py`, `tests/test_baseline_deploy.py` | Явный запуск исходного Vps на согласованном тестовом VPS с заменой только hook годового Fail2ban; baseline не меняется |
| `ftm/store.py`, `ftm/migrations/001_initial.sql`, `ftm/metadata_cli.py` | WAL/FK/транзакции, пользователи и независимые устройства, идемпотентность, безопасный metadata import, audit и SQLite Backup API |
| `ftm/agent.py`, `scripts/verify_devices.py` | Проверенные на VPS hot add/revoke, атомарный CID/config update и ownership registry; неизвестные peers/CID сохраняются, службы не перезапускаются |
| `scripts/verify_recovery.py` | Реальный restore на том же VPS и rollback после инъекции ошибки; ключи, импорт и SSH сохранены |

## Проверки

Последний полный локальный прогон —115 tests: Windows110PASS/5skips, WSL109PASS/6web dependency skips, baseline8 и binary smoke PASS. Ниже сохранена историческая матрица ранних этапов; результаты новых блоков находятся в документах выше.

| Проверка | Результат |
| --- | --- |
| Исходные тесты Vps, Ubuntu WSL / Python 3.12.3 | **PASS: 8/8**, без пропусков |
| Тесты Manager, Ubuntu WSL / Python 3.12.3 | **65/65 PASS**, без пропусков |
| Тесты Manager, Windows / Python 3.10.11 | **75 PASS**, 5 Linux-only/crypto пропусков; всего 80 тестов |
| Тесты на отдельном VPS 1 vCPU/961 MiB | **80/80 Manager + 8/8 Vps PASS** |
| Годовая политика Fail2ban на VPS | **PASS**, filter/threshold/nftables/SQLite/restart, test ban удалён, fresh SSH успешен |
| Первая и повторная установка базового VPN | **PASS**, все ключи/CID/параметры сохранены при повторе; 3 службы active, 2 peers |
| Зашифрованный бэкап вне VPS | **PASS**, ciphertext и recovery file сохранены вне Git; decrypt/parse проверен на VPS и локально, ключ соответствует выданному iPhone-профилю |
| Recovery / injected rollback | **PASS** на том же VPS, до начала metadata migration; не второй чистый VPS |
| iPhone через VK | **PASS**, результат пользователя + серверные handshake/rx/tx; после recovery снова наблюдался трафик |
| Dynamic peer control | **PASS**, реальный add/revoke синтетического WG peer без рестарта, replay persistent config в network namespace, сохранение unknown sentinel |
| Encrypted SQLite checkpoint | **PASS**, Backup API → encryption → offsite decrypt → integrity check; это ещё не общий автоматический Manager restore |
| SHA256 baseline + исходный package verifier | **PASS**, все 23 файла, бинарники amd64/arm64 и архив |
| Bash syntax | **PASS** |
| Реальный Linux amd64 binary smoke | **PASS**, help/CID/startup/shutdown; не VPN-трафик |
| Bash entrypoint + JSON config dry-run | **PASS**, без изменений системы |
| Host preflight на текущем WSL | Ожидаемый код **2**, blockers/missing tools перечислены ниже; не утверждает готовность установки |

Команда полного прогона из Windows:

```powershell
wsl -d Ubuntu-24.04 -- python3 /mnt/c/project/FTM/scripts/validate_linux.py
```

Основной unit/CLI/binary прогон не запускает исходный установщик Vps и не меняет системные службы или firewall. Отдельная явно разрешённая операция `secure-ssh --apply` меняет только Fail2ban. Дополнительно пользователь разрешил реальную установку базового VPN через `ftm.baseline_deploy`: добавлены его службы, интерфейс и scoped firewall rules. Это отдельная операция, общий install/apply Manager остаётся недоступным.

### Что подтверждено локально

- Хеши файлов baseline, обоих транспортных бинарников и исходного runtime-архива.
- Восемь исходных тестов Vps, включая настоящий OpenSSL backup round-trip, неверную парольную фразу и подмену ciphertext.
- Чистый repeatable план, отказ от fresh поверх переданного/обнаруженного legacy state, наследование портов/subnet и неизменность входных данных.
- Отсутствие секретов из legacy state в inspect/plan и содержимого повреждённого файла в CLI-ошибках.
- JSON schema/type/size/duplicate-key checks, POSIX 0600 и symlink rejection.
- Мастер в настоящем псевдотерминале без `--domain`, non-interactive config и отмена по EOF/SIGINT.
- Генерация настоящим исходным profile writer двух независимых синтетических импортов, их round-trip и root-only режимы файлов в Linux.
- Запуск **закреплённого amd64-бинарника** с настоящим baseline wire-профилем `rtpopus3` и `-obf-key-file` на синтетическом ключе, проверка версии по startup log (флага `-version` нет), операции с CID и завершение локального listener.

### Среда

Windows Python 3.10.11; Ubuntu 24.04 WSL Python 3.12.3, kernel `6.18.33.2-microsoft-standard-WSL2`. WSL сообщает 12 CPU и около 15.5 GiB RAM — **это не стенд 1 vCPU/1 GiB**. Производительность и ресурсные цели на минимальном VPS не измерялись.

Read-only preflight на WSL корректно возвращает код 2: пользователь не root, `wg` и `iptables` отсутствуют. Ничего не доустанавливалось. Полные файловые тесты идут на Linux storage, а не на NTFS, где режим 0600 может не применяться.

Дополнительная среда: отдельный VPS Ubuntu 24.04.4 LTS amd64, **1 vCPU / 961 MiB RAM**, диск около 58 GiB, SSH 22. Установлены Fail2ban 1.0.2, python3-systemd, nftables, iptables, WireGuard tools, qrencode и FreeTurn 4.1.2-vps1. Прошли unit/CLI/binary проверки и повторная установка. Нагрузочный benchmark VPN ещё не выполнен. Подробности — в [отчёте SSH](SSH_PROTECTION.md) и [проверке iPhone](IPHONE_TEST.md).

## Матрица приёмки и незавершённые проверки

| Проверка | Статус и причина |
| --- | --- |
| Свежая установка/повторная установка исходного Vps на Ubuntu 24.04 1 vCPU/1 GiB | PASS с отдельным годовым Fail2ban hook; без заимствования полного Manager installer |
| Настоящие `vps-vk status`, генерация profiles/QR | PASS — службы active, два peers, private artifacts 0600; миграция старого рабочего VPS NOT RUN |
| Android ↔ сервер 4.1.2-vps1; Anton48 через VK TURN | iPhone PASS пользователем и на сервере; Android NOT RUN для этой установки |
| Активный CID hot reload и отзыв уже открытой сессии | SOURCE ONLY — polling 10 с подтверждён в pinned source; поведение трафика не проверено |
| WireGuard data plane, Direct/Relay E2E, DNS/IPv6 leaks | iPhone VK data plane PASS. Direct/Auto, DNS/IPv6 leaks, новые devices и три одновременных клиента NOT RUN |
| Бэкап и восстановление | Managed/web v2 offsite decode и same-host restore/rollback PASS; настоящий reboot PASS. Чистый хост и ACME cache recovery NOT RUN |
| Полная Android/Windows сборка, arm64 execution, Go rebuild | NOT RUN; Desktop checkout больших binary blobs не завершился из-за сети, текстовые исходники изучены отдельно |
| Trusted TLS/IP, Caddy, API/React | PASS на тестовом VPS; domain migration NOT RUN. Не все вкладки MVP завершены |
| Подписки, автофейловер, Windows driver/service | NOT IMPLEMENTED — последующие этапы |
| GitHub CI и публикация | NOT RUN — изменения локальные, push не выполнялся |

## Совместимость и откат

Baseline не изменён. `install --dry-run`, `inspect` и `preflight` не применяют системные изменения. В binary smoke используется только временная CID-база и ephemeral loopback listener. `secure-ssh --apply` — отдельно разрешённое изменение Fail2ban. `ftm.baseline_deploy --apply` разрешён пользователем только для тестового VPS: первая установка создаёт ключи, повторная сохраняет их. SSH не перезапускался, MainPID 712 и NRestarts 0 сохранены, свежий SSH-вход после развёртывания успешен.

Откат Fail2ban и baseline VPN реально проверены. Metadata импортированы в SQLite без WG private keys и VK link. Новые manager devices применяются отдельным root агентом; legacy revoke/enable разрешены только после проверенного root adoption и на тестовом VPS уже проверены. SQLite/CID/PSK и registry хранятся private. Combined managed VPN checkpoint и same-host restore/rollback проверены; финальный clean-host Manager restore ещё не готов; исходный Vps остаётся в `vendor/vps/`.

## Следующий конкретный шаг

Managed startup, checkpoint, IPC, русская панель, IP/internal HTTPS и client registration/subscriptions проверены. Следующий шаг — bootstrap/claim и admin re-auth/export этапа4. Android, live new-CID authorization и три настоящих клиента остаются открытыми проверками. [Client API](CLIENT_API.md), [очередь этапов](IMPLEMENTATION_PLAN.md).

Рабочий VPS по-прежнему не используется как тестовая среда. Новый тестовый VPS предоставлен пользователем отдельно; доступ и изменение его Fail2ban разрешены текущим поручением.
