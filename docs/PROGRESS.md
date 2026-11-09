# Ход работ

**Обновлено:** 10.11.2026, Asia/Tomsk.

## Текущий этап

**Обновление managed migration:** на тестовом VPS явно приняты под управление оба legacy peer; revoke/enable неактивного Android peer и dynamic status 1/2/3 peers PASS, профиль iPhone сохранён. Отложенные add/revoke/enable проверены на копии SQLite/config с настоящим WG в отдельном network namespace. Текущие тесты: **77/77 Manager на VPS**, Windows 73 PASS / 4 Linux skips; SHA256 всех 23 baseline файлов совпали. `/opt/ftm`, совместимый системный wrapper, startup hook и общий encrypted restore ещё не установлены. Старые результаты ниже описывают предыдущие checkpoints.

По поручению пользователя включены почасовые запуски разработки в этом чате до **10.11.2026 09:20 Asia/Tomsk**. Очередь и точное состояние передачи: [NIGHT_WORK.md](NIGHT_WORK.md). Это не обещание завершения всего ТЗ за ночное окно.

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

Последний полный локальный прогон:

| Проверка | Результат |
| --- | --- |
| Исходные тесты Vps, Ubuntu WSL / Python 3.12.3 | **PASS: 8/8**, без пропусков |
| Тесты Manager, Ubuntu WSL / Python 3.12.3 | **65/65 PASS**, без пропусков |
| Тесты Manager, Windows / Python 3.10.11 | **61 PASS**, 4 Linux-only пропуска; всего 65 тестов |
| Тесты на отдельном VPS 1 vCPU/961 MiB | **65/65 Manager + 8/8 Vps PASS** |
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
| Бэкап и восстановление | Offsite ciphertext и same-host restore при отсутствующем state PASS; injected rollback PASS. Второй чистый хост и полный reboot NOT RUN |
| Полная Android/Windows сборка, arm64 execution, Go rebuild | NOT RUN; Desktop checkout больших binary blobs не завершился из-за сети, текстовые исходники изучены отдельно |
| Trusted TLS/domain/IP, Caddy, API/React, подписки, автофейловер, Windows driver/service | NOT IMPLEMENTED — последующие этапы |
| GitHub CI и публикация | NOT RUN — изменения локальные, push не выполнялся |

## Совместимость и откат

Baseline не изменён. `install --dry-run`, `inspect` и `preflight` не применяют системные изменения. В binary smoke используется только временная CID-база и ephemeral loopback listener. `secure-ssh --apply` — отдельно разрешённое изменение Fail2ban. `ftm.baseline_deploy --apply` разрешён пользователем только для тестового VPS: первая установка создаёт ключи, повторная сохраняет их. SSH не перезапускался, MainPID 712 и NRestarts 0 сохранены, свежий SSH-вход после развёртывания успешен.

Откат Fail2ban и baseline VPN реально проверены. Metadata импортированы в SQLite без WG private keys и VK link. Новые manager devices применяются отдельным root агентом; старые legacy revoke/disable пока отклоняются до managed startup migration. SQLite/CID/PSK и registry хранятся private. Combined Manager backup/restore ещё не готов; исходный Vps остаётся в `vendor/vps/`.

## Следующий конкретный шаг

Закрыть managed startup migration и динамическую совместимость legacy CLI, ввести общий encrypted checkpoint VPN + SQLite + registry и проверить reboot/restore. Затем — ограниченный IPC/права перед FastAPI и русской панелью. Android, live new-CID authorization и три настоящих клиента остаются открытыми проверками. [План](STAGE2_PLAN.md), [результаты](STAGE2_PROGRESS.md).

Рабочий VPS по-прежнему не используется как тестовая среда. Новый тестовый VPS предоставлен пользователем отдельно; доступ и изменение его Fail2ban разрешены текущим поручением.
