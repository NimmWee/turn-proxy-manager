# Ход работ

**Обновлено:** 10.11.2026, Asia/Tomsk.

## Текущий этап

**Этап 1 — локальная реализация подготовлена; полная E2E-приёмка не подтверждена.** К реализации этапов 2–8 пока не переходили. Следующий обязательный шаг — воспроизвести исходный VPN на тестовом VPS и проверить реальные Android/iPhone, затем начинать SQLite/динамические устройства.

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

## Проверки

Последний полный локальный прогон:

| Проверка | Результат |
| --- | --- |
| Исходные тесты Vps, Ubuntu WSL / Python 3.12.3 | **PASS: 8/8**, без пропусков |
| Тесты Manager, Ubuntu WSL / Python 3.12.3 | **PASS: 31/31**, без пропусков |
| Тесты Manager, Windows / Python 3.10.11 | **PASS: 27**, 4 платформенных пропуска (права POSIX, PTY, Linux inventory и Linux binary smoke); все четыре прошли в Linux |
| SHA256 baseline + исходный package verifier | **PASS**, все 23 файла, бинарники amd64/arm64 и архив |
| Bash syntax | **PASS** |
| Реальный Linux amd64 binary smoke | **PASS**, help/CID/startup/shutdown; не VPN-трафик |
| Bash entrypoint + JSON config dry-run | **PASS**, без изменений системы |
| Host preflight на текущем WSL | Ожидаемый код **2**, blockers/missing tools перечислены ниже; не утверждает готовность установки |

Команда полного прогона из Windows:

```powershell
wsl -d Ubuntu-24.04 -- python3 /mnt/c/project/FTM/scripts/validate_linux.py
```

Проверки не запускают исходный установщик Vps и не меняют WireGuard/firewall/systemd.

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

## Не выполнено / не подтверждено

| Проверка | Статус и причина |
| --- | --- |
| Свежая установка/повторная установка исходного Vps на чистой Ubuntu 24.04 1 vCPU/1 GiB | NOT RUN — пользователь подтвердил, что доступен только рабочий VPS; отдельного тестового VPS и разрешённого deploy нет |
| Настоящие `vps-vk status`, `vps-vk profiles`, миграция существующей установки | NOT RUN — не подключались к рабочему VPS; synthetic files не подменяют этот тест |
| Android 5.3.2 ↔ сервер 4.1.2-vps1; Anton48 через VK TURN | NOT RUN — нет реальных устройств/операторской сети/CAPTCHA в тестовой среде |
| Активный CID hot reload и отзыв уже открытой сессии | SOURCE ONLY — polling 10 с подтверждён в pinned source; поведение трафика не проверено |
| WireGuard data plane, Direct/Relay E2E, DNS/IPv6 leaks | NOT RUN — binary smoke не передаёт пользовательский VPN-трафик |
| Бэкап вне VPS и восстановление на чистом VPS | NOT RUN — локальная криптография проверена, production recovery нет |
| Полная Android/Windows сборка, arm64 execution, Go rebuild | NOT RUN; Desktop checkout больших binary blobs не завершился из-за сети, текстовые исходники изучены отдельно |
| Trusted TLS/domain/IP, Caddy, API/React, подписки, автофейловер, Windows driver/service | NOT IMPLEMENTED — последующие этапы |
| GitHub CI и публикация | NOT RUN — изменения локальные, push не выполнялся |

## Совместимость и откат

Baseline не изменён. Ни одна команда Manager не применяет системные изменения, не заменяет ключи, не перезапускает VPN/SSH и не добавляет правила firewall. В smoke используется только временная CID-база и ephemeral loopback listener, процесс завершается в finally.

Системный rollback для текущего шага не требуется: на сервер ничего не устанавливалось. Для отката локальной разработки используется история Git; исходный Vps остаётся в `vendor/vps/`. Настоящие snapshot/apply/rollback и импорт в SQLite пока не реализованы.

## Следующий конкретный шаг

На отдельном тестовом VPS зафиксировать исходное состояние/службы/правила, сохранить зашифрованную резервную копию вне VPS, проверить восстановление. Выполнить исходный install/reinstall, `status` и `profiles`; подтвердить трафик Android и Anton48 через VK, а также SSH после проверки. Зафиксировать SHA клиента и сценарий CAPTCHA. После этого закрыть gate этапа 1 и реализовать этап 2: SQLite users/devices и минимальный привилегированный agent.

Наличие только рабочего VPS не считается разрешением на его изменение. Проверку fresh install нельзя проводить поверх рабочей установки.
