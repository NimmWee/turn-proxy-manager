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
