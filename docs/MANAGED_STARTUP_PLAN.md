# Управляемая загрузка и совместимость legacy CLI

Пользователь поручил продолжать после рабочего metadata/agent milestone. Работа одним агентом; исходный `vendor/vps/` не меняется. API/панель только после устранения startup/revoke ограничений.

- [x] Ввести отдельную управляемую ownership-модель для старых устройств. Явное root adoption проверяет соответствие SQLite, live peers, CID и persistent WG config исходному state, сохраняет peer keys/PSK/IP/IPv6 и ссылки. Сначала только config/registry, без перезапуска служб.
- [x] После успешного adoption разрешить metadata revoke/enable старых устройств; privileged agent принимает legacy операции только по ранее подтверждённому root registry. Защита от присвоения чужих peers сохраняется.
- [x] Persistent WG config — полная конфигурация backend с пометками только собственных blocks. Network-up загружает её без повторного legacy render. Перед загрузкой идёт reconcile desired/registry/config, чтобы отказ между SQLite commit и системным вызовом не воскрешал отозванные устройства.
- [x] Новый совместимый `vps-vk status` учитывает динамические devices/actual peers, не число 2. Обычные `profiles` сохраняют формат активного iPhone и не возвращают отозванные профили. Старые install/restore/render не выполняются поверх managed state.
- [x] Установить root-owned runtime в `/opt/ftm` и ограниченные systemd oneshot/service hooks с фиксированными путями, без web-root. До HTTP API не менять DB ownership и не выдавать непривилегированному процессу прямой root SQLite доступ.
- [x] Общий encrypted checkpoint: согласованные SQLite Backup API, root registry, baseline keys/config, scoped network metadata; аутентификация до распаковки, allowlist путей/размеров, запрет symlink/кодовых файлов в backup. Проверка restore на временном каталоге и rollback на тестовом VPS.
- [x] Проверить adoption без смены профиля/handshake, revoke/reenable синтетического legacy Android peer (не активного iPhone), dynamic status с новым устройством, startup replay. Полный reboot выполнить только с сохранённым offsite checkpoint и проверенным аварийным восстановлением SSH/сети.
- [ ] После этого подготовить фиксированный IPC/ACL для непривилегированного API, затем FastAPI/панель; не объявлять Android E2E или три реальных клиента проверенными по синтетическим тестам.

Промежуточный результат: adoption и revoke/enable PASS на тестовом VPS; dynamic status/profiles реализован, системный wrapper пока не установлен. Offline preparation и загрузка 1/3/2 peers проверены в изолированной netns на копии metadata. Полный reboot, deployment hook и общий encrypted restore остаются открытыми. Ночное продолжение: docs/NIGHT_WORK.md.

10.11.2026: runtime wrappers/hook установлены. Общий managed checkpoint и offsite staged restore, same-host recovery/rollback, real service startup и host reboot PASS. Общий backup ещё не включает отсутствующие Caddy/API настройки; clean-host restore остаётся задачей installer. Следующий блок — docs/IPC_PLAN.md.
