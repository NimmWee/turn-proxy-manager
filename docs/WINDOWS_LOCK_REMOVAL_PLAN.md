# Удаление постоянной блокировки сети — Windows0.24

Поручение18.11.2026: полностью убрать отдельную функцию «Блокировка сети». Не продолжать прерванные performance tests в рамках этого изменения. Без субагентов.

Удалить UI, IPC enable/disable, capability/status, CLI включения/выключения и весь код установки persistent WFP rules. Временная изоляция работающего VPN, domain BLOCK, DNS/IPv6 protection остаются частью работающего VPN; самостоятельной блокировки после его отключения больше нет. Для перехода с0.23 — только delete-only migration с fixed GUIDs при guarded elevated setup/uninstall, без создания фильтров и без действий в status/preview/connect.

Read-only проверка установленного0.23: туннель остановлен; аутентифицированный broker status networkLock=unknown. Прямой provider lookup вернул0x80320005, FWP_E_PROVIDER_NOT_FOUND: правил нет. В0.23 этот корректный код отсутствия ошибочно не распознавался; удаляется зависимость Connect от проверки persistent provider. Никакой очистки/переключения VPN для проверки не выполнялось.

- [x] Целевая проверка delete-only migration: missing provider/no-op, точные owned keys, transaction rollback/ошибки доступа; прежние enable/disable IPC отвергаются.
- [x] Удалить feature code/UI, восстановить обычный runtime firewall, подключить cleanup только к setup/uninstall.
- [x] Обновить ТЗ/остаток/README, собрать отдельный0.24, проверить Go/C#/embedded UI/offline/package.
- [x] Подготовить переход установленного idle0.23 с сохранением ключей/данных; фактическую проверку/ограничения записать отдельно.

## Выполнено и проверено18.11

- Удалены `NetworkLockWindow.cs`, entry в MainWindow/native scenario, status поле/capability, enable/disable IPC и старый CLI `--network-unlock`. Удалён весь `internal/lockfirewall` с установкой provider/filter/allowances. Временный firewall активного system runtime снова использует обычный динамический официальный backend и освобождается при Close.
- `internal/legacylock` содержит только Remove для fixed GUIDs0.23. Отсутствующий provider0x80320005 — успешный no-op без транзакции/записей. При существующем provider удаляются256 известных filter keys, собственные sublayer/provider в одной транзакции; ошибки доступа/commit вызывают abort, чужие объекты не перечисляются и не удаляются. Установка/создание правил в этом пакете отсутствует. Upgrade запускает миграцию в replacement после остановки старого broker; её отказ проходит обычный rollback/restart старой службы.
- Go test/vet/release build PASS; целевые проверки no-op/owned GUIDs/rollback/access и отказа старым IPC PASS. Старый CLI возвращает usage/exit2 без elevated действий. C# build и существующие DPAPI/key/catalog/managed/policy/network suites PASS. Native single-window сценарий PASS, отдельная блокировка отсутствует. Offline state digest unchanged, routing preview PASS; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK корректно оставляет другой VPN нетронутым. Baseline23 files/vendor package PASS.
- Установленное ядро обновлено через штатный guarded elevated setup, exit0. Реальный helper подтвердил NetworkChanged=false (routes/adapters), EncryptedDataPreserved=true (ciphertext digest профиля/options/ключевых DPAPI файлов/каталога и owner), TunnelStarted=false. Старые бинарники сохранены обычным механизмом upgrade;0.23 preview ZIP/payloads не перезаписаны.
- Аутентифицированный IPC после обновления: ServiceVersion0.24.0, State=stopped, HasProfile=true, lock capability отсутствует. Оба старых enable/disable запроса действительно отвергнуты установленной службой с UNKNOWN_OPERATION. Туннель остаётся stopped. Попытка непривилегированного чтения installed EXE hash отклонена DACL; это не сравнение хешей и не mismatch, проверка установленного ядра выполнена authenticated SCM/pipe/version путём.
- На этом компьютере legacy provider изначально отсутствовал. Реальное удаление присутствующего provider **NOT RUN**; проверена delete-only транзакция на fake ops и реальный absent-provider переход. VPN Connect, leak/performance/sleep/remote/VPS проверки не запускались. Прерванный performance benchmark не продолжался.

Артефакт: `clients/windows/artifacts/FreeTurn-Windows-0.24.0-preview-win-x64.zip`, 90.43MiB,15 payloads/209 соответствующих исходников/81 notices. SHA256 `fd77db212a809b39637e45c41b9212b2f5abc3ef43708fb8bb3b9e9c2448ab44`. Хеши и source correspondence PASS,0.23 ZIP/payloads unchanged. Пользователю запускать UI0.24 из нового пакета, чтобы совпадала версия с установленным ядром.
