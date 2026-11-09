# Следующий блок: непривилегированный API и root-owned metadata

После управляемой загрузки и проверенного checkpoint нужен локальный IPC. API и веб-сервер не должны получать root или право записи в `/var/lib/ftm/manager.sqlite3`. В текущей реализации root agent и startup читают эту БД; её chown на пользователя API создал бы небезопасную границу.

Выбранный путь: отдельный root service владеет metadata и сетевыми операциями. Непривилегированный `ftm-api` обращается к Unix socket через строго ограниченный JSON протокол. Это сохраняет root-owned SQLite и позволяет оставить startup reconcile до появления отдельного безопасного metadata worker.

1. Socket `/run/ftm/control.sock`, каталог root-owned без права записи API, mode 0660 root:ftm-api. Проверять SO_PEERCRED: только root и точный UID системного ftm-api; принадлежности группе недостаточно. Ограничить размер сообщения, время чтения, очередь и число обработчиков. Содержимое запросов не логировать.
2. Разрешить только заранее описанные операции status, users list/create/enable/disable и devices list/add/revoke/enable. Поля и типы — allowlist; не принимать SQL, shell, пути, unit names или произвольные network arguments. Выдачу секретного device config/bootstrap добавить отдельным контрактом следующего этапа, обычные списки остаются redacted.
3. Root service сам вызывает Store и NetworkAgent под существующим lifecycle flock. Device add идемпотентен по request_id, IP/CID/keys выделяются транзакционно. Ошибка системного применения сохраняет pending/error для повторения, не выдаёт ложный успех.
4. Hardened systemd unit с фиксированными writable paths и CAP_NET_ADMIN для существующего WG. Отдельный rootless API unit — только доступ к socket, без sudo и доступа к VPN keys. Не открывать публичные HTTP endpoints до auth/TLS.
5. Целевые проверки границы: чужой UID и неизвестная/слишком большая команда отклоняются; от API UID выполняется реальный add/revoke синтетического peer без изменения профиля iPhone. Без автотеста на каждую вспомогательную функцию. После этого FastAPI и сборка русской панели вне VPS.

Реализовано и установлено на тестовом VPS: `ftm.control`, `ftm.control_install` и `ftm-control.service`. SQLite остаётся root:root 0600, socket root:ftm-api 0660 в каталоге 0750. От API UID выполнены настоящий hot add, идемпотентный повтор и revoke; чужой UID с той же группой отвергнут. Неизвестная команда и path field отвергнуты, API не читает SQLite/registry/obf key напрямую. Config/profile и MainPID VPN/SSH после проверки совпали. Три целевых boundary tests PASS. Maintenance lock возвращает unavailable меньше чем за секунду вместо блокировки worker.

Добавлен metrics RPC с CPU/RAM и WG transfer/latest-handshakes, без credential-bearing dump. Обычный worker занимал около 11 MiB по systemd. Постоянного reconcile timer ещё нет; изменения из IPC применяются сразу, error outbox остаётся повторяемым. Общий checkpoint расширяется настройками private API при их появлении.
