# Журнал событий в панели

10.11.2026. Read-only `events.list` через существующую UID boundary, integer limit1..200. Возвращаются только id/action/subject_type/subject_name/ts. Raw details, credential hashes, токены, ключи и SQL из запроса не выдаются. Authenticated GET `/api/events` внутри секретного admin prefix; обычный session/Host guard сохранён.

RU «Журнал»: последние100 записей, поиск по понятному названию события/имени, дата в локальном часовом поясе браузера, empty state и refresh. UUID и технические action codes не отображаются. Это изменения доступа/устройств, не история посещённых сайтов и не raw system journal. Неизвестные будущие actions имеют нейтральную подпись.

Production build на ПК PASS: JS259.3KB/79.02KB gzip, CSS33.21KB/7.44KB gzip. Новых UI автотестов не добавлено: существующие6 control/web boundary cases PASS, затем настоящий HTTPS браузер. Проверены92 реальных audit events, поиск/пустой результат, desktop1440×1000/light и mobile390×844/dark, отсутствие horizontal overflow/JS errors. Скриншоты `logs/events-desktop.png`, `logs/events-mobile-dark.png` (ignored).

Реальный anonymous GET401; authorized200, <=100 rows и только allowlisted response fields. Root IPC отверг limit0/201/bool/string, limit7 вернул не больше7. После runtime/API/control обновления PID VPN/SSH/Caddy не изменились; API/control перезапускались для загрузки кода. БД/ключи/профиль не менялись. Baseline23 hashes и исходный package verifier PASS.

Runtime **46acba450725bbf4**. Последний offsite checkpoint остаётся `/root/ftm-managed-e3336b9bbf.vpnbackup`, SHA256 **dab56a048c677b26e80f487e58824dfbc5f01978efe5628b7f91efd5fd2cf0ca**: журнал только читал данные, новый snapshot не требовался. Bootstrap/public enrollment и оставшиеся вкладки ещё впереди. Клиентский physical E2E этим не подтверждается.
