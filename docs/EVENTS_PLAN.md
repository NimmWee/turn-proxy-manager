# Журнал изменений в панели

Независимый read-only блок этапа3 из обязательных вкладок ТЗ. До ночного cutoff. Не добавлять mutation, raw service logs, секреты, website browsing history или произвольный SQL.

- [x] Ограниченный `events.list` IPC: только integer limit1..200; SELECT явных audit metadata и имени subject, без sanitized_details/raw credentials/hash/SQL parameters от клиента.
- [x] Authenticated GET API и RU секция панели: последние100 событий, поиск по событию/имени, дата, пустое состояние, refresh, desktop/mobile/light/dark. Не показывать UUID/технические action codes пользователю.
- [x] Production build на ПК; deploy после актуального offsite checkpoint, без VPN/SSH restart. Реальный unauthorized401, ограничение limit, отсутствие credential fields и browser navigation/search/mobile. Обычная UI функция — без новых автотестов каждого компонента.
- [x] Docs/local commit и итоговая health проверка. После08:20Томск новые изменения не начинать.

