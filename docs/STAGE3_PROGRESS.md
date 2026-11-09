# Private API и первая русская панель

10.11.2026. Это рабочий private milestone этапа 3, не финальная приёмка всего этапа: публичный Caddy/TLS и клиентские подписки ещё впереди.

## Что работает на тестовом VPS

- Rootless `ftm-api.service`, UID `ftm-api`, bind **127.0.0.1:8080**. Публичных HTTP-портов не добавлено. Для доступа используется SSH forwarding. `/` — нейтральная страница; панель по случайному пути, который хранится только в закрытом login note.
- Root-owned `/etc/ftm` 0700, `web.json` 0600. API получает read-only копию через systemd `LoadCredential`; root SQLite и VPN keys ему напрямую недоступны. Metadata управляется через проверенный Unix IPC с SO_PEERCRED.
- Scrypt N=2^15/r=8/p=3, случайная соль, серверные opaque sessions с TTL 4 часа, HttpOnly/SameSite=Strict cookie, CSRF и Origin для изменений, login rate limit. Logout удаляет серверную сессию. Secure cookie предусмотрена для HTTPS; в текущем loopback HTTP/SSH режиме она выключена. Публичного HTTP login нет.
- Пользователи: список, создание с лимитом, отключение/включение. Устройства: отдельный public key, создание, отключение/включение с подтверждением. Обычные списки не содержат CID, PSK или private keys. Генерация готовых новых клиентских профилей и enrollment остаются этапом 4.
- React/Vite/Tailwind, RU интерфейс, light/dark, поиск/фильтр, таблицы на desktop и карточки на мобильном. Сборка выполнялась на рабочем компьютере; Node на VPS не устанавливался.
- Настоящие CPU/RAM/WG transfer/latest-handshakes через отдельный metrics RPC. Первый CPU sample неизвестен до следующего чтения. График хранит реальные samples в памяти браузера. Traffic — с момента создания WG interface; история месячного трафика пока не ведётся. Recent activity — оценка по handshake, не E2E.

## Что проверено

Через браузер по SSH forwarding к настоящему API выполнены неправильный/правильный login, создание тестового пользователя, поиск/empty state, disable/enable, создание synthetic WG device и disable/enable. На сервере подтверждены **3 реальных kernel peers** во время проверки. Финальное отключение тестового пользователя отозвало его устройство; снова **2 исходных peers**.

WG/CID/registry/state/obf/iPhone import совпали с hash до UI CRUD. MainPID VPN и SSH не изменились **при этих действиях**. Отдельная последующая проверка restore преднамеренно перезапускала FreeTurn/API; её нельзя смешивать с hot CRUD результатом.

Проверены logout и повторный вход, Escape/cancel форм, навигация, light/dark и 390×844 mobile. Снимки просмотрены, горизонтального overflow на desktop/mobile нет; ошибка JS не наблюдалась. После поправки мобильные поля ввода имеют 16 px. Это browser emulation, не физический iPhone/Android тест. [Сценарии и снимки](UI_QA.md).

Windows venv: **89 tests**, 84 PASS, 5 платформенных/crypto skips. Это существующие проверки и несколько новых целевых security cases, без покрытия каждого UI-компонента. Production build: JS около 257 KB / 78 KB gzip, CSS около 32 KB / 7 KB gzip. `pip check` PASS, npm audit при установке — 0 vulnerabilities. GitHub CI подготовлен с pinned/hash-checked Python dependencies; remote CI пока не запускался.

Во время проверки по systemd API занимал около **33–35 MiB**, наблюдавшийся peak около **66 MiB** после login; control worker около **11 MiB**, FreeTurn около **12 MiB**. Это замер этой проверки, не нагрузочная гарантия. Существующий CPUQuota FreeTurn не менялся.

## Копия и восстановление панели

Checkpoint v2 включает root web config (password hash и секретный path), metadata/registry/VPN. Opaque sessions не архивируются: после restore нужен новый login. Ciphertext скачан вне VPS и расшифрован/staged в WSL с integrity/schema/ownership checks. На самом VPS временно изменён admin username, выполнены restore и injected rollback; исходная web identity вернулась, при rollback вернулась предыдущая изменённая identity. Финальный snapshot совпал с оригиналом, после восстановления login через браузер снова прошёл.

Root login note не публикуется и не входит в Git; файл для пользователя скачан в закрытый локальный каталог. Текущий restore — тот же provisioned host с тем же baseline identity. Чистый VPS, миграция IP, публичный TLS, три настоящих клиента и phone E2E после reboot остаются открытыми gates. [Точный scope](CHECKPOINT.md).

Следующие задачи: Caddy/trusted TLS или подтверждённый private режим, постоянный reconciler и stage 4 registration/subscriptions/bootstrap. Затем доступная работа Android/Windows по ТЗ. Полный installer остаётся dry-run.
