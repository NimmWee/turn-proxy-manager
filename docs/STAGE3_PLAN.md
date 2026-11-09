# План: API и русская панель

Исполнение: executing-plans, один агент. Дизайн — `STAGE3_DESIGN.md`, требования — основной ТЗ. Предпочтение пользователя: целевые проверки рисков вместо полного автотестового покрытия.

- [x] Зафиксировать текущий IPC результат и свежую offsite копию; завершить unit/systemd checks ограниченного control service. Root SQLite ownership сохранить.
- [x] `ftm/metrics.py`, `ftm/control.py`: allowlisted metrics RPC с настоящими CPU/RAM/WG totals/handshake estimates; без dump приватных ключей и без публикации CID.
- [x] `ftm/web_auth.py`: scrypt credentials, bounded sessions и login rate limit. Целевые проверки сессии/отзыва/CSRF и неверных credentials.
- [x] `ftm/web.py`: FastAPI factory, приватный path, auth и CRUD к Unix client, Origin/CSRF, schema/body limits, безопасные ошибки/headers. Никакой прямой root DB связи. Pin FastAPI/Uvicorn; production API loopback-only на данном шаге.
- [x] `web/`: React/Vite/Tailwind, RU overview/users/devices, формы и статусы, light/dark и мобильный layout. Сборка на рабочем компьютере, не на VPS. Не рисовать отсутствующие функции как готовые.
- [x] `ftm/web_install.py`: root-owned venv/runtime/static, отдельный ftm-api unit без capabilities и root metadata доступа, private web config и root-only login note. Свежий checkpoint до deploy; не открывать публичные порты и не перезапускать VPN/SSH.
- [x] Реальная проверка browser + HTTP auth/CRUD/CSRF/logout, ресурсы и сохранность профиля. Обновить docs, локальный commit без GitHub push.
- [ ] После рабочего private UI: расширить checkpoint root web settings и подготовить Caddy/trusted TLS и re-auth backup trigger. Затем доступные этапы подписок и клиентов.
