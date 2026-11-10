# Публичная панель по доверенному HTTPS

Продолжение согласованного ТЗ и ночного поручения. Brainstorming/writing-plans/executing-plans, без субагентов и новых пользовательских вопросов. HTTPS probe уже проверен; используем тот же public IPv4 и сертификат. Домен требует отсутствующих внешних данных, поэтому не добавляется автоматически.

Выбран отдельный root-only enable поверх проверенного private API. Простой reverse proxy без изменения auth отвергнут: он оставил бы HTTP cookie/Origin. Новый формат web credentials v2 хранит canonical HTTPS origin и требует Secure cookie; v1 остаётся private. Origin сравнивается с фиксированной конфигурацией, Host allowlist расширяется одним IP. Uvicorn доверяет forwarded headers только loopback Caddy; публичного bind API нет.

- [x] Целевые security cases для config/origin/Secure cookie, затем минимальное изменение `ftm/web_auth.py` и `ftm/web.py`.
- [x] Доверенный Caddy renderer: secret panel path проксируется только в HTTPS, `/` и все остальные пути нейтральные. HTTP не обслуживает login. В request/error logs секреты не попадают.
- [x] `ftm/https_edge.py`: fixed-file root enable с matching offsite checkpoint и trusted certificate; rollback после любого отказа. Private web config обновляется через LoadCredential restart, root note остаётся вне Git. VPN/SSH не перезапускаются при enable.
- [x] Checkpoint v2 сохраняет новый web config; same-host restore регенерирует Caddy config доверенным кодом из web settings, останавливая edge до смены auth. Исполняемые units/config из backup не принимаются. ACME cache остаётся на уже provisioned host; clean-host restore пока не поддерживается.
- [x] Сборка/целевые проверки, runtime deploy, реальный HTTPS login/logout/CSRF/CRUD и внешняя TLS проверка, injected enable rollback и restore/rollback между private/public config. Новая offsite копия, docs и local commit.

До полного прохождения этих проверок публичный proxy не включать. Ночной deadline 08:20 Томск / 01:20 UTC; при нехватке окна оставить проверенный private режим.

