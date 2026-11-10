# Этап 4: регистрация и подписки

Ночное поручение, выполнение одним агентом. Не менять рабочий iPhone и не выдавать готовность Android/Windows по контрактному mock. Обычные изменения — сборка/сценарий, целевые тесты только для credential/data/access risks.

## Первый блок: жизненный цикл credentials

Использовать уже созданные `subscriptions` и `device_tokens`, без изменения схемы и ownership. Отдельный `ftm/credentials.py` работает только с Store. 256-битные случайные opaque tokens, разные user/device prefixes, domain-separated SHA256 в SQLite; plaintext только в результате выпуска и private root artifact. Обычные списки/аудит не содержат токенов или хешей.

- [x] Выпуск/rotation/revoke одной user subscription identity; rotation URL сохраняет уже зарегистрированные VPN peers и device credentials. Revoke URL запрещает новую регистрацию, для отключения устройств использовать отдельный user/device disable.
- [x] Независимые device credentials: только active/enabled device и enabled user, iOS исключён (ручной Anton48 profile). Rotation отзывает старый credential. Device revoke/user disable транзакционно отзывают device credentials; enable не оживляет старые токены.
- [x] Целевые проверки hash-only persistence, scope separation, concurrent rotation, disable/re-enable и отсутствие случайного отзыва устройств при смене URL. Root-only CLI пишет новый секрет в новый private0600 файл; не принимает токен через argv и не печатает его.
- [x] Реальная проверка на VPS с временным peer: создать/применить, rotate/revoke credentials и убедиться, что user URL rotation сохраняет WG/CID; отозвать peer в конце, сохранить профиль/ключи/PID. Новая offsite копия, docs и local commit.

Это **foundation**, без публичных client endpoints и UI кнопок выдачи. Выпуск из панели требует admin re-auth и отдельной защиты export. Root API не расширять секретными операциями до этого контракта.

## Следующие блоки

- [x] Проверить pinned Android/Go profile parsers, JSON Schema и round-trip настоящего Go parser. Android runtime NOT RUN; source mapping/SHA проверены. Не выдумывать freeturn URL flags. [Контракт](PROFILE_CONTRACT.md).
- [ ] Enrollment: on-device key, idempotency, user credential check и device limit в одной транзакции, отдельный device credential и per-device config/revision/ETag.
- [ ] Узкий VPN HTTPS allowlist с проверкой IP/domain TLS identity, client auth/throttling, bootstrap claim TTL/one-time consume и сохранением последней рабочей конфигурации.
- [ ] Клиентский reference mock явно отделить от реальных Android/Windows; затем клиентская интеграция и настоящие devices.

До 08:20 Томск /01:20 UTC закончить доступный блок, после cutoff новые изменения не начинать.
