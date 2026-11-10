# HTTPS и восстановление очереди

Продолжение этапов 2–3 по ночному поручению, один агент. Private панель уже проверена; доступ к рабочему VPS запрещён.

- [x] Получить доверенный IP certificate через закреплённый Caddy, сначала только нейтральная страница. Изолированный пользователь, root-owned runtime, отсутствие публичного API, секретов в access/error logs и изменений VPN/SSH.
- [x] Закрепить только собственные TCP 80/443 firewall rules при запуске. Реально проверить повторный install, запуск hook, отказ/rollback и внешний TLS client. Не делать ещё один reboot ради этой обратимой проверки.
- [x] В существующий root control worker добавить периодический retry pending/applying/error операций под тем же nonblocking lifecycle lock. Интервал 30 секунд, exponential error backoff до пяти минут, deferral при maintenance. Без новых shell/SQL endpoints, потоков, root DB ACL и VPN restart.
- [x] Проверить durable add/revoke в настоящем WG без inline RPC apply; проверить lock contention и неизменность исходных peers/profile. Подготовить актуальный checkpoint и проверить его вне VPS.
- [x] Зафиксировать фактический результат и ограничения, локальный commit без push.

Публичный login ещё не включать: требуется отдельный согласованный HTTPS origin, Secure cookie, proxy-aware Origin/Host, checkpoint/restore edge settings и реальная auth проверка по HTTPS. Нейтральный TLS probe — самостоятельный проверенный шаг, не завершение этапа 3. Caddy renew работает автоматически; фактическая выдача следующего сертификата за короткое ночное окно NOT RUN.
