# Выдача подписки и стартового профиля из панели

10.11.2026, согласованный тестовый VPS. В «Пользователях» для enabled пользователя доступны «Подписка» и «Стартовый профиль». Файлы скачиваются как JSON; опубликованные Android/Windows пока не умеют импортировать эти envelopes, что явно написано в форме. QR и native import ещё впереди.

## Доступ и доставка

Каждый POST требует valid session, фиксированный HTTPS Origin, CSRF и повторный пароль администратора. Root дополнительно читает свой web.json и проверяет scrypt hash: один API UID не разрешает secret export. Пять неверных подтверждений за600с блокируют root export на остаток окна; state общий для control daemon, не доверяет присланному IP. Основной VPN от этого не зависит. Private web mode экспорт не открывает.

Пароль отправляется в HTTPS body и Unix IPC, не в URL; не хранится в БД/cache/аудите. Ошибки содержат только безопасный RU текст. Секретный результат используется для Blob download, не выводится в UI и не сохраняется в browser storage кодом приложения. API/control/Caddy request/access logs не содержат секретов.

Root delivery cache `/var/lib/ftm/exports`700, файлы600, не читается ftm-api UID. Максимум64 файла; выдача доступна600с. Очистка каждые30с и перед export; при остановленном daemon файлы могут оставаться до следующего старта, но просроченная выдача не разрешается. Cache failure выдаёт503/диагностику без private paths и не останавливает control/VPN. Cache — временная доставка, **не входит в checkpoint**. Скачанный личный профиль хранить вне проекта и передавать доверенным способом.

UUID запроса сохраняется атомарно с операцией: bootstrap использует bootstraps.id, subscription export — settings tombstone без secret. Повтор с тем же UUID/password возвращает тот же файл без второй rotation/device. После утраты/истечения файла —410; другой payload того же запроса —409. Старый cache не возвращает отозванный subscription token; Root сверяет текущий nonce/token hash и enabled state. Orphan файл после failed transaction/restore старой БД не принимается без соответствующего DB tombstone.

Подписка выдаётся в `ftm-enrollment` v1: origin и user_token, предназначенный для регистрации устройств. Новая выдача вращает token, сохраняя подключённые peers/device credentials. Для bootstrap нужны действующая subscription identity и свободное место в device_limit. Profile создаёт отдельное устройство, применяется reconciler; дождаться active в списке. Сам claim описан в [BOOTSTRAP.md](BOOTSTRAP.md).

## Подтверждено

- Windows125 tests118PASS/7skips; WSL125 tests115PASS/10skips, baseline8 и binary smoke PASS. Две file-delivery проверки требуют Linux root; отдельно на настоящем VPS **3/3 admin-export tests PASS** без пропусков. Дополнительная HTTP проверка закрывает session/Origin/CSRF/root error boundary.
- Реальный `/root/ftm-admin-export-report.json`: login→no CSRF403→wrong password403→subscription/ bootstrap export/retry. Retry не создаёт второй peer/rotation. Потеря cache возвращает410; новый token делает прежний cached export недоступным. ftm-api UID не читает root cache; private values не найдены в service journals. Временный peer отключён, исходные keys/config/profile и PID VPN/SSH сохранены.
- Первоначальная проверка сразу после restart попала в readiness window: Caddy зафиксировал connection refused, первый временный пользователь остался без devices. Повтор после готовности PASS. Verifier теперь явно ждёт API listener перед сценарием; это исправление проверки готовности, не повод отключать TLS/авторизацию.
- Настоящий Chromium на рабочем ПК, trusted TLS без bypass: login, новый тестовый пользователь, неправильное подтверждение и очистка password input, скачивание subscription и bootstrap в private Downloads вне Git, отключение тестового пользователя. Формы отдельно просмотрены1440×1000 и390×844, mobile page без горизонтального overflow. Снимки `logs/panel-export-desktop.png` и `logs/panel-export-mobile.png` ignored, без secrets.
- Дополнительный DOM/storage assertion и browser logout не завершились из-за timeout/reset Node REPL; **NOT RUN**, не PASS. Headless process после reset отсутствует; API перезапущен для сброса тестовых sessions. По коду export не пишет browser storage; это не заменяет незавершённую browser assertion.

Runtime `0ed4fd0cb6c56be1`; frontend JS263.52KB/80.08KB gzip, CSS33.28KB/7.45KB gzip. Сборка выполнялась локально. API/control перезапускались для кода; VPN/SSH не перезапускались. Native client E2E и VK bootstrap T10 **NOT RUN**.

## Checkpoint

После API/browser cleanup: `/root/ftm-managed-37e7a1f7bb.vpnbackup` → private `manager-admin-export.vpnbackup`. SHA256 `674932dda5ba7b02b20843722e52c35934c58080b854f57e54c68a2f1eabb24d`. WSL decrypt/stage PASS:17 metadata devices (тестовые отключены),2 owned peers,web v2. Live snapshot после сброса browser sessions совпал с offsite. Новый live restore/reboot в этом блоке не выполнялся. Checkpoint содержит durable tombstones, не private delivery files; clean-host recovery остаётся будущей работой.
