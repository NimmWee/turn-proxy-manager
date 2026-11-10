# Проверки выдачи из панели

Требования и утверждения: session/CSRF/Origin и root password до каждого secret export; native compatibility заметна; download вне проекта; retry не создаёт второго peer/rotation; disabled/expired/orphan cache не раскрывается; private key/nonce/token не видны в DOM, browser storage, logs или Git.

Рабочий сценарий: Users→«Подписка»→пароль→JSON download; Users→«Стартовый профиль»→name/platform/password→JSON download; закрытие modal, обновлённый devices list. Password очищается после ответа. Viewports1440 и390: формы/кнопки доступны, page overflow отсутствует, table scroll допустим.

Негативные сценарии: неверный password оставляет форму и безопасную ошибку; запрос без CSRF/session не доходит до Root export. Повтор UUID после ответа возвращает тот же файл; после потери cache —410, не новая выдача. Новый subscription request отзываeт предыдущий URL-token, старый cache больше не выдаётся.

Root file tests отдельно на Linux root; Windows/WSL skip не считать PASS. Реальный HTTPS сценарий — scripts/verify_admin_exports.py. Browser — функциональная и отдельная визуальная проверка, файл в private Downloads, screenshots только без секретов. Нативный импорт NOT RUN.
