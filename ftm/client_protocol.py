"""Safe errors shared by root IPC and the native client HTTP boundary."""

ERRORS = {
    "subscription_conflict": (409, "Состояние подписки изменилось. Обновите список и повторите действие"),
    "routing_conflict": (409, "Правила уже изменены. Перечитайте их с сервера перед публикацией"),
    "admin_password_required": (403, "Подтвердите действие действующим паролем администратора"),
    "export_expired": (410, "Файл больше недоступен. Обновите список устройств и начните новую выдачу"),
    "export_conflict": (409, "Параметры выдачи изменились. Закройте форму и начните заново"),
    "bootstrap_unavailable": (410, "Стартовый профиль истёк или уже использован. Запросите новый у администратора"),
    "bootstrap_source_denied": (403, "Активируйте стартовый профиль через его VPN-подключение"),
    "credential_invalid": (401, "Ключ доступа отсутствует или недействителен"),
    "device_disabled": (403, "Доступ устройства отключён"),
    "enrollment_denied": (403, "Регистрация недоступна: проверьте доступ и лимит устройств"),
    "enrollment_conflict": (409, "Параметры регистрации конфликтуют с существующим устройством"),
    "invalid_request": (422, "Проверьте параметры запроса"),
    "rate_limited": (429, "Слишком много запросов. Повторите позже"),
    "service_unavailable": (503, "Сервис временно недоступен. Сохраните рабочую конфигурацию"),
}


class ClientFault(RuntimeError):
    def __init__(self, code):
        if code not in ERRORS:
            code = "service_unavailable"
        self.code = code
        self.status, self.message = ERRORS[code]
        super().__init__("Client operation rejected")
