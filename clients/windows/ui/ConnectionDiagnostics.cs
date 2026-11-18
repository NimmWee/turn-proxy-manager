namespace FreeTurn.Windows;

internal static class ConnectionDiagnostics
{
    internal static string Stage(string? stage) => stage switch
    {
        "service_start" => "Запуск системной службы",
        "profile_check" => "Проверка конфигурации",
        "wireguard_start" => "Запуск WireGuard",
        "system_routing_start" => "Запуск системной маршрутизации",
        "system_dns_cache" => "Подготовка DNS маршрутизатора",
        "system_routing_preflight" => "Проверка сети и свободных адресов",
        "system_adapter_start" => "Создание адаптера маршрутизатора",
        "system_firewall_start" => "Включение защиты трафика",
        "system_network_config" => "Настройка адресов адаптера",
        "system_wireguard_start" => "Запуск ядра VPN",
        "system_stack_start" => "Запуск обработки TCP и UDP",
        "system_routes_publish" => "Применение маршрутов и DNS",
        "system_routing_ready" => "Системная маршрутизация настроена",
        "stopping" => "Отключение туннеля",
        "transport_start" => "Запуск FreeTurn",
        "vk_auth" => "Подключение через VK",
        "captcha" => "Проверка CAPTCHA",
        "turn_connect" => "Соединение с TURN",
        "relay_ready" => "Канал TURN получен",
        "handshake_wait" => "Ожидание ответа сервера VPN",
        "egress_check" => "Проверка интернета через VPN",
        "connected" => "Подключение подтверждено",
        "error" => "Не удалось подключиться",
        "stopped" => "VPN отключён",
        _ => "Ожидание состояния службы"
    };

    internal static string Error(string? code) => code switch
    {
        "SYSTEM_DNS_CACHE_INVALID" => "История адресов DNS повреждена или недоступна. Подключение остановлено; проверьте журнал.",
        "SYSTEM_DNS_CACHE_WRITE_FAILED" => "Не удалось сохранить адреса DNS. Новые запросы блокируются; проверьте журнал.",
        "SYSTEM_DNS_CACHE_FULL" => "Пул адресов маршрутизатора заполнен. Новые домены блокируются; проверьте журнал.",
        "SYSTEM_ROUTING_BUILD_REQUIRED" => "Для системной маршрутизации нужна новая версия ядра из этого пакета.",
        "SYSTEM_ROUTING_POLICY_INVALID" or "SYSTEM_DNS_SERVER_INVALID" => "Проверьте правила маршрутизации и IPv4-адреса DNS.",
        "SYSTEM_PROFILE_NETWORK_UNSUPPORTED" or "SYSTEM_PRIVATE_DNS_UNSUPPORTED" => "Адреса или DNS профиля пока несовместимы с системной маршрутизацией. Проверьте профиль сервера. Для AmneziaWG обычный режим WireGuard не подходит.",
        "AWG_SYSTEM_BACKEND_REQUIRED" => "AmneziaWG требует включённой системной маршрутизации и совместимого сервера.",
        "SYSTEM_TUN_NAME_IN_USE" or "SYSTEM_TUN_RANGE_IN_USE" => "Сетевой адаптер или диапазон маршрутизатора уже используется. Другой VPN может мешать запуску.",
        "SYSTEM_FIREWALL_FAILED" => "Windows не смогла включить защиту маршрутизатора. Подключение отменено.",
        "SYSTEM_TUN_CREATE_FAILED" or "SYSTEM_TUN_IDENTITY_FAILED" or "SYSTEM_TUN_ADDRESS_FAILED" or "SYSTEM_TUN_OPTIONS_FAILED" => "Не удалось подготовить сетевой адаптер маршрутизатора.",
        "SYSTEM_ROUTE_APPLY_FAILED" or "SYSTEM_DNS_APPLY_FAILED" or "SYSTEM_DNS_FLUSH_FAILED" or "SYSTEM_STACK_START_FAILED" or "SYSTEM_STACK_CREATE_FAILED" => "Не удалось запустить системную маршрутизацию. Изменения отменяются.",
        "SYSTEM_NETWORK_ROLLBACK_FAILED" or "SYSTEM_TUN_CLOSE_FAILED" => "Windows сообщила об ошибке восстановления сети. Отключите VPN и проверьте журнал.",
        "VK_LINK_INVALID" => "VK отклонил ссылку на звонок. Проверьте её актуальность.",
        "VK_AUTH_FAILED" => "Не удалось получить данные подключения VK.",
        "VK_RATE_LIMIT" => "VK ограничил частоту запросов. Подождите перед новой попыткой.",
        "CAPTCHA_TIMEOUT" => "Время ожидания CAPTCHA истекло.",
        "DNS_FAILED" => "Не удалось определить адрес сервера через DNS.",
        "TURN_CONNECT_FAILED" => "Не удалось соединиться с TURN.",
        "TURN_ALLOCATION_FAILED" => "TURN не выделил канал подключения.",
        "NETWORK_TIMEOUT" => "Сетевой запрос не получил ответ вовремя.",
        "NETWORK_REFUSED" => "Удалённый узел отклонил соединение.",
        "PROFILE_MISSING" => "Не найден сохранённый профиль службы.",
        "CONFIG_MISMATCH" => "Конфигурация туннеля не совпадает с выбранным профилем. Выберите сервер заново.",
        "OTHER_VPN_OR_NONPHYSICAL_UPLINK" or "NO_IPV4_PHYSICAL_UPLINK" => "Нет подходящего прямого интернет-канала. Проверьте другой VPN.",
        "TRANSPORT_START_FAILED" or "TRANSPORT_ERROR" => "FreeTurn сообщил об ошибке транспорта.",
        "TUNNEL_START_FAILED" => "Системная служба туннеля завершилась с ошибкой.",
        "WG_CONFIG_FAILED" => "WireGuard не смог загрузить сохранённую конфигурацию.",
        "WG_ADAPTER_FAILED" => "Windows не смогла создать сетевой адаптер WireGuard.",
        "WG_DRIVER_FAILED" => "Не удалось настроить или включить драйвер WireGuard.",
        "WG_FIREWALL_FAILED" => "Не удалось применить правила защиты WireGuard.",
        "WG_NETWORK_CONFIG_FAILED" => "Не удалось настроить адреса или маршруты адаптера WireGuard.",
        "WG_LOG_FAILED" => "WireGuard не смог открыть служебный журнал.",
        "SCM_START_TIMEOUT" => "Служба не ответила Windows вовремя при запуске.",
        "WINDOWS_SERVICE_FAILED" => "Windows завершила системную службу с ошибкой.",
        _ => "Причина не передана службой. Обновите службы и повторите попытку."
    };

    internal static string Detail(ServiceReply reply)
    {
        if (reply.State == "error") return (string.IsNullOrEmpty(reply.FailureStage)?"":"Этап: "+Stage(reply.FailureStage)+".\n")+Error(reply.DiagnosticError)+(reply.ServiceWin32Code==0?"":$" Коды Windows: {reply.ServiceWin32Code}/{reply.ServiceSpecificCode}.") + (reply.TunnelActive ? " Нажмите кнопку, чтобы отключить неработающий туннель." : " Можно повторить подключение.");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var since = reply.StageSince > 0 ? reply.StageSince : reply.Started;
        var seconds = since > 0 ? Math.Max(0, now - since) : 0;
        var text = Stage(reply.Stage) + $" · {seconds} с";
        if (reply.TotalStreams > 0) text += $"\nПотоки: {reply.Streams}/{reply.TotalStreams}";
        if (reply.State == "captcha" && reply.Manual) return text + "\nЗавершите проверку в окне VK.";
        if (!string.IsNullOrEmpty(reply.DiagnosticError)) text += "\nПоследняя ошибка: " + Error(reply.DiagnosticError);
        if (reply.LastProgress > 0 && now - reply.LastProgress >= 30) text += $"\nНовых событий нет {Math.Max(0, now - reply.LastProgress)} с. Можно отменить подключение.";
        return text;
    }
}
