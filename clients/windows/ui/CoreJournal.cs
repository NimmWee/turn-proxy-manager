namespace FreeTurn.Windows;
internal sealed record CoreEvent(ulong Seq,long At,string Level,string Code,int Stream=-1,int Streams=0,int Total=0);
internal static class CoreJournal
{
    private static readonly Dictionary<string,string> Messages=new(){
        ["SYSTEM_DNS_CACHE_WRITE_FAILED"]="Маршрутизатор: история DNS не сохранена, новые домены блокируются",["SYSTEM_DNS_CACHE_FULL"]="Маршрутизатор: пул DNS заполнен, новые домены блокируются",
        ["VK_AUTH_START"]="VK: получение параметров звонка и авторизация",["VK_JOIN_RETRY"]="VK: прогрев страницы не удался, ядро продолжает авторизацию",["VK_PREVIEW_RETRY"]="VK: preview звонка не получен, используется следующий шаг",["AUTH_CACHE"]="Использованы сохранённые параметры авторизации",
        ["CAPTCHA_AUTO_START"]="CAPTCHA: автоматическая проверка",["CAPTCHA_MANUAL"]="CAPTCHA: проверка во встроенном браузере",["CAPTCHA_TOKEN"]="CAPTCHA: получен результат проверки",["CAPTCHA_RETRY"]="CAPTCHA: резервный способ или повтор проверки",
        ["DNS_UDP"]="DNS: UDP-проверка успешна",["DNS_DOH"]="DNS: UDP недоступен, переход на DoH",["DNS_QUERY_FAILED"]="DNS: ошибка запроса DoH",
        ["TURN_READY"]="TURN: выделение канала успешно, поток готов",["TURN_RETRY"]="TURN: повтор подключения",["STREAMS_CHANGED"]="Изменилось число готовых потоков",["SESSION_CONNECTING"]="Транспорт запускается",["SESSION_READY"]="Транспорт готов; отдельно проверяются WireGuard и интернет",["SESSION_ERROR"]="Транспорт сообщил ошибку",["CORE_WARNING"]="Предупреждение ядра (неизвестный шаблон, исходный текст скрыт)",["CORE_ERROR"]="Ошибка ядра (неизвестный шаблон, исходный текст скрыт)",
        ["VK_LINK_INVALID"]="VK: ссылка недоступна",["VK_RATE_LIMIT"]="VK: ограничение частоты запросов",["VK_AUTH_FAILED"]="VK: авторизация не завершена",["CAPTCHA_TIMEOUT"]="CAPTCHA: истекло время ожидания",["DNS_FAILED"]="Не удалось разрешить адрес",["TURN_ALLOCATION_FAILED"]="TURN: ошибка выделения канала",["TURN_CONNECT_FAILED"]="TURN: подключение не установлено",["NETWORK_TIMEOUT"]="Сетевой запрос не получил ответ вовремя",["NETWORK_REFUSED"]="Сетевое соединение отклонено",["TRANSPORT_ERROR"]="Ошибка транспорта",["TUNNEL_START_FAILED"]="Ошибка запуска туннеля"
    };
    internal static string? Format(CoreEvent e)
    {
        if(!Messages.TryGetValue(e.Code,out var message)||e.Level is not ("info" or "warn" or "error")||e.Stream is < -1 or >31||e.Streams is <0 or >256||e.Total is <0 or >256)return null;
        DateTime time;try{time=DateTimeOffset.FromUnixTimeMilliseconds(e.At).LocalDateTime;}catch{return null;}
        var stream=e.Stream>=0?$" [поток {e.Stream+1}]":"";var counts=e.Code=="STREAMS_CHANGED"?$" · {e.Streams}/{e.Total}":"";
        return $"{time:HH:mm:ss.fff} [{e.Level.ToUpperInvariant()}]{stream} {message}{counts} · {e.Code}";
    }
}
