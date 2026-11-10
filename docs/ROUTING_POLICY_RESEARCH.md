# Раздельная маршрутизация и DNS: требования и решение

10.11.2026, Asia/Tomsk. По запросу пользователя изучены скриншот и `POLESNIESOVETI12/web-panel-proxy`. **Только документация:** клиентский/серверный код, профили, DNS, firewall и VPS не менялись. Ниже проект будущей функции, не отчёт о её работе.

## Что подтверждено в референсе

Исходники: [wpp_routing.py](https://github.com/POLESNIESOVETI12/web-panel-proxy/blob/a4c7ae2402a4a6f37987c2c40d0f0249e6fd3b5a/wpp_routing.py), [wpp_ui.py](https://github.com/POLESNIESOVETI12/web-panel-proxy/blob/a4c7ae2402a4a6f37987c2c40d0f0249e6fd3b5a/wpp_ui.py). Локальный read-only checkout `.references/web-panel-proxy`, HEAD `a4c7ae2402a4a6f37987c2c40d0f0249e6fd3b5a`, MIT License. Установщики/тесты чужого проекта не запускались.

Семь переключателей на скриншоте совпадают с routing UI. В генераторе есть custom direct/proxy domain lists, приоритет YouTube/push перед RU, отдельные DNS и BitTorrent block. Основной результат — конфигурация клиентского Xray для VLESS/Hysteria2; AWG имеет отдельные IP-list механизмы. Это не универсальные серверные firewall rules для любого WG-клиента. Мы берём UX и смысл правил; Xray/чужую панель/протоколы не устанавливаем.

SHA256 прочитанных файлов: `wpp_routing.py` — `8e9268befc2beaa8291ab9119b6d0c7c1ba5fcbd9f451100e4acdac825b3e986`; `wpp_ui.py` — `7b2c855f97c8cb369f23b78d139ac17b01a695a1bcc6121dbf48b4a92894dcfb`.

## Семантика для FTM

«Напрямую» означает **выход через обычный Wi-Fi/мобильный/домашний канал клиента, без VPS**, а не FreeTurn Direct. FreeTurn Direct/Relay — выбор транспорта до VPS; оба по-прежнему относятся к действию «Через VPN».

Маршрутизатор должен работать **в клиенте** до WG-шифрования. VPS не может вернуть уже пришедший к нему запрос в домашний исходящий IP телефона. [WireGuard](https://www.wireguard.com/#cryptokey-routing) маршрутизирует IP-пакеты, а AllowedIPs не является готовым доменным policy engine. На Android/Windows нужен согласованный TUN/per-flow router + DNS dispatcher с bypass sockets, поверх существующего WG/FreeTurn. До выбора реализации — короткий spike на обеих ОС, оценка лицензий/RAM/UDP и совместимости. Только app-based split tunneling или одноразовый resolve доменов в IP не закрывает задачу.

Политика администратора версионируется и распространяется через managed subscription, с atomic apply/rollback и сохранением последней исправной версии. Текущая strict managed-v1 не расширяется неизвестными полями: согласовать новую schema/capabilities и совместимость. Panel показывает published/applied revision и «не поддерживается/не подтверждено» для старого клиента. Текущие APK, reference caller и Anton48 не объявляются поддерживающими эту функцию; iPhone-профиль не менять.

## Переключатели и домены

| Настройка | Требуемое поведение |
| --- | --- |
| Российские сайты напрямую | RU domain set, .ru/.su/.рф (IDNA), известные RU services и GeoIP RU как fallback; контроль версий/хешей/размера/лицензии списков |
| Локальная сеть напрямую | Домашний роутер/локальные сети через физический интерфейс; без доступа к закрытым private/metadata службам VPS |
| YouTube через VPN | YouTube, video/CDN/API домены и UDP/QUIC; выше широких RU/GeoIP правил |
| Push Apple и Google через VPN | Только соответствующие APNs/FCM service domains/addresses; IPv4/IPv6 и общие CDN требуют проверки на ОС |
| Проверка интернета напрямую | Идентифицированные Android/Apple/Windows/Firefox connectivity/captive portal endpoints; это отличается от туннельного health probe |
| Блокировать BitTorrent | Блокировать распознанный torrent/DHT/tracker трафик, не отправлять его в обход через DIRECT |
| Раздельный DNS | RU/DIRECT имена через выбранный direct resolver, VPN имена через защищённый resolver внутри VPN |

В разделе «VPN/Транспорт → Маршрутизация» нужны семь понятных переключателей, поля «Напрямую», «Через VPN», «Блокировать». **Только домены, один в строке**, без JSON/регулярных выражений/синтаксиса Xray и ручных IP-маршрутов. До300 custom domains на профиль как начальный bounded limit. Добавить/удалить/поиск, exact/suffix режим «включая поддомены», предпросмотр конфликтов, понятные ошибки и проверку «домен → правило/действие/DNS» без постоянной истории посещений.

Нормализация IDNA/нижний регистр/конечная точка, проверка hostname и длины; отвергать URL с path/query, port, credentials, IP literal, wildcard/regex и неверные/public-suffix-only entries. `example.ru` с поддоменами не должен совпадать с `notexample.ru`. Дубликаты объединять; противоречащие действия для одной нормализованной записи не публиковать. Служебные домены банка/входа/CDN могут потребовать отдельных записей; одного видимого имени сайта не всегда достаточно.

## Приоритеты

Сверху вниз, без изменения защитных инвариантов:

1. Защита control/data plane: TURN/VK auth/transport sockets идут наружу через protected underlay; внутренний management API — только нужный VPN IP/TCP443 **внутри туннеля**. Закрытые VPS services/metadata не становятся доступными из-за LAN bypass. При пересечении домашнего10/8 с VPN subnet приоритет имеет точный внутренний API маршрут; остальная изоляция сохраняется.
2. Включённая BitTorrent policy и явные admin BLOCK.
3. Явные доменные исключения администратора DIRECT/VPN: наиболее специфичный exact/suffix match. Они выше пресетов; UI показывает, если исключение меняет YouTube/push policy.
4. Preset YouTube и push → VPN; connectivity checks → DIRECT; выбранная LAN policy → DIRECT. Правила для известных имён важнее широкого GeoIP bypass.
5. RU domains → DIRECT; затем GeoIP RU fallback для остальных классифицируемых адресов. Общий IP разных сервисов не превращать автоматически в глобальное DIRECT исключение для всех доменов.
6. Всё остальное → VPN. Неопределённый VPN flow/недоступный VPN не получает скрытый DIRECT fallback. Kill switch блокирует VPN-classified flows; явно разрешённый DIRECT может продолжать работать. Проверять, что системный Android lockdown не делает DIRECT недоступным, и честно показывать конфликт политики.

Изменения публикуются администратором с session/CSRF/Origin и аудитом изменения правил. БД остаётся root-owned, изменения через allowlisted IPC; raw config/shell не принимается. Политика включается в encrypted backup/restore. Новые schema/migrations согласовать с текущим строгим checkpoint validator до применения; сейчас миграции не создаются.

## DNS и известные ограничения

Яндекс DNS для RU, Cloudflare/Google для остальных — желаемые стартовые resolver presets со скриншота, а не гарантия доступности из любой сети. Перед реализацией проверить их официальные TLS endpoints и маршруты. Администратор выбирает resolver и transport; защищённый VPN DNS не должен при сбое незаметно уходить в direct plaintext53. Для DIRECT доменов resolver должен давать подходящие локальные/CDN ответы; CNAME цепочки сохраняют routing intent исходного имени. Resolver sockets и bootstrap DNS сами не создают маршрутную петлю.

DNS cache учитывает TTL, CNAME, A/AAAA, смену сети/политики и общий IP нескольких доменов. Не публиковать глобальные бессрочные IP routes после одного resolve; не сливать VPN имена в direct resolver ради геолокации. Проверить приложения с собственным DoH/DoT, IP literal, encrypted ClientHello и QUIC: если доменное правило невозможно достоверно применить, не заявлять success и не включать DIRECT по догадке. TLS interception/установка пользовательского CA для этого не требуются и не планируются.

Локальные имена домашней сети разрешать через её DHCP/system resolver и поддерживаемый ОС mDNS, а не через публичные Яндекс/Cloudflare/Google. Не ломать локальные DNS suffix/discovery и не пересылать private names в VPN/public resolver. Применение зависит от физического интерфейса и обновляется при смене Wi-Fi/мобильной сети.

Текущая IPv6 block policy сохраняется до отдельной проверки. Нельзя открыть IPv6 в обход ради GeoIP/LAN/DNS. Приватность определяется согласованным маршрутом: DIRECT/RU DNS намеренно виден выбранному direct resolver, а VPN DNS не должен утекать туда. Не вести персональный журнал доменов/сайтов; диагностические запросы администратора кратковременны и явны.

## BitTorrent и сообщения «отключите VPN»

Одного Xray `protocol:bittorrent` из референса или блокировки6881–6889 недостаточно для заявления о блокировке любого зашифрованного/обфусцированного BitTorrent. Для FTM нужны проверенные возможности native flow classifier, known tracker/DHT rules и при необходимости app/process policy; server backstop только в согласованном scope, без тяжёлого непроверенного DPI на1GiB и без firewall flush. Проверить TCP/UDP/DHT и обход сменой порта, отсутствие DIRECT fallback и ложной блокировки HTTPS/QUIC. UI показывает реальный уровень поддержки; checkbox без enforcement не считается реализацией.

Цель DIRECT policy — чтобы выбранные сайты видели обычный провайдерский IP при включённом VPN. Это может устранить отказ по IP VPS. **Нельзя обещать отсутствие любой VPN detection:** приложение может видеть VPN adapter/Android VpnService, сайт — account/географию/собственную репутацию IP. Спуфинг device/VPN state не добавляется. Приёмка проверяет настоящий egress и целевые пользовательские сценарии; отсутствие одного предупреждения не доказывает универсальную невидимость VPN.

## Будущая приёмка — NOT IMPLEMENTED / NOT RUN

- T29: на Android/Windows при активном VPN RU/custom-DIRECT и router идут по физическому каналу, YouTube/push/custom-VPN — через VPS; приоритеты, exact/suffix/IDNA и shared IP не дают неверный bypass. Внутренний API работает через VPN, закрытые VPS services остаются закрыты.
- T30: split DNS, CNAME/TTL/A/AAAA, смена сети, собственный DoH и недоступность resolver/VPN; нет непредусмотренного direct fallback/leak. Connectivity check direct не подменяет WG handshake/HTTPS health check через VPN.
- T31: BitTorrent policy реально применяется в заявленном scope, включая DHT/смену порта; нет скрытого DIRECT обхода и поломки обычного HTTP/HTTPS/QUIC. Unsupported/частичная поддержка видна, не маркируется PASS.
- Panel: plain domain entry, безопасная публикация, device applied revision, offline/legacy client status, rollback, backup/restore и reconnect без потери ключей. Не навязывать новый импорт работающему Anton48.

Целевые автотесты — только precedence/security/validation/leak-sensitive cases; обычный UI — сборка и сценарий, сеть — реальные устройства. Текущее исследование не включает реализацию или испытание нового маршрутизатора.
