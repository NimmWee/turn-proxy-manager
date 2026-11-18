# Windows0.21: .local через одноразовый mDNS

17.11.2026, Asia/Tomsk. Продолжение согласованного ТЗ; без субагентов, реального Connect/SCM/маршрутов/firewall/VPS/GitHub. Отдельный package-0.21;0.20 и предыдущие releases не перезаписывать. Скорость отложена.

## Решение до кода

RFC6762§5.1/6.7 допускает query с ephemeral UDP source port →224.0.0.251:5353; responder возвращает обычный unicast DNS response с исходными ID/question. Выбран этот bounded режим. Постоянный listener5353/DNS-SD/multicast membership добавляли бы конфликты с Windows Bonjour и дополнительные WFP-разрешения; системный resolver может использовать другие интерфейсы/протоколы. Их не использовать.

Только A-имена *.local через DNS-маршрутизатор при LAN DIRECT. Native IPv6/AAAA/HTTPS/SVCB egress не добавлять; соответствующие DNS query — NODATA. PTR/SRV/TXT/underscore browsing не реализуются. Обычный Windows Bonjour/native5353 discovery вне TUN DNS не считать проверенным; новой WFP exceptions для него нет. Автоматический список принтеров не обещается.

- Новый system_mdns_windows.go: immutable source/index/on-link private prefix; один query, TTL255, fresh random ID,2s timeout,4 concurrent sockets/64 received packets/4096-byte packet bound. Нет имени в журнале/диске или durable fake index. Никакого public/unicast DNS/VPN fallback.
- Network factory system_mdns_network_windows.go: проверка LUID/index/physical up/source до socket и принятия ответа. Bind source:0, IP_UNICAST_IF + IP_MULTICAST_IF для выбранного интерфейса, IP_PKTINFO, TTL255. Unconnected UDP, без reuse/membership/порта5353. После recv проверять WSA packet-info receiving interface и exact destination, source5353/private on-link; ограничить A addresses тем же private prefix, без protected10.77.43/24/network/broadcast/metadata. Invalid/unrelated/unsolicited packets игнорировать до bounded timeout, после смены uplink ошибка.
- DNS отвечает original query ID/question; принимает legacy response ID/question/Rcode/AA/class, не разрешает cache-flush, public/CNAME-cross-scope. CNAME flatten только внутри.local,≤8 links; TTL≤10s. LAN off не выполняет запрос. Existing local unicast53 и public DNS раздельны.
- systemNetworkPlan получает private prefix из фактического preferred unicast address/mask (не произвольного route). Runtime связывает resolver только при подходящем LAN контексте. Read-only status MDNSConfigured означает настройку пути, не proof обнаружения устройства. UI честно показывает scope.

## Выполнение

- [x] Failing DNS scope/answer regression; targeted bad packet/peer/interface/ID/CNAME/address/refusal/no-fallback/cancel/concurrency tests.
- [x] Реализовать pure resolver/WSA parser и native socket binding; никакого network activity из check/preview.
- [x] Связать preflight/backend/DNS/status/UI; ключи/backup schema прежние.
- [x] Go test/vet/build, native loopback packet-info (без multicast), C#/native UI/offline/old-release hashes; docs.

## Источники и границы

[RFC6762§6.7 и11](https://www.rfc-editor.org/rfc/rfc6762.html): legacy response и on-link validation; [Microsoft IN_PKTINFO](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-in_pktinfo), [IPv4 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options). X/net IPv4 control messages Windows не реализованы; использовать Go net.ReadMsgUDP и pinned x/sys WSACMSGHDR/IN_PKTINFO layout с проверкой размеров/alignment.

mDNS не аутентифицирует LAN responder; source prefix/interface/ID ограничения не заменяют доверие к локальной сети. IPv4 link-local169.254 и публично адресованные LAN в этом подэтапе не поддерживаются. Real multicast/LAN device/Windows resolver/Bonjour/TUN/WFP/leaks E2E — NOT RUN.

## Результат17.11.2026

- Регрессионный тест сначала не компилировался из-за отсутствующего mdnsExchange, затем после добавления transport упал на старой классификации.local; после интеграции PASS. Реализованы legacy one-shot A, source/mask/index/LUID/hardware-state guard, explicit multicast interface/TTL255/IP_PKTINFO, random nonzero ID и строгая envelope/peer/interface/destination/answer проверка. UDP5353 не занимается, membership и новые WFP exceptions не добавляются.
- Четыре targeted Go checks PASS: synthetic DNS→mDNS→private A без fake identity, LAN-off/AAAA/HTTPS/SVCB/no-unicast/public fallback, invalid peer/interface/ID/flags/CNAME/address/class/TTL, packet-info length/duplicate,4-query bound/cancel/stale-before-open. CNAME только.local, flatten и≤10s; public/off-link/VPS/metadata/network/broadcast targets не принимаются. Нативный Windows loopback UDP/WSARecvMsg подтвердил фактический layout packet-info с receiving index/destination. Это реальный loopback, но не multicast/LAN.
- Preflight строит mDNS link из preferred physical source и фактического OnLinkPrefixLength; active runtime связывает resolver только при LAN DIRECT/подходящей private subnet. Новая capability system-mdns-oneshot-ipv4-v1 и MDNSConfigured в read-only runtime report; flag означает настройку, не подтверждённое обнаружение. UI показывает mode и ограничение DNS-пути. Backup/catalog schemas и ключи не меняются; прежние runtime JSON читаются, Go json.Unmarshal допускает новое optional поле при rollback старым reader.
- Go full test/vet/release build PASS; WPF publish0 warnings/errors. C# crypto/DPAPI/backup/managed/settings/sync synthetic checks и actual C#→Go routing/GeoIP preview PASS. Native final single-window/nested/busy/editor/browser checks PASS (synthetic/no services). Lower light routing render осмотрен, текст/скролл/действия доступны. После README scope clarification проверенные EXE SHA остались прежними.
- Offline маршруты/адаптеры/службы до и после идентичны; preflight OTHER_VPN_OR_NONPHYSICAL_UPLINK. Другой VPN не отключался. Baseline23/vendor package verifier PASS. Реальные profiles/ключи/iPhone/installed services/VPS/GitHub не менялись.
- ZIP 90.36MiB/16 entries/15 payload SHA/195 corresponding sources/81 notices; SHA256 `88ed92e268628018f7677517beda379cceee214551c2c1dae44264e7a4afcc77`. Payload/source correspondence PASS;0.20 ZIP и payloads0.18/0.19/0.19.1/0.20 побайтно сохранены. Output package-0.21, без реального подключения.

**Остаток/приёмка:** actual multicast socket binding на hardware interface, LAN device, native Windows DNS/native5353/Bonjour path, TUN/WFP/stop/sleep/leaks — **NOT RUN**. mDNS не аутентифицирует локальную сеть. Это A-resolution через TUN DNS, не полноценный DNS-SD/PTR/SRV browser/реклама служб. Реальные устройства, IPv4 link-local и публично адресованные LAN не объявляются поддержанными этим checkpoint. Далее app matching/policy delivery/always-on/смена сети и прочий технический объём; оптимизация скорости отложена.
