# Локальные замеры ядра FreeTurn —18.11.2026

Реализован и запущен воспроизводимый Windows-стенд настоящего pinned core4.1.5. Он проверяет UDP relay, DTLS, rtpopus3 и локальный TURN TCP/UDP. Это измерение локального транспорта; скорость интернета, VK и установленного VPN здесь **не измерялась**. Сборка/установленное ядро0.24 не менялись.

## Что делает стенд

`scripts/core_local_benchmark.py` копирует закреплённый `.references/core-windows-v4.1.5` во временный каталог и добавляет `clients/windows/benchmarks/core_transport_windows_test.go`. Временная инструментализация считает переполнение входной очереди core; Direct bind ограничен127.0.0.1. По окончании runner сверяет SHA256 исходного дерева. `vendor/vps/`, Go module cache и оригинальный core не изменяются.

Путь пакета: генератор → настоящий udprelay.Run → DTLS/rtpopus3 → Direct либо локальный Pion TURN5.0.13 (TCP или UDP) → настоящий udpserver.Handle → UDP echo → обратный путь. Все сокеты/permissions только127.0.0.1; всеN сессий ожидаются ready до нагрузки. Ключ маскировки и сертификат синтетические, существуют только в памяти. Нет чтения профилей, CAPTCHA/VK/HTTP-запросов, внешних адресов или публичного debug порта. Настройки сети/служб не меняются.

Среда: Windows/amd64, Intel i5-12400F, Go1.27.3, GOMAXPROCS2 и GOMEMLIMIT256MiB только дочернего процесса. Payload1280B, UDP буферы генератора/приёмника4MiB, core/TURN buffers без увеличения. Фаза1.2s +400ms drain,2 повтора. QPC используется для фактического времени и RTT: первоначальная проба со слишком грубым clock была заменена, её нулевые RTT не используются. Пакеты проверяются по номеру, фазе и полному содержимому; loss, corruption, duplicates и reordering считаются отдельно.

CPU относится **ко всему процессу**: клиент, сервер, TURN и генератор;100% = одно логическое ядро. CPU/alloc включают400ms drain, goodput — фактический период получения. `allocatedBytes` — накопленные выделения памяти, **не используемая RAM**. CPU pprof заметно включает native Winsock/QPC/генератор, поэтому его нельзя выдавать за профиль только клиента.

## Обычная нагрузка:90 фаз

Direct/TURN TCP/TURN UDP ×N1/2/4/6/8 ×10/50/100Mbps ×2. Все562440 отправленных пакетов получены без corruption/duplicates; счётчик переполнения core очереди0. **100Mbps задавались генератором: это не найденный предел скорости.**

Медианы двух фаз при заданных100Mbps:

| Путь | N | Echo Mbps | p95 RTT,ms | CPU всего процесса,% | Alloc KiB/echo |
| --- | ---: | ---: | ---: | ---: | ---: |
| Direct |1|99.95|0.552|58.1|24.0|
| Direct |2|99.97|0.603|76.7|24.0|
| Direct |4|99.99|0.590|69.8|24.0|
| Direct |6|100.00|0.669|74.2|24.0|
| Direct |8|99.99|0.766|77.1|24.1|
| TURN TCP |1|99.98|0.718|74.7|35.8|
| TURN TCP |2|99.97|0.774|83.5|35.6|
| TURN TCP |4|99.99|0.788|87.9|35.6|
| TURN TCP |6|100.00|0.906|85.9|35.6|
| TURN TCP |8|99.96|1.007|93.3|35.6|
| TURN UDP |1|99.99|0.714|74.7|30.1|
| TURN UDP |2|99.98|0.712|66.4|30.1|
| TURN UDP |4|99.98|0.768|86.9|30.2|
| TURN UDP |6|99.97|0.822|90.8|30.2|
| TURN UDP |8|99.99|0.902|83.0|30.2|

ПриN1 reordering0; приN6/8 около50–55% доставленных пакетов приходят после уже виденного большего номера. Это счётчик перестановки датаграмм, не потеря/повреждение. Влияние на внутренний TCP/WireGuard здесь не измерено. Простое увеличение потоков не даёт выигрыша на этой фиксированной нагрузке. Вывод «один поток всегда лучше в VK» из этих данных делать нельзя: нет сетевой задержки/потерь/квот реального relay.

## Перегрузка:36 фаз

Те же три пути,N1/4/8, заданные250/500Mbps,2 повтора. Проверка целостности PASS, но под перегрузкой есть реальные end-to-end потери. Завершившийся Go test не означает отсутствие потерь.

| Путь | N | Echo при250Mbps | Потери,% | Echo при500Mbps | Потери,% |
| --- | ---: | ---: | ---: | ---: | ---: |
| Direct |1|249.79|0.04|220.81|55.70|
| Direct |4|249.79|0.06|296.51|40.50|
| Direct |8|249.65|0.09|305.88|38.61|
| TURN TCP |1|199.15|20.06|140.00|71.89|
| TURN TCP |4|220.84|11.43|181.83|63.48|
| TURN TCP |8|224.65|9.89|184.35|62.94|
| TURN UDP |1|235.23|5.77|155.01|68.89|
| TURN UDP |4|243.96|2.27|203.87|59.05|
| TURN UDP |8|242.50|2.85|206.83|58.48|

CPU процесса упирается примерно в145–150% с учётом drain на двух выделенных Go cores. Падение goodput при увеличении offered load показывает перегрузку стенда. Это не оценка скорости пользовательского VPS. Core inboundQueueDrops во всех фазах0: увеличение именно этой очереди не обосновано; потери дальше по пути пока не локализованы. Пределы короткой loopback-фазы не заменяют длительный тест, реальную сеть и отдельные CPU клиента/сервера.

## Профилирование и проверенный кандидат

Сняты отдельные3s CPU/alloc profiles приN6/100Mbps для каждого пути. В Direct основные alloc — DTLS marshal/unmarshal, cryptobyte и AEAD; вместе гораздо больше, чем metadata connutil. В TURN TCP дополнительно заметен `STUNConn.ReadFrom`: в отдельном100Mbps профиле14.45% alloc_space; у UDP видны ChannelData/HandleInbound. Криптографию, nonce, аутентификацию и wire формат не меняли.

Проверен ровно один кандидат **только во временной копии Pion**:

```go
// baseline: две последовательные копии при очередном TCP read
s.buff = append(s.buff, append([]byte{}, payload[:n]...)...)
// эксперимент: одна копия, прежний frame parser/buffer
s.buff = append(s.buff, payload[:n]...)
```

До каждого A/B запуска PASS штатные TestStunConn/TestConsumeSingleTURNFrame и дополнительный `turn_framing_test.go`: fragmented/coalesced STUN+ChannelData, padding, несколько кадров, перезапись возвращённого буфера и EOF, chunks1/3/11/2048 через net.Pipe. Никаких внешних сокетов. Оба плеча используют одну fixture и одинаковые fingerprints исходных core/Pion.

A/B: TURN TCP,N6,100/250/500Mbps,3 повтора по2s, pprof включён в обоих плечах. Медианы:

| Offered | Baseline echo | Candidate echo | Baseline alloc/фаза | Candidate alloc/фаза |
| ---: | ---: | ---: | ---: | ---: |
|100Mbps|100.004Mbps|99.993Mbps|709866400B|654594880B|
|250Mbps|201.912Mbps|209.965Mbps|1579320752B|1490967048B|
|500Mbps|165.599Mbps|165.568Mbps|1577268296B|1462101688B|

При100Mbps обе стороны без потерь и передали одинаковое19531 echo/фаза; объём выделений уменьшился **на7.79% во всём процессе стенда**. Временная Pion dependency общая для локального TURN-клиента и TURN-сервера: это не измеренный процент экономии отдельного реального клиента. CPU заметно колеблется; при500Mbps прироста throughput нет, перегрузочные потери остаются. **Стабильное ускорение VPN не доказано.** Candidate годится для отдельного поддерживаемого dependency patch после расширенной проверки/реальной приёмки; в поставляемый core, module cache или pinned source не включён. Изменение только локальной зависимости не требует ослаблять протокол/сервер.

## Как повторить

```powershell
python scripts/core_local_benchmark.py --go C:/VPNN/.toolchains/go/bin/go.exe --output .local-cache/core-benchmark/transport-repeat.json
python scripts/core_local_benchmark.py --go C:/VPNN/.toolchains/go/bin/go.exe --paths tcp --streams 6 --rates 100,250,500 --rounds 3 --seconds 2 --profile --variant baseline --output .local-cache/core-benchmark/ab-base-repeat.json
python scripts/core_local_benchmark.py --go C:/VPNN/.toolchains/go/bin/go.exe --paths tcp --streams 6 --rates 100,250,500 --rounds 3 --seconds 2 --profile --variant turn-single-copy --output .local-cache/core-benchmark/ab-candidate-repeat.json
```

Не запускать сравниваемые нагрузки параллельно. Полные JSON/pprof лежат в ignored `.local-cache/core-benchmark/`: `transport-matrix.json`, `high-load.json`, `profile-direct/tcp/udp.*`, `ab-baseline.*`, `ab-single-copy.*`; наружу не публиковались. Новые отчёты включают SHA256 оригинального core/Pion и fixture. Final smoke после доработки runner:3 пути, по292/292 echo, loss/corruption0, исходники неизменны.

Baseline23files и package runtime source checksums PASS;0.24 ZIP SHA256 остался `fd77db212a809b39637e45c41b9212b2f5abc3ef43708fb8bb3b9e9c2448ab44`. SCM read-only: broker Running, VPN tunnel Stopped. Реальный Connect, VK/оператор, WGNT/gVisor/TUN, AWG, VPS1vCPU и реальные телефонные E2E — **NOT RUN**.

Дальше: локализовать end-to-end перегрузочные потери дополнительными граничными счётчиками; при разрешённом живом сценарии сравнить Direct/VK, TCP/UDP, N и WGNT/system backend с одинаковыми условиями. Не менять одновременно MTU/число потоков/криптобиблиотеки и не обещать процент интернет-ускорения по loopback.
