# Windows0.20: проверяемая база геолокации для IP-правил

17.11.2026, Asia/Tomsk. Продолжение согласованной технической части. Без субагентов, реального VPN/SCM/маршрутов/VPS/GitHub. Оптимизация скорости отложена. Сборка отдельно package-0.20, прежние ZIP/payloads сохраняются.

## Дизайн до кода

Нынешний RU IP fallback использует IPverse/RIR allocation hint. Нужна база геолокации с источником, датой, hash и лицензией. Варианты: оставить регистрацию IP (не выполняет требование GeoIP); MaxMind (потребует внешнего доступа/лицензионного ключа); DB-IP Lite CC BY4.0 без учётной записи (выбрано). Приблизительную базу не называть точным определением физического местоположения.

Официальный CSV DB-IP Lite November2026 скачан по HTTPS,32,485,911 bytes /732,796 rows; publisher SHA1 e2061015c43ec91c94a12191a6a613279eb94c0c и MD5 совпали. Дальнейший build pin — SHA256 compressed/uncompressed. Gzip4,623,153 bytes; compressed SHA256 e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd. Источник содержит9950 RU IPv4 ranges, объединяется в12902 prefixes. Полный исходный gzip и CC BY4.0 license/attribution/notice об изменении включить в source archive; IPv6 проверять как входные данные, но не включать в runtime IPv4 routing.

- Новый pure compiler routing_geoip.py: bounded gzip/CSV, SHA256, exact row count, strict canonical endpoints/country/order/nonoverlap и исключение special/private диапазонов из RU. Не исполнять supplier code. Невалидный source прекращает build, не заменять его RIR fallback.
- prepare_system_routing.py воспроизводимо компилирует доменные списки прежней версии и RU GeoIP. Закрепить новый lock и compiled hashes. Проверять всё до записи outputs. --check без сети. Добавить ссылки/hash/date/license в metadata каталога; runtime проверяет общий SHA и metadata/источник/prefixes.
- Маршрутизация и её приоритеты прежние: BLOCK/служебные адреса/LAN/custom/YouTube/push/connectivity/domain preset выше IP fallback. Неизвестные/не-RU IP остаются VPN. DNS при ошибках не получает direct fallback. Ordinary WGNT и ключи не меняются.
- Pure check preview выдаёт GeoIP provenance; C# проверяет её и показывает источник/месяц/атрибуцию как базу этого пакета, не выдавая её за активную базу старой службы. Без фоновой загрузки или runtime API запросов к поставщику. Полноценные безопасные обновления списков/managed policy delivery — отдельный оставшийся блок.

## Шаги

- [x] Целевые failing checks старого источника и compiler refusal: tamper/format/order/reserved/IPv6 separation. Никакого полного покрытия всех функций.
- [x] Pure compiler, pinned sources/compiled assets/license notices, runtime provenance validation и неизменность приоритетов.
- [x] C# provenance/preview + понятный источник в routing UI, сборка0.20 и native/offline/crypto checks по изменённым границам.
- [x] Bundle hashes/source correspondence/old-package preservation и актуализация ТЗ/прогресса. Реальные TUN/WFP/VPN/GeoIP routing/leak E2E — NOT RUN.

## Источники

[DB-IP Lite download/license/monthly snapshot](https://db-ip.com/db/download/ip-to-country-lite), [CSV specification](https://db-ip.com/db/format/ip-to-country-lite/csv.html), [CC BY4.0](https://creativecommons.org/licenses/by/4.0/).

## Результат17.11.2026

- Go regression на старом каталоге воспроизвёл отсутствие GeoIP provenance (FAIL), после изменения PASS. В runtime теперь DB-IP Lite2026-11,12902 RU IPv4 prefixes; source metadata и compiled catalog SHA проверяются перед использованием. Source checksum совпадает с pinned source map; date/country/license/URL/count обязательны. Неканонические/перекрывающиеся/повторные/служебные диапазоны отклоняются. При corrupt source build/runtime отказывают, RIR fallback отсутствует.
- Pure Python3 targeted checks PASS: exact диапазон без захвата соседних адресов, non-RU/IPv6 exclusion; compressed/raw hash, record count/decompression bound, CSV format/order/overlap/reversed/mixed-family и private/metadata/broad range refusal. Official payload verified against published raw SHA1/MD5; дальнейший pin — SHA256. В исходном архиве сохранены полный original CSV.gz, CC BY4.0 и modification/attribution notice.
- Go targeted/full test и vet/build PASS. Проверены реальный embedded dataset/provenance, tamper, malformed future metadata/count/source, reserved/duplicate prefixes, RU/non-RU, YouTube/push/custom BLOCK/protected management приоритеты. Доменные списки прежние1923 suffix/236 exact, источники90 files. Повторный compiler run дал побайтно прежние catalog/LICENSES/sources.zip; --check без сети PASS.
- Actual C#→packaged Go bridge PASS: metadata DB-IP/2026-11/12902 и RU DIRECT/non-RU VPN; inactive/networkChanged=false. C# crypto/catalog/backup/preferences/claim/sync/LKG fake checks PASS. Python→Go v1 managed/enrollment contract PASS; ftm/API/SQLite ownership и ключевые форматы не менялись.
- WPF release publish0 warnings/errors, final native single-window/nested/busy/editor/browser checks PASS (synthetic/no service/no network). Routing dark/top и light/bottom420×740 renders осмотрены: скролл/нижние действия/атрибуция доступны. UI показывает источник/дату именно базы пакета, не обещает её активацию в старой службе; runtime activation только после пользовательского Connect.
- Offline route/adapter/service digest unchanged; preflight physical uplink ready, driver checksum true, actual Connect не запускался. Baseline23/vendor package verifier PASS.
- Package0.20: 90.33MiB/16 entries/15 payload hashes/192 bundled sources/81 notices; SHA256 `c18b7bfa3817e78c175710e7518a672f4e4da8a81f371e15e14f3240e1bd853b`. Payload/source correspondence и вложенные original GeoIP/license/attribution PASS.0.18/0.19/0.19.1 ZIP и16 payload files каждого сохранены побайтно; installed services, реальные профили/ключи, VPS/GitHub не менялись.

**Границы:** источник/формат/целостность/приоритеты проверены; фактическая география каждого IP не проверялась и поставщиком не гарантируется. Реальные TUN/WFP/VPN/GeoIP routing/DNS/IPv6 leak/sleep/crash E2E — NOT RUN. Безопасное обновление списков и managed policy delivery, app matching, mDNS и always-on остаются отдельными задачами. Оптимизация скорости по поручению пользователя отложена.
