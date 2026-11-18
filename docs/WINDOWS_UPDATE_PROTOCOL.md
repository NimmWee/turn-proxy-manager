# Проверка подписанного обновления Windows —18.11.2026

Доступны offline проверка и библиотека загрузки по HTTPS. Автоматическое обновление приложения ждёт канала, ключа издателя и интеграции.

Выбран Ed25519: отдельно настроенный доверенный public key, exact channel и HTTPS origin. Public key никогда не берётся из полученного release envelope. Production key не генерируется/не сохраняется в Git; тестовые ключи живут только в памяти. Код — отдельный module clients/windows/update-check. Это технический verifier, не завершённый пользовательский updater.

Wire contractv1: канонический компактный JSON envelope с payload (base64url UTF-8 JSON) и signature (base64url Ed25519). Подписывается domain separator `FreeTurn.Windows.Release.v1` + NUL + точные payload bytes. Payload содержит app/schema/platform/channel/version/монотонный sequence/issuedAt/expiresAt и artifact(name,url,bytes,sha256). Версия строго три uint16 компонента; channel/exact origin/app/arch, ограниченный срок, max256MiB, filename/path и SHA проверяются. Неизвестные поля/дубликаты/неоднозначный JSON отклоняются через точное canonical roundtrip. Sequence должен быть выше принятого fence, версия — выше установленной. Retry/repair той же версии остаётся ручному Setup, не automatic updater.

Проверки: подпись чужим ключом/изменённые bytes/истёкший manifest/rollback/channel/origin/path/размер/дубли и повреждённый локальный artifact. Fixed error codes без сырых manifest/parser strings. CLI проверяет файл **на момент чтения**, не обещает защиту последующего запуска по изменяемому пути; будущий updater должен удерживать проверенный файл или применять защищённый staging и повторную проверку.

`Downloader.Check` запрашивает манифест по адресу `<origin>/windows/<channel>/release.json`. `Downloader.Download` принимает проверенный кандидат и абсолютный путь к закрытому каталогу. Он возвращает открытый поток после проверки временного файла по размеру, сигнатуре `MZ` и SHA256. При закрытии поток удаляет временный файл. HTTPS проверяет сертификат, отказывает при перенаправлении, ограничивает заголовки, время запроса, размер манифеста и записи на диск. Срок кандидата проверяется до и после загрузки.

Следующий шаг интеграции — закрытое хранилище доверенного ключа и принятой ревизии, согласие пользователя, проверка состояния служб, защищённая передача установщика в процесс установки и приёмка отката на чистой VM. Приложение 0.27 и разработческий CLI пока используют прежние сценарии. Тесты загрузки поднимают HTTPS на loopback и проверяют отказ при недоверенном TLS, редиректе, отмене, превышении размера, неподходящей подписи, просрочке и изменённых байтах.

Дополнительная локальная проверка загрузила по HTTPS все 83 408 646 байт готового Setup 0.27, сверила исходный SHA256, повторно проверила открытый поток и подтвердила удаление временного файла. Манифест подписан одноразовым тестовым ключом в памяти. Запуск Setup — NOT RUN.

## Выполнено локально

Реализованы `verify.go`, `download.go` и разработческий offline CLI `cmd/update-check`. Go test, vet и сборка CLI прошли. CLI при неизвестном или некорректном аргументе скрывает его значение.

Независимый interop smoke Python cryptography→actual Go CLI PASS: подписан test manifest на реальные83371759B Setup0.25, проверены hash/MZ/size; tampered artifact, same version, replayed sequence, чужой public key и invalid CLI value отказаны. Test private key существовал только в памяти и не выводился. Evidence ignored `.local-cache/windows-build/update-check-smoke.json`; developer binary `.local-cache/windows-build/FreeTurn.UpdateCheck.exe`. Проверяемый Setup **не запускался**, HTTP/сервисы/сеть не использовались. Модуль не включён в frozen0.25/Setup; ещё не пользовательская функция обновления.
