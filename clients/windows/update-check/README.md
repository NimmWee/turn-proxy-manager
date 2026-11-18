# Проверка и загрузка релиза Windows

Библиотека проверяет подпись манифеста и байты установщика. Разработческий CLI проверяет уже скачанные файлы. Интеграция в Windows-приложение, защищённое хранилище доверия и установка ещё в работе.

```powershell
C:/VPNN/.toolchains/go/bin/go.exe test ./...
C:/VPNN/.toolchains/go/bin/go.exe vet ./...
C:/VPNN/.toolchains/go/bin/go.exe build -trimpath -buildvcs=false -o FreeTurn.UpdateCheck.exe ./cmd/update-check
FreeTurn.UpdateCheck.exe --trust trusted.json --release release.json --artifact Setup.exe --current-version 0.25.0 --accepted-sequence 6
```

CLI принимает обычные локальные Windows-файлы; UNC/device/ADS paths и не-regular files не являются поддерживаемым вводом. Приватный ключ не нужен. Trust JSON содержит поля в порядке `publicKey`, `origin`, `channel`: public key —32 байта Ed25519, base64url без padding; origin —canonical HTTPS DNS origin без path/port/query; channel —preview или stable. Public key должен поступить от владельца **отдельно от release/feed**, затем храниться будущим клиентом в защищённой конфигурации. Нельзя брать ключ из скачанного release и тем самым объявлять его доверенным.

Envelope: `payload`, затем `signature`, оба base64url без padding. Подпись Ed25519 над UTF-8 `FreeTurn.Windows.Release.v1` + NUL + точные bytes payload. Payload —compact canonical JSON в порядке полей `Manifest` из verify.go; artifact —в порядке полей `Artifact`. Повторные/неизвестные/case-aliased keys, trailing values и иная canonical форма не принимаются. Вне payload допустимы несущественные пробелы, порядок ключей сохраняется.

Payload v1: app=freeturn-windows, platform=windows-amd64, exact channel; версия из трёх uint16 без ведущих нулей; sequence выше сохранённого fence; issuedAt/expiresAt —RFC3339 UTC Z, окно не более30 дней и не из будущего за пределами5 минут. Artifact name строго FreeTurn-Setup-VERSION-CHANNEL-win-x64.exe, URL строго TRUSTED_ORIGIN/windows/NAME, размер2..256MiB, lowercase SHA256. Кандидат должен быть новее установленной версии; same-version repair остаётся ручному Setup.

`VerifyArtifact` сверяет `MZ`, размер и SHA256 открытого файла. `NewDownloader` создаёт HTTPS-клиент с проверкой сертификата и ограничениями на время и размер ответа. `Check` получает манифест из `/windows/<channel>/release.json`. `Download` сохраняет пакет во временный файл в закрытом каталоге вызывающей стороны, сверяет байты и возвращает открытый поток. Закройте поток, чтобы удалить файл. Приложению предстоит реализовать защищённую передачу файла установщику и сохранение принятой ревизии.

Проверено локально: Go test/vet/build, signed valid candidate и отказы на чужой key/подмену payload/неверный channel/origin/platform/version/TTL/rollback/размер/JSON неоднозначность и повреждённый artifact. Отдельная Python cryptography→реальный Go CLI проверка использовала сгенерированный **только в памяти** тестовый Ed25519 key и байты собранного Setup0.25; файл установщика не исполнялся. Никакого production signing key не создавалось/не сохранялось. В диагностику идут только fixed codes и безопасные version/channel/sequence/byte counters.
