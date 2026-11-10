# Совместимость формата профилей

Следующий доступный блок этапа4. Прочитаны pinned Go `internal/uri/uri.go`, Android `FreeturnLink.kt`/`ShareLinkBuilder.kt`, Go `docs/sub.md` и неизменённый baseline `profile_links()`. HEAD refs совпадают с upstream lock.

- [x] Отдельный pure codec для существующего `freeturn://base64url(JSON)` v1; только реально имеющиеся wire fields, строгие типы/размер/duplicate-key checks, без новых URL flags и изменения рабочих профилей. JSON Schema генерировать из тех же definitions. Partial KCP не принимать: Go заполняет отсутствующие значения нулём, Android — defaults; полный KCP устраняет эту неоднозначность.
- [x] Две целевые проверки: baseline synthetic round-trip и отказ от повреждённых/неоднозначных payload без секретов в ошибках. Не писать тест для каждого поля.
- [x] На рабочем ПК взять исходный Go parser ровно из pinned commit с проверкой source SHA256, выполнить его настоящие Parse/String над synthetic baseline profiles и обратно через Python. Go compiler local, GOPROXY off, никаких компиляций/VPN изменений на VPS.
- [x] Android parser source сверить по SHA256, runtime Kotlin/Android отдельно NOT RUN при отсутствии toolchain. Не называть Go parser round-trip клиентским VPN E2E.
- [x] Документировать поля, WireGuard endpoint semantics и отличие core text sub.md от ещё не реализованного managed enrollment. Local commit.

Это compatibility foundation, не публичный subscription response, Direct/Auto или bootstrap protocol. Нельзя просто добавить managed metadata в share JSON: upstream parsers игнорируют неизвестные поля, а String() их потеряет. Нужен отдельный версионированный клиентский envelope в следующем блоке.

