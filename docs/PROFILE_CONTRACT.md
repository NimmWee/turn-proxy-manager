# Существующий FreeTurn share format

Этап4, 10.11.2026. Совместимый wire format зафиксирован; managed enrollment/bootstrap envelope ещё не реализован.

Прочитаны baseline `profile_links()`/`wireguard_client()`, [Go parser](https://github.com/hackdiaz-dev/free-turn-proxy/blob/21dca376ca26d2b6d0e2d84d107b9314b5041146/internal/uri/uri.go), [Android parser](https://github.com/hackdiaz-dev/turn-proxy-android/blob/be516f1122ac38523203dbffde8603a8b3e755fc/app/src/main/java/com/freeturn/app/data/share/FreeturnLink.kt), ShareLinkBuilder и Go `docs/sub.md`. Commits/source SHA256 — `profile-formats.lock.json`, совпадают с upstream lock. Исходники не менялись и не включены заново в Git.

## Поля

`freeturn://` содержит **unpadded base64url UTF-8 JSON**. Required: integer `v=1`, nonempty string `provider`, `peer`. Optional strings: `transport`, `mode`, `obf`, `key`, `cid`, `listen`, `dns`, `dnss`, `name`, `vk`, `wg`; integers `timing`, `n`, `spc`; booleans `bond`, `mcap`; object `kcp`.

KCP keys: integer `nodelay`, `interval`, `resend`, `nc`, `sndwnd`, `rcvwnd`, `mtu`, boolean `acknodelay`. **FTM требует полный объект:** отсутствующие поля Go превращает в zero values, Android — в KcpProfile.DEFAULT. Partial KCP мог бы дать разные настройки. Int32 range выбран для Android Int; это syntax portability, не runtime tuning validation.

`ftm.profile_codec` даёт strict bounded encode/decode/validate, отказывает duplicate/unknown fields и не включает input в ошибки. JSON Schema2020-12 в `schemas/freeturn-link-v1.schema.json` генерируется из тех же definitions. Предел JSON65536 UTF-8 bytes/string49152 chars. Codec не проверяет backend/transport runtime compatibility и не применяет конфигурацию.

## Baseline transport

Android baseline использует provider `vk`, transport `tcp`, mode `udp`, obf `rtpopus3`, `n=6`, `spc=3`, отдельный `cid`, VK link и WG config. Новые flags не придуманы. Mode относится к проксированию UDP WireGuard, transport — к TURN transport; это не публичный WG endpoint.

В `wg` — Interface PrivateKey/Address/DNS/MTU и Peer PublicKey/PresharedKey/AllowedIPs/Endpoint/PersistentKeepalive. Endpoint **127.0.0.1:9000**, локальный FreeTurn listener; backend UDP51830 снаружи не открывается. Codec не нормализует WG text и не меняет ключи, CID или рабочий iPhone profile. Android ShareLinkBuilder при собственном экспорте удаляет MTU/comments — отдельная client normalization, не серверная миграция.

## Реальная проверка

`python scripts/verify_profile_parsers.py` на рабочем ПК взял Go parser из pinned git object, проверил SHA256 и сохранил LICENSE рядом с временным source. **Настоящие Go Parse/String** выполнили три synthetic профиля: baseline WG, Unicode name и полный KCP. Python decoded Go output; WG/CID/VK/obf fields совпали. Compiler Go1.26.2 windows/386, isolated stdlib-only package, GOPROXY off/GOTOOLCHAIN local, без dependency downloads. Полный core module требует Go1.26.10 и здесь не собирался.

Android source SHA256/mapping проверены; actual Kotlin runtime **NOT RUN** (kotlinc отсутствует). APK, Windows VPN и физические подключения этим не подтверждаются. Два целевых Python cases PASS; Windows весь набор102 tests:97PASS/5skips.

Linux WSL:102 tests,99PASS/3web dependency skips, baseline8 и binary smoke PASS. Runtime `41768b222d0f96cc` включает codec/schema/pins. Root credential CLI дополнительно проверен с parent-directory fsync перед DB commit; секрет не печатался, VPN peers не менялись. Актуальная offsite копия `/root/ftm-managed-bde749470a.vpnbackup`, SHA256 **af42934ae523012aae80513234ec46c905c444b6b12b567c47b8d7842d4e4f0f**; local private `manager-profile-contract.vpnbackup`, реальный WSL decode/stage PASS:9 metadata/2peers/public web settings. Private human-readable `Панель.txt` с доступом подготовлен вне Git, в том же закрытом Downloads каталоге.

## Следующий контракт

Core text `sub.md` — список share links с name/refresh; VK call link по документации нужен отдельно. Это не индивидуальный enrollment. Managed token/bootstrap metadata нельзя помещать в неизвестные share JSON поля: parsers их игнорируют и при String() теряют. Нужны отдельный versioned client envelope, device credential и revision/ETag. Нормальная регистрация сохраняет private key на клиенте. VK lifetime/CAPTCHA не позволяют обещать автоматическую выдачу свежих TURN credentials.
