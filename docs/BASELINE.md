# Проверенная исходная точка

Дата аудита: **10.11.2026**, Asia/Tomsk. Это результаты чтения исходников и локальных проверок, не отчёт о production-развёртывании.

## Версии и лицензии

Полные SHA и хеши сохранённых файлов находятся в [upstreams.lock.json](../upstreams.lock.json).

| Проект | Зафиксированный commit | Что установлено при аудите | Лицензия |
| --- | --- | --- | --- |
| NimmWee/Vps | `25172a54f57afd29478051fbde9a4060c443d974` | Установщик 1.0.0; два клиента; runtime 4.1.2-vps1 | MIT; отдельная HBL для FreeTurn |
| hackdiaz-dev/free-turn-proxy | `21dca376ca26d2b6d0e2d84d107b9314b5041146` | Текущие modes/sub/URI, clientsdb, CLI; Direct/Relay вручную | Happy Bunny License |
| hackdiaz-dev/turn-proxy-android | `be516f1122ac38523203dbffde8603a8b3e755fc` | Android 5.3.2, minSdk 24, compile/targetSdk 37, Java 17 | GPL-3.0 |
| l1ch666/turn-proxy-android | `386f85f222704fdbcff79121b8e9c606ebc1be24` | Desktop 2.7.0, Compose/JDK 21; ограничения ниже | GPL-3.0 |
| anton48/vk-turn-proxy-ios | `a41bd5628a8bdbdc6ff7e3d794fb76d97ea08871` | README build 479; AppConfig/BackupManager содержат legacy import-поля | GPL-3.0 |
| itsnotkubrick/3X-UI_KIT | `7b10e1d9f227d313fbb912069bbcda0b961ff9a9` | 1.2.1; выбор домен/IP, DNS-проверка, случайный путь, статический `/` | MIT |

Из Vps сохранены все **23 отслеживаемых файла**, включая лицензии, исходники, тесты, manifest, бинарники и архив. На копии проверены SHA256 каждого файла и исходный verifier пакета. `vendor/vps/` не используется как исполняемый установщик Manager.

У Desktop первоначальный полный checkout не завершился из-за сетевого сбоя при получении большого blob. Commit/tree и необходимые текстовые файлы прочитаны через `git show`; поставленные EXE/DLL не проверены и не скопированы в Manager. Это аудит исходного кода, а не проверка сборки/работы Desktop.

## Закреплённый runtime Vps

- FreeTurn **4.1.2-vps1**, upstream `6d857e1e847a38fdee3e150314fb37009e3c37a6` (4.1.2).
- Локальный patch добавляет `-obf-key-file`; Go mod/sum сохранены. Manifest указывает Go 1.27.3, go.mod — минимальную версию 1.26.10. Это сведения из поставки; воспроизводимая пересборка здесь не выполнялась.
- amd64 SHA256: `9e6ccfde48ac0dc3ffdb398ef19f2203521febd3eeecfc6ae36a441226601a0c`.
- arm64 SHA256: `0862013f4fcc9214acde948b6913fe434dfcd9ed7359a506681594852be1c1f5`.
- Архив 1.0.0: `30ea1801f9c98e11d41e1408796fe2bf0dd803debc10882c19815c7e9ab2d063`.
- Выполнен именно amd64 runtime: help, временная CID-база, loopback startup/shutdown, строка версии в startup log. Флага `-version` у него **нет**.

## Контракт существующей установки

Источники: [src/vps_vk.py](../vendor/vps/src/vps_vk.py), [install.sh](../vendor/vps/install.sh), [manifest](../vendor/vps/artifacts/manifest.json).

| Область | Текущее поведение |
| --- | --- |
| CLI | `install`, `status`, `profiles`, `backup`, `restore`, `uninstall`, `network-up`, `network-down`; root на VPS |
| Конфигурация | `/etc/vps-vk/main/`; root/group protected `obf.key`, `clients.json`, root-only `wireguard.conf` |
| Состояние | `/var/lib/vps-vk/main/state.json`; JSON version 1, фиксированные `iphone`/`android` |
| Интерфейс | `vkvpn0`, `10.77.43.0/24`, server `.1`, iPhone `.2`, Android `.3`, MTU 1280 |
| Транспорт | `0.0.0.0:56001/udp` → backend `127.0.0.1:51830`, rtpopus3 |
| Службы | `vps-vk.service`, `vps-vk-network.service`, отдельно Fail2ban |
| Ресурсы FreeTurn | GOMEMLIMIT=48MiB, GOMAXPROCS=1, MemoryHigh=64M, MemoryMax=96M, CPUQuota=50%; не менялись |
| Статус | Успешен, только если службы active и число WG peers **ровно 2** |
| Firewall | Правила с comment `vps-vk-main`; внешний WG backend закрыт; вход с VPN в службы VPS запрещён; IPv6 forwarding из VPN блокируется |
| API | HTTP control plane в исходном Vps отсутствует |
| Бэкап | `VPSVK1`, AES-256-CBC/PBKDF2 и HMAC-SHA256; аутентификация до расшифровки, только валидированный JSON |

### Форматы профилей

- iPhone: `vkturnproxy://import?data=<base64(JSON)>`, `version=1`, `type=connection`, `settings`. Важны `useDTLS=true`, `useWrapS=true`, `useUDP=false`, `obfProfile=rtpopus3`, `wrapKeyHex`, `clientID`, независимые WG keys/PSK.
- Android: `freeturn://<base64url(JSON) без padding>`, `v=1`, `provider=vk`, `transport=tcp`, `mode=udp`, `obf=rtpopus3`, `cid`, `vk`, `wg`. Парсер Android 5.3.2 читает `vk` и `wg`; это не доказательство wire-совместимости с сервером.
- Настоящий профиль содержит секреты. В тестах используются только синтетические ключи; импортируемые пользовательские ссылки не записываются в документацию/логи.
- Исходный генератор WG включает `::/0`, сервер добавляет ULA-адрес, но блокирует IPv6 forwarding. Поведение IPv6 и отсутствие утечек на реальных клиентах ещё надо проверить; baseline не менялся.

## Что важно для дальнейшей реализации

1. **Hot reload CID есть в закреплённом исходнике 4.1.2**, а не только в новом main: `clientsdb.StartHotReload`, polling 10 секунд по mtime. Изменения действуют при новых проверках авторизации; удаление CID само по себе не доказывает закрытие существующей DTLS-сессии. Нужны тест отзыва и удаление WG peer.
2. **Direct — тот же FreeTurn listener и DTLS/OBF**, не публичный WireGuard. Файл `docs/modes.md` явно описывает ручное переключение; Auto предстоит сделать.
3. **Текстовая sub.md не регистрирует устройства.** Нужны отдельные enrollment, ключи/credential на устройство и безопасное применение ревизии.
4. **Android AAR по умолчанию `latest`.** Перед разработкой клиента нужно закрепить release tag и SHA256 AAR/install.sh, а не унаследовать плавающую зависимость.
5. **Desktop не реализует нужный WG-путь.** В `SingBoxConfigFactory.supportedSchemes` только vless/hysteria/hysteria2/hy2. `FullTunnelManager` отмечает Running после запуска elevated-процесса без проверки трафика; остановка использует имя процесса. Это не соответствует требованию отдельного ограниченного сервиса и полноценного FreeTurn/WG туннеля. Код не переносился.
6. **1 vCPU/1 GiB и скорость не подтверждены.** WSL-хост имеет другие ресурсы. Нет проверки реальных Android/iPhone, VK CAPTCHA, оператора и TLS.

Исходный `vendor/vps/docs/verification.md` описывает испытания автора Vps. Они сохранены как исторический документ и **не считаются испытаниями Manager**.
