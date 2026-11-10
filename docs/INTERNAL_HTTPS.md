# Клиентский HTTPS внутри VPN

10.11.2026, согласованный тестовый VPS. `ftm/internal_https.py` устанавливает отдельный root-owned wrapper и ExecStartPost существующей network service. Baseline не меняется. При старте hook помещает только собственное разрешение выше baseline INPUT REJECT: VPN interface, source subnet, собственный VPN address, TCP443. SSH,8080, публичный WG backend и чужие firewall rules не открываются.

Установка требует свежую offsite-verified encrypted копию и lifecycle lock. Нет restart VPN/SSH при установке. При ошибке восстанавливаются прежние hook/wrapper и состояние собственного правила. Fixed `--ensure` доступен только root, не IPC/API. При ошибке ensure пытается удалить собственное разрешение и возвращает ошибку; ExecStartPost с `-` не блокирует запуск основного VPN из-за сбоя management. Ошибка удаления правила остаётся диагностикой для root. Code чтения конфигурации не меняет firewall.

Активность связана с `web.json`: public v2 разрешает внутренний HTTPS, private v1 удаляет исключение. Same-host restore регенерирует правило через доверенный установленный код; команды/unit-файлы из архива не принимаются. Result restore теперь отдельно сообщает `internal_https_rule_synced` и `unrelated_firewall_or_ssh_changed:false`; старое поле `ssh_and_firewall_changed` true при синхронизации собственного правила. Hook/unit пока требуют уже provisioned host; clean-host recovery не реализован.

`ReferenceClient(..., internal_address=...)` явно выбирает RFC1918 IPv4 для TCP443, сохраняя public HTTPS origin, Host и TLS chain/SAN verification по исходному адресу. Proxy и redirects отключены. Никакого TLS bypass. Выбор маршрута не автоматический; клиентская интеграция должна делать его после проверки доверенного manifest/профиля. Reference caller не является готовым VPN приложением.

## Проверено

Реальный root report `/root/ftm-internal-https-report.json`: synthetic enrollment → kernel peer → WireGuard в отдельном namespace → config200/304 по внутреннему адресу. Неверная TLS identity отклонена; TCP22/8080 недоступны. Закрытие и повторное добавление exception реально остановило/вернуло HTTPS. Cleanup сохранил исходные2 peers, ключи, CID/obf, iPhone profile и PID VPN/SSH.

Тестовый WG UDP socket создан в исходном namespace и использует loopback backend, без открытия51830 снаружи. Механизм описан в [документации WireGuard](https://www.wireguard.com/netns/). Проверка обходит TURN/VK и не подтверждает нативный Android/iPhone/Windows E2E.

Полный прогон до финальной защиты availability: Windows115 tests110PASS/5skips, WSL115 tests109PASS/6web dependency skips; baseline8 и binary smoke PASS. После неё targeted4/4 PASS в Windows и WSL. В этом блоке добавлены три проверки для firewall scope, TLS identity и отказа management hook; обычные изменения проверены рабочим сценарием.

Runtime `90d62da6cab56869`. Offsite `manager-internal-https.vpnbackup`: SHA256 `86a0b71ea052a00f40d3fc7cb11f6227b73a6813e1f0bfcad9b5ccc6abd4564b`, root `/root/ftm-managed-d1821e161f.vpnbackup`. WSL decrypt/stage PASS,13 metadata devices/2 owned peers/web v2. Это состояние после первого namespace proof; последующие проверки фиксируются ниже.

Actual public→private restore удалил exception; инъекция ошибки public restore вернула полный private snapshot без exception; финальный public restore вернул правило и trusted401. `/root/ftm-https-recovery-report.json`. При этом FreeTurn/API/Caddy перезапускались для обслуживания; SSH и iPhone profile сохранились. Отдельная ошибка установки после записи hook вернула его прежние bytes и правило.

Настоящий restart `vps-vk-network` выполнил ExecStartPost: exception выше baseline REJECT, все8 служб active, файлы snapshot совпадают. После него namespace HTTPS proof повторён PASS. Первая проверка порядка правила ошиблась на текстовом представлении `iptables -S` (comment между interface и jump); исправлен разбор через shlex, firewall не менялся ради проверки. `/root/ftm-internal-network-restart-report.json`. Отдельно подтверждён именно `SSLCertVerificationError` для чужой TLS identity до HTTP, а не просто отказ разбора manifest.

Финальная offsite копия `/root/ftm-managed-8db580dbfe.vpnbackup` → `manager-internal-final.vpnbackup`, SHA256 `8ced5925e9f4f9ab84ef6eafac6a2d738f14df2ca288857e4472885cf4eeb0bd`. Decrypt/stage в WSL PASS:14 metadata devices (временные отключены),2 owned peers, web v2. Pre-client hashes state/WG/CID/obf/registry/iPhone и прежний SSH PID ещё раз подтверждены после maintenance. Новый reboot не выполнялся.

Финальное исправление availability установлено hot без VPN/SSH restart: runtime `df4586ea13418c73`. Настоящая инъекция ошибки ensure удалила правило, повтор ensure вернул его; systemd ExecStartPost подтверждён с `ignore_errors=yes`. Это targeted проверка, не повторный restart сети с повреждённой live конфигурацией. Data checkpoint не изменился. Свежий pinned SSH и внешний HTTPS anonymous401 PASS.

Bootstrap/claim и клиентский secure storage ещё не реализованы. Physical Android/iPhone/Windows E2E после этих изменений NOT RUN. Исходная пользовательская проверка iPhone остаётся отдельным историческим результатом.
