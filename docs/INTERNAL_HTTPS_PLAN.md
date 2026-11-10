# HTTPS внутри VPN

Продолжение этапа4 по действующему поручению пользователя. Один агент; без production/GitHub. Использованы skills brainstorming/writing-plans; повторные согласования и субагенты не нужны в уже разрешённом объёме.

Решение: один scoped INPUT accept только TCP443 с VPN interface/subnet на собственный VPN address. Другие INPUT ports и UDP backend остаются закрыты. Root-only fixed wrapper и network ExecStartPost восстанавливают порядок после baseline REJECT; vendor не изменяется. Активность связана с сохранённым public web config, поэтому private restore удаляет только это разрешение. Установка требует свежий offsite-verified checkpoint; исключение возвращает прежние файлы/rule, VPN/SSH не перезапускаются.

Availability уточнение: failure ensure закрывает собственное разрешение; systemd игнорирует exit только этого management hook, чтобы доступность VPN не зависела от API config. Targeted Windows/WSL и реальная error injection PASS.

Reference caller может явно выбрать RFC1918 TCP address, сохранив исходный HTTPS URL/Host и проверку TLS chain/SAN по public identity. Proxy и redirect выключены. Никакого insecure TLS или автоматического доверия адресу из непроверенной конфигурации.

- [x] Реализовать fixed scoped rule/hook/install с checkpoint guard, recovery sync и точным отчётом собственных firewall изменений.
- [x] Реализовать opt-in internal TCP override reference caller, целевые identity/redirect/ограничение адреса проверки.
- [x] Локальные проверки прав/rule scope и rollback; baseline hashes без изменений.
- [x] Установить на тестовом VPS; настоящий kernel WG namespace → trusted TLS → config/304. Отказ SSH/8080 из VPN, исходные peers/keys/profile/PID сохранены. Native Android/iPhone/Windows E2E NOT RUN.
- [x] Fresh offsite copy, docs и local commit.

Network namespace проверяет WireGuard и HTTPS, но обходит TURN transport; не выдавать её за FreeTurn VK data-plane E2E. Bootstrap nonce/claim и UI выдачи остаются отдельными блоками.

