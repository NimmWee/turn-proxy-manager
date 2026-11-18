# Windows policy delivery, persistent lock and network recovery

**Исторический отчёт0.23. Постоянная блокировка удалена0.24 по решению пользователя18.11; её live acceptance больше не задача. Policy delivery/recovery сохраняются. См. [удаление0.24](WINDOWS_LOCK_REMOVAL_PLAN.md).**

Authorised18.11.2026: implement items1–3 without live connections, installed service changes, VPS deployment or subagents.

## Design and scope

1. Separate bearer-authenticated /api/client/v1/routing endpoint preserves strict managed v1. Root SQLite owns revisioned policy publication through bounded IPC; panel edits domains/presets using optimistic concurrency. Lists imported by an explicit root-only offline command after pinned preparer verification; no arbitrary URL downloader in a service. TLS authenticates the server, SHA256 verifies catalogue bytes; digest alone is not a publisher signature. Clients stage monotonically, reject same-version changes, validate with engine, retain previous accepted version. Apply only next Connect. Local app rules and enabled/disabled choice remain local; server presets/domains override their equivalents for a managed profile. New endpoint is capability opt-in, old servers404 preserve local settings.
2. Explicit persistent WFP lock, disabled by default, separate from profile/backup. Persistent base deny + minimal loopback/DHCP and exact installed tunnel service SID/path; dynamic TUN allowance in the same sublayer. Block survives worker/broker/UI exit and BFE restart. No claim of pre-BFE boot protection. Disconnect does not unlock; explicit authenticated IPC/elevated recovery and uninstall remove only fixed owned objects. Transactions avoid a replace gap. No other firewall reset.
3. Active manual intent only; debounce changes/sleep, conditional broker recovery of the exact unchanged profile/attempt/epoch. Preserve options/keys and sticky DNS requirement, cancel stale managed/transport work. No auto intent after app restart, no stopping another VPN. Bound retries, CAPTCHA pause, explicit disconnect invalidates intent. Persistent lock covers reconnection gaps when enabled; ordinary dynamic mode cannot promise that protection.

## Work plan

- [x] Root policy store, typed IPC + HTTPS admin/client routes and Russian panel editor; conflict/revocation tests.
- [x] Windows validated/staged catalogue+policy, DPAPI guards, next-connect integration; replay/tamper tests.
- [x] WFP persistent backend with fixed ownership and explicit unlock, service/UI integration; pure ownership/transaction checks.
- [x] Network/power observer and exact conditional broker reconnect; cancellation/race checks.
- [x] Isolated0.23 build, Go/C#/Python/baseline checks, frozen artifact verification; docs report.

## Verification boundary

No actual WFP install/unlock, adapter/route/DNS change, sleep/network handover or VPN connect during this implementation. These E2E remain NOT RUN until user acceptance. Tests focus on access, rollback, data and traffic leak risks; ordinary UI verified by build/scenario.

## Implemented18.11.2026

- `ftm/routing_policy.py`: strict publication, revision CAS, retained catalogue, audit; `routing_publication` in the existing root SQLite backup. Root control startup performs an idempotent schema initialize; API UID has no SQLite permission change. `/api/routing` session/origin/CSRF admin GET/POST, `/api/client/v1/routing` strict bearer/capability/active ownership. Russian panel adds domain/subdomain DIRECT/VPN/BLOCK,7 presets, direct DNS and publication conflicts. No live server deployment.
- Lists remain an operator trust decision from pinned preparer output. Build/verify `clients/windows/prepare_system_routing.py` first, then on the authorised server use `python -m ftm.routing_policy --db /var/lib/ftm/manager.sqlite3 --catalog /root/verified-catalog.json --sha256 <SHA256 from verified output>`. Command requires Linux root, checks size/hash/shape/licence, updates metadata only. No untrusted remote URL, shell or VPN restart. TLS authenticates delivery; digest is not a publisher signature. Windows independently checks catalogue schema/provenance/regex bounds/protected ranges/month plus compressed170000/decompressed1MiB limits before commit.
- `ManagedRouting` stages per-profile Current/Previous in CurrentUser DPAPI, checks unchanged catalog/credentials/runtime and monotonic publication. Same revision content changes and older GeoIP months rejected. Manual managed-page action and opt-in periodic sync retrieve rules. Profiles/keys/token/selection remain; local EXE rules survive. Apply on next system-mode Connect, report numeric applied revision/catalog SHA. Old server404 does not change local settings. New nonempty fields are intentionally refused by old strict backup readers.
- `internal/lockfirewall`: MIT adaptation of WireGuard Windows1.1.1 WFP ABI/rules, fixed provider/sublayer/filter keys, persistent transactional base deny, fixed tunnel service SID + protected executable, dynamic TUN allowance in same sublayer. Provider associated with automatic broker for BFE restart. IPv6 stays denied, DHCPv4/loopback permitted. Broker enables/disables only while stopped. Disconnect/normal cleanup do not remove base lock. Emergency elevated `FreeTurn.Engine.exe --network-unlock` stops the owned worker first and removes only fixed owned objects; uninstall also unlocks. No external firewall reset. Pre-BFE boot protection and live BFE/reboot behaviour NOT RUN.
- `NetworkRecovery`: existing AutoReconnect checkbox now covers physical network changes, suspend/resume and worker exit. Intent only after accepted manual Connect in this window; no restore from disk/startup/backup. Read-only child exports only opaque physical IPv4/LUID/address-prefix/gateway/DNS fingerprint, not addresses. Debounce3s, periodic15s observation, maximum5 recovery attempts, CAPTCHA/suspend/changed-catalog/attempt/epoch guards. Broker mutex covers exact comparison/owned stop/new attempt/start; keys and SYSTEM routing/options stay. Sticky FakeDNS requirement preserved. Current transport frozen, auto path-switch budget not renewed by flaps. Other VPN failure defers. New attempt invalidates old HTTP/health/managed/transport work. User manual disconnect takes priority.

## Actual local verification

- Isolated Linux filesystem: baseline23 locked files and vendor package verifier PASS; full Manager suite137 tests,11 SKIPPED (web dependencies/root-only gates). Private metadata0600, CAS/revoke/policy data tests included. No VPS.
- Windows `.venv`:14 targeted root/client/HTTP tests PASS, including admin session/origin/CSRF,409 conflict, capability, device auth/revoke. Initial default-Python wrapper skips were rerun successfully with the existing venv.
- Go `test -tags with_gvisor ./...`, `vet`, release build PASS. Targeted catalogue valid/hash/gzip-bomb refusal, exact reconnect session/CAPTCHA/manual-stop guards. WFP test captures generated rules without installing: persistent ownership/unique keys,4 deny layers,4 exact exe+service-SID allowances, ephemeral exact-interface allowances; transaction failure/commit abort checks PASS. RtlCreateServiceSid/app-ID construction is read-only; actual WFP install was not invoked.
- C# build, DPAPI/backup/managed suites and `--check-policy-network` PASS: replay/substitution/stale write/tampered catalogue refusal without changing saved ciphertext; retained history/key/token/app rules; fake HTTPS→actual Go validator staging; sleep/attempt/budget/manual-stop state decisions. Actual C#→Go system routing/managed and Python↔Go managed contract PASS.
- Native WPF `--check-single-window` PASS with synthetic catalogue: embedded pages including lock page, guarded editor save, one visible window, nested/busy navigation, hidden/manual WebView local checks. No services/network configuration used.
- `verify_offline.ps1`: foreground guards/import/preflight/routing checks PASS, state digest unchanged; preflight correctly refuses OTHER_VPN_OR_NONPHYSICAL_UPLINK. Actual service IPC, VPN, WFP, DNS/IPv6 leak, crash/reboot, sleep/physical handover and real server policy E2E **NOT RUN**.
-0.22 payload hashes and ZIP remain unchanged.0.23 separate package/ZIP includes all corresponding client sources and dependency notices; final hash/size in local package report.

## Remaining acceptance, before claiming these blocks fully production-ready

1. On the authorised test VPS, deploy the root/API/panel update with verified backup and confirm existing iPhone/keys remain. Publish/import a pinned new catalogue, receive it through real internal TLS, verify active revision only changes after next Connect, reject replay/revoke.
2. On a dedicated Windows test session verify explicit lock enable→Connect→Disconnect/worker crash/UI exit→still blocked, unlock/recovery/uninstall→ordinary connectivity restored. Confirm rules reload after reboot/BFE restart; pre-BFE boot-time coverage remains a separate implementation if required. Do not use a remote-only host for the first lock test.
3. Real Wi-Fi/Ethernet/DHCP/DNS changes, sleep/Modern Standby, unavailable underlay/other VPN and5-attempt exhaustion; user Disconnect wins, same key/path, fresh egress proof, no packet leak with persistent lock. Live CAPTCHA under lock must be checked (no broad UI/browser exception was added).

No subagents, GitHub push, real VPS access, installed service update, Connect, firewall/route/DNS change or reboot during this task. AWG, installer/updater, redesign and speed optimisation were outside the selected1–3 scope.

Final artifact: `clients/windows/artifacts/FreeTurn-Windows-0.23.0-preview-win-x64.zip`, 90.45MiB,16 entries/15 payloads/215 corresponding sources/81 notices. SHA256 `742ab3c7048def0d6c89d7a03ebfdd3806eab90b47e6a2d986d0e5e331cb3660`. Payload hashes/source correspondence PASS;0.22 ZIP/payloads unchanged. Native lock page loading/padding corrected and rerun PASS.
