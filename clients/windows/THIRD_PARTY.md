# Dependencies and notices

Starting with the 0.2 port, Windows client models/design are adapted from FreeTurn Android 5.3.4, commit `bab60c5fb620cbea2570eeeb5a0697dc355071f4` (https://github.com/hackdiaz-dev/turn-proxy-android). The derived Windows UI is GPL-3.0-only; full license text is `Android-LICENSE.txt`. Preserve upstream attribution and provide corresponding source with redistribution. No Android APK or Compose Desktop binaries are bundled. The independent engine uses the public Go API of FreeTurn core and the official WireGuard Windows tunnel package.

`Windows-Client-Sources.zip` in the package includes the corresponding client/engine source, build scripts, dependency locks and license text. Extract into a workspace root to preserve the `clients/windows` layout; the pinned core source is fetched and verified by `prepare.py`.

- FreeTurn core v4.1.5, `hackdiaz-dev/free-turn-proxy`, commit `f6b1f25767755d9bf34cbf78818b74c5062d7d0c`: Happy Bunny License, distributed as `FreeTurn-Core-LICENSE.txt`.
- WireGuard Windows v1.1.1: MIT, https://git.zx2c4.com/wireguard-windows/tree/COPYING . Go module checksums in `engine/go.sum`.
- WireGuardNT 1.1: official signed amd64 binary, license from its SDK distributed as `WireGuardNT-LICENSE.txt`. Archive and DLL hashes in `dependencies.json`.
- Microsoft go-winio v0.6.2: MIT, https://github.com/microsoft/go-winio/blob/v0.6.2/LICENSE . Local pipe remote clients are rejected by upstream.
- Microsoft WebView2 SDK 1.0.4314.35: Microsoft license included in the NuGet package, https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4314.35 . Evergreen Runtime is installed separately by its own installer.
- SSH.NET 2026.0.1, Copyright © Renci 2010–2026: MIT, https://github.com/sshnet/SSH.NET/tree/eaa52dba9555ca1ce57972557277c46733987dc5 ; license text included as `SSH.NET-LICENSE.txt`. Dependencies (including BouncyCastle) are pinned by NuGet locks, with license notices collected from packages. No SSH credential is passed on an OS command line.
- Go transitive modules are pinned in `engine/go.mod` and `engine/go.sum`; NuGet dependency integrity is pinned in `ui/packages.lock.json`.
- Opt-in system routing in0.10 uses sing-tun v0.9.6 (GPL-3.0-or-later), its pinned sing/gVisor dependencies, and AmneziaWG-Go netstack. Exact versions/checksums are in Go locks. Ordinary WGNT stays default; real system-routing acceptance is still NOT RUN.
- sing-tun embeds the unmodified official signed Wintun 0.14.1 amd64 DLL. Its SHA256 and archive/license pins are in `dependencies.json`; the build verifies hash and Authenticode in the module cache. `Wintun-LICENSE.txt` is the official prebuilt-binary license, distinct from the MIT Go bindings.
- Routing data: V2Fly domain-list-community (MIT) and DB-IP IP to Country Lite2026-11 (CC BY4.0). [IP Geolocation by DB-IP](https://db-ip.com/); license: https://creativecommons.org/licenses/by/4.0/ . Modified by FreeTurn Manager: RU IPv4 selection, range-to-CIDR conversion and merging; IPv6 omitted. Source URLs/compressed and raw SHA256/record count/compiled hashes are pinned in `routing-data.lock.json`. `engine/routingdata/sources.zip` contains used domain data, the complete original DB-IP CSV.gz, license and attribution/modification notice; `LICENSES.txt` repeats the notices. GeoIP is approximate, with limited coverage/accuracy. Runtime downloads no rule updates.
- Domain normalization and the bundled Public Suffix List use the existing pinned `golang.org/x/net v0.60.0` IDNA/publicsuffix packages (BSD-3-Clause; notices collected from the Go module). No online suffix-list fetch or domain telemetry is performed.

The build collects Go, NuGet and included .NET runtime license/notice texts in `THIRD_PARTY_NOTICES.txt`. Review the final bundle before public redistribution. This local development package is not a signed public release.

- Roboto Regular/Medium/Bold, Google: Apache-2.0. Static fonts embedded as WPF resources, not installed into Windows. Source https://github.com/googlefonts/roboto-2/tree/38062f4b4a0be4346d07a928408da21602545e9e ; per-file SHA256 in dependencies.json, full license in Roboto-LICENSE.txt.
