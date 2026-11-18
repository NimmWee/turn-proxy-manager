param([string]$PackageDirectory = "")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$package = if ($PackageDirectory) { [IO.Path]::GetFullPath($PackageDirectory) } else { Join-Path $PSScriptRoot "artifacts/package" }
$engine = Join-Path $package "FreeTurn.Engine.exe"
$script:offlineSnapshots=[Collections.Generic.List[object]]::new()

function Invoke-Engine([string]$Argument, [string]$InputText = "") {
    $info = [Diagnostics.ProcessStartInfo]::new($engine)
    if ($Argument) { $info.ArgumentList.Add($Argument) }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $process = [Diagnostics.Process]::Start($info)
    try {
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(12000)) { $process.Kill(); throw "Engine offline command timed out" }
        return @{ Exit = $process.ExitCode; Output = $process.StandardOutput.ReadToEnd(); Error = $process.StandardError.ReadToEnd() }
    } finally { $process.Dispose() }
}

function Get-StateDigest {
    $routes = @(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric)
    $adapters = @(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid | Select-Object InterfaceGuid,InterfaceIndex,Status)
    $services = @(Get-Service -Name FreeTurnManager,'WireGuardTunnel$FTM' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object Name,Status)
    $snapshot = @{ Routes=$routes; Adapters=$adapters; Services=$services; DataExists=(Test-Path (Join-Path $env:ProgramData "FreeTurnManager")); InstallExists=(Test-Path (Join-Path $env:ProgramFiles "FreeTurnManager")) }
    $script:offlineSnapshots.Add($snapshot)
    $state=$snapshot|ConvertTo-Json -Depth 5 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($state))) } finally { $sha.Dispose() }
}

$before = Get-StateDigest
$default = Invoke-Engine ""
if ($default.Exit -ne 2) { throw "Default action must fail closed" }
foreach ($mode in @("--broker", "--tunnel")) {
    $guard = Invoke-Engine $mode
    if ($guard.Exit -ne 1) { throw "Foreground service guard failed" }
}
$removedLock = Invoke-Engine '--network-unlock'
if ($removedLock.Exit -ne 2) { throw 'Removed network lock CLI must remain unavailable' }
$invalidSetup = Invoke-Engine '--setup' # Missing SID must never enter install/upgrade.
if ($invalidSetup.Exit -ne 2) { throw 'Setup argument guard failed' }
# All keys, links and addresses in this fixture are synthetic and non-working.
$key = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('x' * 32)))
$wg = "[Interface]`nPrivateKey = $key`nAddress = 10.77.43.9/32`nDNS = 1.1.1.1`nMTU = 1280`n[Peer]`nPublicKey = $key`nPresharedKey = $key`nAllowedIPs = 0.0.0.0/0, ::/0`nEndpoint = 127.0.0.1:9000`nPersistentKeepalive = 25`n"
$fixture = @{ v=1; provider="vk"; peer="203.0.113.1:5000"; mode="udp"; transport="tcp"; obf="rtpopus3"; key=('a'*64); cid=('b'*32); n=6; spc=3; vk="https://vk.com/call/join/SYNTHETIC"; wg=$wg } | ConvertTo-Json -Compress
$share = "freeturn://" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($fixture)).TrimEnd('=').Replace('+','-').Replace('/','_')
$valid = Invoke-Engine "--check-profile" $share
$invalid = Invoke-Engine "--check-profile" "freeturn://INVALID_SYNTHETIC_INPUT"
if ($valid.Exit -ne 0 -or -not ($valid.Output | ConvertFrom-Json).ok -or $invalid.Exit -ne 1) { throw "Offline import scenario failed" }
$bootstrapNative=$fixture|ConvertFrom-Json
$bootstrapNative.peer='8.8.8.8:5000'
$bootstrapShare='freeturn://'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($bootstrapNative|ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
$bootstrap=@{version=1;format='ftm-bootstrap';device_id='11111111-2222-3333-4444-555555555555';public_key='m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=';origin='https://8.8.8.8';internal_api_ip='10.77.43.1';claim_nonce=('ftmb1_'+('A'*43));expires_at='2020-01-01T00:00:00Z';share=$bootstrapShare}
$bootstrapCheck=Invoke-Engine '--check-bootstrap' ($bootstrap|ConvertTo-Json -Compress)
$bootstrap.origin='https://1.1.1.1'
$bootstrapRejected=Invoke-Engine '--check-bootstrap' ($bootstrap|ConvertTo-Json -Compress)
if($bootstrapCheck.Exit-ne 0-or -not($bootstrapCheck.Output|ConvertFrom-Json).ok-or $bootstrapRejected.Exit-ne 1){throw 'Offline bootstrap key/origin validation failed'}
$enrollmentKey=@{origin='https://8.8.8.8';private_key=$key;public_key='m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY='}
$enrollmentCheck=Invoke-Engine '--check-enrollment-key' ($enrollmentKey|ConvertTo-Json -Compress)
$enrollmentKey.origin='https://169.254.169.254'
$enrollmentRejected=Invoke-Engine '--check-enrollment-key' ($enrollmentKey|ConvertTo-Json -Compress)
if($enrollmentCheck.Exit-ne 0-or -not($enrollmentCheck.Output|ConvertFrom-Json).ok-or $enrollmentRejected.Exit-ne 1){throw 'Offline enrollment identity/origin validation failed'}
$routingInput = '{"policy":{"v":1,"rules":[{"domain":"example.com","action":"direct","subdomains":true}]},"host":"cdn.example.com"}'
$routing = Invoke-Engine '--check-routing' $routingInput
if ($routing.Exit -ne 0) { throw 'Offline routing preview failed' }
$routingReport = $routing.Output | ConvertFrom-Json
if (-not $routingReport.ok -or $routingReport.networkChanged -or $routingReport.scope -ne 'socks-tcp-ipv4' -or $routingReport.decision.action -ne 'direct') { throw 'Offline routing preview returned an unsafe result' }
$systemRouting=Invoke-Engine '--check-system-routing' '{"policy":{"v":1,"enabled":true,"presets":{"russianDirect":true,"youtubeVPN":true}},"host":"youtube.com","ip":"77.88.55.55"}'
if ($systemRouting.Exit -ne 0) { throw 'Offline system routing preview failed' }
$systemReport=$systemRouting.Output | ConvertFrom-Json
if (-not $systemReport.ok -or $systemReport.active -or $systemReport.networkChanged -or $systemReport.scope -ne 'system-routing-preview' -or -not $systemReport.runtimeIntegrated -or $systemReport.decision.action -ne 'vpn') { throw 'System preview claimed active/changed network or lost precedence' }
$preflight = Invoke-Engine "--preflight"
$preflightReport = $preflight.Output | ConvertFrom-Json
if (-not $preflightReport.driverChecksum -or $preflightReport.architecture -ne "amd64") { throw "Driver or architecture check failed" }
$after = Get-StateDigest
if ($before -ne $after) { $changed=@('Routes','Adapters','Services','DataExists','InstallExists')|Where-Object{($script:offlineSnapshots[0][$_]|ConvertTo-Json -Depth 5 -Compress)-cne($script:offlineSnapshots[1][$_]|ConvertTo-Json -Depth 5 -Compress)};throw ("Network/service state changed during offline verification; inspect before proceeding. Categories: "+($changed-join ',')) }
$report = @{ OfflineImport="PASS"; BootstrapValidation="PASS"; EnrollmentKeyValidation="PASS"; RoutingPolicyPreview="PASS"; SystemRoutingPreview="PASS"; ForegroundServiceGuards="PASS"; StateDigestUnchanged=$true; Preflight=$preflightReport; SystemServiceIPC="NOT RUN"; WindowsVPNE2E="NOT RUN" }
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $PSScriptRoot "artifacts/offline-check.json") -Encoding utf8
$report | ConvertTo-Json -Depth 4
