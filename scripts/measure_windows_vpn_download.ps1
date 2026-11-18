param(
    [Parameter(Mandatory)][string]$StatusHelper,
    [Parameter(Mandatory)][ValidateSet('relay','direct')][string]$Path,
    [Parameter(Mandatory)][ValidateSet('tcp','udp','dtls')][string]$Transport,
    [Parameter(Mandatory)][ValidateRange(1,32)][int]$Streams,
    [ValidateRange(1,3)][int]$Rounds = 3
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$helper = (Resolve-Path -LiteralPath $StatusHelper).ProviderPath
$curl = Join-Path $env:SystemRoot 'System32/curl.exe'

function Read-Status {
    $response = & dotnet $helper --read-throughput-status
    if ($LASTEXITCODE -ne 0) { throw 'FreeTurn status unavailable' }
    return $response | ConvertFrom-Json
}

function Confirm-Path($status) {
    if (!$status.Ok -or $status.State -ne 'connected' -or !$status.Handshake -or
        $status.ConnectionId -eq 0 -or $status.RuntimePath -ne $Path -or
        $status.Effective.Transport -ne $Transport -or $status.Streams -ne $Streams) {
        throw 'Expected FreeTurn path or ready stream count is unavailable'
    }
}

function Confirm-Session($status, $initial) {
    Confirm-Path $status
    if ($status.ConnectionId -ne $initial.ConnectionId -or $status.Started -ne $initial.Started -or $status.PathEpoch -ne $initial.PathEpoch) {
        throw 'FreeTurn session changed during measurement'
    }
}

function Read-EngineCPU {
    return Get-CimInstance Win32_PerfRawData_PerfProc_Process -Filter "Name LIKE 'FreeTurn.Engine%'" |
        Select-Object IDProcess,PercentProcessorTime
}

$start = Read-Status
Confirm-Path $start
$cpuStart = @(Read-EngineCPU)
$watch = [Diagnostics.Stopwatch]::StartNew()
$sampleSizes = @(0) + (@(2097152) * $Rounds)
$samples = @(foreach ($requested in $sampleSizes) {
    $before = Read-Status
    Confirm-Session $before $start
    $measure = & $curl --silent --max-time 12 --connect-timeout 5 --ipv4 --http1.1 --noproxy '*' `
        --max-filesize 2097152 --output NUL --write-out '%{http_code},%{size_download},%{time_starttransfer},%{time_total},%{speed_download}' `
        ('https://speed.cloudflare.com/__down?bytes=' + $requested)
    $exitCode = $LASTEXITCODE
    $after = Read-Status
    Confirm-Session $after $start
    $status, $received, $firstByte, $elapsed, $bytesPerSecond = $measure.Split(',')
    $invariant = [Globalization.CultureInfo]::InvariantCulture
    $complete = $exitCode -eq 0 -and $status -eq '200' -and [long]$received -eq $requested
    [pscustomobject]@{
        RequestedBytes = $requested; ReceivedBytes = [long]$received; HTTP = [int]$status; ExitCode = $exitCode
        Complete = $complete; FirstByteSeconds = [double]::Parse($firstByte,$invariant)
        Seconds = [double]::Parse($elapsed,$invariant)
        Mbps = if ($requested -gt 0) { [math]::Round([double]::Parse($bytesPerSecond,$invariant) * 8 / 1000000, 2) }
        TunnelRxDelta = [long]$after.Rx - [long]$before.Rx
        VPNFlowsDelta = if ($null -ne $after.VPNFlows) { [long]$after.VPNFlows - [long]$before.VPNFlows }
    }
})
$cpuEnd = @(Read-EngineCPU)
$wall = $watch.Elapsed.TotalSeconds
$cpu = @(foreach ($sample in $cpuEnd) {
    $previous = $cpuStart | Where-Object IDProcess -eq $sample.IDProcess
    if ($previous) {
        [math]::Round(100 * (([double]$sample.PercentProcessorTime - [double]$previous.PercentProcessorTime) / 10000000) / $wall, 1)
    }
})

[pscustomobject]@{
    Engine = $start.ServiceVersion; Path = $Path; Transport = $Transport; ReadyStreams = $Streams
    Effective = $start.Effective; SystemRouting = $start.SystemRoutingActive
    EngineCPUPercentOfOneCore = $cpu; Samples = $samples
} | ConvertTo-Json -Depth 5
