param([string]$ReportPath,[string]$RuntimeReader)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-FTMRingLog([string]$Path) {
    # Pinned WireGuard Windows1.1.1 layout:8-byte header +2048*(int64+512).
    # Open read-only. Do not use NewRinglogger: it creates/truncates the file.
    try {
        $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            if ($stream.Length -ne 1064968) { return @{State='INVALID_SIZE'} }
            $bytes = [byte[]]::new(1064968); $stream.ReadExactly($bytes)
        } finally { $stream.Dispose() }
    } catch [IO.FileNotFoundException] { return @{State='MISSING'} }
      catch [UnauthorizedAccessException] { return @{State='ACCESS_DENIED'} }
    if ([BitConverter]::ToUInt32($bytes,0) -ne 0x0badbabe) { return @{State='INVALID_MAGIC'} }
    $rules = [ordered]@{
        WG_WATCH='Watching network interfaces'; WG_ADAPTER_CREATE='Creating network adapter'
        WG_FIREWALL='Enabling firewall'; WG_CONFIGURE='Setting interface configuration'
        WG_RUNNING='Startup complete'; WG_STOPPED='Shutting down'
        WG_CONFIG_ERROR='Unable to load configuration'; WG_ADAPTER_ERROR='Error creating adapter|Unable to create network adapter'
        WG_FIREWALL_ERROR='Unable to enable firewall'; WG_DEVICE_ERROR='Unable to set device configuration|Unable to bring up adapter'
        WG_NETWORK_ERROR='Unable to configure adapter network settings'; WG_LOG_ERROR='Unable to open log file'
        PATH_NOT_FOUND='cannot find the path specified|не удается найти указанный путь'
        FILE_NOT_FOUND='cannot find the file specified|не удается найти указанный файл'
        ACCESS_DENIED='Access is denied|Отказано в доступе'; SHUTDOWN_TIMEOUT='Failed to shutdown after 30 seconds'
        WG_HANDSHAKE_SENT='Sending handshake initiation'; WG_HANDSHAKE_RESPONSE='Receiving handshake response'
        WG_HANDSHAKE_TIMEOUT='Handshake.*did not complete'; WG_SEND_FAILED='Failed to send handshake initiation'
        WG_RX_KEEPALIVE='Receiving keepalive'; WG_KEYPAIR_CREATED='Keypair.*created'; WG_ROUTE_FAILED='No route to host'
    }
    $events = [Collections.Generic.List[object]]::new(); $total=0
    for($index=0;$index -lt 2048;$index++) {
        $offset=8+$index*520; $stamp=[BitConverter]::ToInt64($bytes,$offset)
        if($stamp -le 0){continue}; $total++
        $text=[Text.Encoding]::UTF8.GetString($bytes,$offset+8,512).Split([char]0)[0]
        $codes=@(foreach($rule in $rules.GetEnumerator()){if($text -match $rule.Value){$rule.Key}})
        if($codes.Count -gt 0){$events.Add(@{UnixNanoseconds=$stamp;Codes=$codes})}
        $text=$null
    }
    return @{State='READ';TotalLines=$total;RecognizedEvents=@($events|Sort-Object UnixNanoseconds|Select-Object -Last 80)}
}

if($MyInvocation.InvocationName -eq '.') { return }
if([string]::IsNullOrWhiteSpace($ReportPath)){throw 'ReportPath is required'}
$absolute=[IO.Path]::GetFullPath($ReportPath)
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
if([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem){$tempRoot=[IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'Temp')).TrimEnd('\')}
if([IO.Path]::GetDirectoryName($absolute) -ne $tempRoot -or [IO.Path]::GetFileName($absolute) -notmatch '^ftm-windows-diagnostics-[a-f0-9]{32}\.json$'){throw 'Unsafe report destination'}
for($parent=Get-Item -LiteralPath $tempRoot;$null -ne $parent;$parent=$parent.Parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe report directory'}}
$report=[ordered]@{Schema=1;ReadOnly=$true;RingLog=Read-FTMRingLog (Join-Path $env:ProgramData 'FreeTurnManager\log.bin')}
$report.Services=@(Get-CimInstance Win32_Service|Where-Object{$_.Name -in @('FreeTurnManager','WireGuardTunnel$FTM')}|Select-Object Name,State,ExitCode,ServiceSpecificExitCode)
$report.Files=@(foreach($name in @('profile.dpapi','options.dpapi','runtime.dpapi','failure.dpapi')){
    $path=Join-Path $env:ProgramData ('FreeTurnManager\'+$name)
    if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path;@{Name=$name;Bytes=$item.Length;UpdatedUTC=$item.LastWriteTimeUtc.ToString('o')}}
})
if($RuntimeReader){$expected=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\clients\windows\artifacts\package\FreeTurn.Engine.exe'));if([IO.Path]::GetFullPath($RuntimeReader) -ne $expected){throw 'Unexpected runtime reader'}; $runtimeText=& $expected '--read-runtime-diagnostic'; $report.Runtime=$runtimeText|ConvertFrom-Json}
$json=$report|ConvertTo-Json -Depth 8
$output=[IO.File]::Open($absolute,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$buffer=[Text.UTF8Encoding]::new($false).GetBytes($json);$output.Write($buffer);$output.Flush($true)}finally{$output.Dispose()}
