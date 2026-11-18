param([Parameter(Mandatory)][string]$ReportPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$destination=[IO.Path]::GetFullPath($ReportPath)
$expectedTemp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
if([IO.Path]::GetDirectoryName($destination) -ne $expectedTemp -or [IO.Path]::GetFileName($destination) -notmatch '^ftm-windows-diagnostics-[a-f0-9]{32}\.json$'){throw 'Unsafe report destination'}
$suffix=[Guid]::NewGuid().ToString('N')
$taskName='FreeTurn-ReadOnlyDiagnostic-'+$suffix
$systemReport=Join-Path $env:SystemRoot ('Temp\ftm-windows-diagnostics-'+$suffix+'.json')
$reader=(Resolve-Path (Join-Path $PSScriptRoot 'read_windows_vpn_diagnostics.ps1')).Path
$engine=(Resolve-Path (Join-Path $PSScriptRoot '..\clients\windows\artifacts\package\FreeTurn.Engine.exe')).Path
$arguments='-NoProfile -NonInteractive -File "'+$reader+'" -ReportPath "'+$systemReport+'" -RuntimeReader "'+$engine+'"'
$action=New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument $arguments
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
$registered=$false
try {
    # On-demand only: no persistent trigger. Never starts/stops VPN services.
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered=$true
    Start-ScheduledTask -TaskName $taskName
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 200
        $info=Get-ScheduledTaskInfo -TaskName $taskName
        $task=Get-ScheduledTask -TaskName $taskName
    } while(($info.LastRunTime.Year -lt 2020 -or $task.State -eq 'Running') -and [DateTime]::UtcNow -lt $deadline)
    if($task.State -eq 'Running' -or $info.LastTaskResult -ne 0 -or !(Test-Path -LiteralPath $systemReport)){throw 'Diagnostic task did not finish successfully'}
    # This contains only the reader's allowlisted counters/codes, never raw logs.
    $safe=[IO.File]::ReadAllBytes($systemReport)
    $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$output.Write($safe);$output.Flush($true)}finally{$output.Dispose()}
} finally {
    if($registered){Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    if(Test-Path -LiteralPath $systemReport){Remove-Item -LiteralPath $systemReport}
}
