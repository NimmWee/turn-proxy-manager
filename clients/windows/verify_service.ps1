# Read-only native regression: normal-user UI code must authenticate the real
# SYSTEM service and read a status without access to its private process token.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$testNamespace = "FreeTurn.NativeCheck.N" + [Guid]::NewGuid().ToString('N')
$source = "using System;`nusing System.Collections.Generic;`nusing System.Linq;`nusing System.Threading;`nusing System.Threading.Tasks;`n" + (Get-Content (Join-Path $PSScriptRoot 'ui/ServiceClient.cs') -Raw)
$source += "`n" + (Get-Content (Join-Path $PSScriptRoot 'ui/SocksSettings.cs') -Raw).Replace('namespace FreeTurn.Windows;','')
$source += "`n" + (Get-Content (Join-Path $PSScriptRoot 'ui/RoutingPolicy.cs') -Raw).Replace('namespace FreeTurn.Windows;','').Replace('using System.Globalization;','').Replace('using System.Text.Json.Serialization;','').Replace('JsonPropertyName(','System.Text.Json.Serialization.JsonPropertyName(')
$source += "`n" + (Get-Content (Join-Path $PSScriptRoot 'ui/CoreJournal.cs') -Raw).Replace('namespace FreeTurn.Windows;','')
$source += "`n" + (Get-Content (Join-Path $PSScriptRoot 'ui/SystemRoutingSettings.cs') -Raw).Replace('namespace FreeTurn.Windows;','').Replace('using System.Net;','').Replace('using System.Net.Sockets;','').Replace('using System.Text.Json.Serialization;','').Replace('JsonPropertyName(','System.Text.Json.Serialization.JsonPropertyName(').Replace('IPAddress.','System.Net.IPAddress.').Replace('AddressFamily.InterNetwork','System.Net.Sockets.AddressFamily.InterNetwork')
$source = $source.Replace('namespace FreeTurn.Windows;', "namespace $testNamespace;")
Add-Type -TypeDefinition $source -CompilerOptions '/nullable:enable' -ErrorAction Stop
$clientType = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType("$testNamespace.ServiceClient",$false) } | Where-Object { $null -ne $_ } | Select-Object -First 1
try {
    $method = $clientType.GetMethod('Send',[Reflection.BindingFlags]'NonPublic,Static')
    $task = $method.Invoke($null,@('status',$null,$null))
    $reply = $task.GetAwaiter().GetResult()
    if (-not $reply.Ok) { throw 'SERVICE_STATUS_REJECTED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    [pscustomobject]@{ VerifiedService=$true; Elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); State=$reply.State; HasProfile=$reply.HasProfile; NetworkChanged=$false } | ConvertTo-Json -Compress
} catch {
    # Never serialize a reply (it may contain a local CAPTCHA URL) or exception
    # strings from third-party code. This check sends no profile and no commands.
    throw 'Native service authentication/status regression failed'
}
