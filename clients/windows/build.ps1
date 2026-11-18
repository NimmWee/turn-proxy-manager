param([string]$GoExecutable = "go", [switch]$SkipPrepare, [string]$OutputDirectory = "")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$nativeRoot = $PSScriptRoot
$workspaceRoot = Split-Path (Split-Path $nativeRoot -Parent) -Parent
$output = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $nativeRoot "artifacts/package" }
New-Item -ItemType Directory -Force -Path $output | Out-Null
if (-not $SkipPrepare) {
    & python (Join-Path $nativeRoot "prepare.py")
    if ($LASTEXITCODE -ne 0) { throw "Dependency preparation failed" }
}
$driverPath = Join-Path $nativeRoot "artifacts/dependencies/wireguard.dll"
$signature = Get-AuthenticodeSignature -LiteralPath $driverPath
if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch 'O=WireGuard LLC') { throw "WireGuardNT signature is not trusted" }
$lock = Get-Content (Join-Path $nativeRoot "dependencies.json") -Raw | ConvertFrom-Json
& python (Join-Path $nativeRoot "prepare_system_routing.py") --check
if ($LASTEXITCODE -ne 0) { throw 'Routing asset verification failed' }
if ((Get-FileHash -LiteralPath (Join-Path $nativeRoot 'Wintun-LICENSE.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $lock.wintun.licenseSha256) { throw 'Wintun license checksum mismatch' }
if ((Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $lock.wireguardNT.amd64Sha256) { throw "WireGuardNT checksum mismatch" }
foreach ($fontAsset in $lock.roboto.files.PSObject.Properties) {
    if ($fontAsset.Name -notin @('Roboto-Regular.ttf','Roboto-Medium.ttf','Roboto-Bold.ttf')) { throw 'Unexpected font asset' }
    $fontPath = Join-Path $nativeRoot ("ui/Assets/" + $fontAsset.Name)
    if ((Get-FileHash -LiteralPath $fontPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $fontAsset.Value) { throw 'Roboto checksum mismatch' }
}
$oldArch = $env:GOARCH
$oldOS = $env:GOOS
$oldCGO = $env:CGO_ENABLED
Push-Location (Join-Path $nativeRoot "engine")
try {
    $env:GOARCH = "amd64"
    $env:GOOS = "windows"
    $env:CGO_ENABLED = "0"
    $singTunModule = $lock.singTunGoModule.Split('@')[0]
    $singTunJson = & $GoExecutable list -mod=readonly -m -json $singTunModule
    if ($LASTEXITCODE -ne 0) { throw 'Pinned sing-tun module unavailable' }
    $singTunInfo = ($singTunJson -join "`n") | ConvertFrom-Json
    if (($singTunInfo.Path + '@' + $singTunInfo.Version) -ne $lock.singTunGoModule) { throw 'Unexpected sing-tun version' }
    $embeddedWintun = Join-Path $singTunInfo.Dir 'internal/wintun/amd64/wintun.dll'
    if ((Get-FileHash -LiteralPath $embeddedWintun -Algorithm SHA256).Hash.ToLowerInvariant() -ne $lock.wintun.amd64Sha256) { throw 'Embedded Wintun checksum mismatch' }
    $wintunSignature = Get-AuthenticodeSignature -LiteralPath $embeddedWintun
    if ($wintunSignature.Status -ne 'Valid' -or $wintunSignature.SignerCertificate.Subject -notmatch 'O=WireGuard LLC') { throw 'Embedded Wintun signature is not trusted' }
    & $GoExecutable test -mod=readonly -tags with_gvisor ./...
    if ($LASTEXITCODE -ne 0) { throw "Engine checks failed" }
    & $GoExecutable vet -mod=readonly -tags with_gvisor ./...
    if ($LASTEXITCODE -ne 0) { throw "Engine vet failed" }
    & $GoExecutable build -mod=readonly -tags with_gvisor -trimpath -ldflags="-s -w" -o (Join-Path $output "FreeTurn.Engine.exe") .
    if ($LASTEXITCODE -ne 0) { throw "Engine build failed" }
} finally {
    Pop-Location
    $env:GOARCH = $oldArch
    $env:GOOS = $oldOS
    $env:CGO_ENABLED = $oldCGO
}
$projectVersion = ([xml](Get-Content (Join-Path $nativeRoot 'ui/FreeTurn.Windows.csproj') -Raw)).Project.PropertyGroup.Version
$engineVersion = & (Join-Path $output 'FreeTurn.Engine.exe') --version
if ($LASTEXITCODE -ne 0 -or $engineVersion -notmatch ('engine ' + [regex]::Escape($projectVersion) + '-preview;')) { throw 'UI/engine version mismatch' }
& dotnet publish (Join-Path $nativeRoot "ui/FreeTurn.Windows.csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:RestoreLockedMode=true -o $output
if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }
Copy-Item -LiteralPath $driverPath -Destination (Join-Path $output "wireguard.dll") -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "artifacts/dependencies/WireGuardNT-LICENSE.txt") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $workspaceRoot ".references/core-windows-v4.1.5/LICENSE") -Destination (Join-Path $output "FreeTurn-Core-LICENSE.txt") -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "README.md") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "THIRD_PARTY.md") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "dependencies.json") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "Android-LICENSE.txt") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "Roboto-LICENSE.txt") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "SSH.NET-LICENSE.txt") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "WindowsSDK-LICENSE.rtf") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $nativeRoot "Wintun-LICENSE.txt") -Destination $output -Force
Add-Type -AssemblyName System.IO.Compression
$sourceZipPath = Join-Path $output "Windows-Client-Sources.zip"
$sourceStream = [IO.File]::Create($sourceZipPath)
$sourceZip = [IO.Compression.ZipArchive]::new($sourceStream,[IO.Compression.ZipArchiveMode]::Create)
try {
    $sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $nativeRoot "ui"),(Join-Path $nativeRoot "engine"),(Join-Path $nativeRoot "catalog-check") -Recurse -File | Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' -and $_.Extension -in @('.cs','.xaml','.csproj','.go','.ttf','.ico') })
    $sourceFiles += @('README.md','THIRD_PARTY.md','Android-LICENSE.txt','Roboto-LICENSE.txt','SSH.NET-LICENSE.txt','WindowsSDK-LICENSE.rtf','dependencies.json','build.ps1','prepare.py','collect_licenses.py','generate_icon.ps1','import_android_icons.py','verify_service.ps1','verify_offline.ps1','verify_ssh_loopback.py','engine/go.mod','engine/go.sum','ui/packages.lock.json','catalog-check/packages.lock.json') | ForEach-Object { Get-Item -LiteralPath (Join-Path $nativeRoot $_) }
$sourceFiles += @('Wintun-LICENSE.txt','routing-data.lock.json','prepare_system_routing.py','routing_geoip.py','verify_geoip.py','verify_managed_contract.py','engine/routingdata/catalog.json','engine/routingdata/LICENSES.txt','engine/routingdata/sources.zip') | ForEach-Object { Get-Item -LiteralPath (Join-Path $nativeRoot $_) }
    foreach ($sourceFile in $sourceFiles) {
        $relativeSource = [IO.Path]::GetRelativePath($nativeRoot,$sourceFile.FullName).Replace('\','/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($sourceZip,$sourceFile.FullName,"clients/windows/$relativeSource") | Out-Null
    }
} finally { $sourceZip.Dispose(); $sourceStream.Dispose() }
& python (Join-Path $nativeRoot "collect_licenses.py") --go $GoExecutable --output (Join-Path $output "THIRD_PARTY_NOTICES.txt")
if ($LASTEXITCODE -ne 0) { throw "Dependency notices collection failed" }
$packageNames = @("FreeTurn.Windows.exe", "FreeTurn.Engine.exe", "wireguard.dll", "FreeTurn-Core-LICENSE.txt", "WireGuardNT-LICENSE.txt", "Android-LICENSE.txt", "Roboto-LICENSE.txt", "SSH.NET-LICENSE.txt", "WindowsSDK-LICENSE.rtf", "Windows-Client-Sources.zip", "THIRD_PARTY_NOTICES.txt", "README.md", "THIRD_PARTY.md", "dependencies.json")
$packageNames += 'Wintun-LICENSE.txt'
$packagePaths = $packageNames | ForEach-Object { Join-Path $output $_ }
$hashes = $packagePaths | ForEach-Object { "{0}  {1}" -f (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $_ -Leaf) }
$hashes | Set-Content -LiteralPath (Join-Path $output "SHA256SUMS.txt") -Encoding utf8
$projectFile = [xml](Get-Content (Join-Path $nativeRoot "ui/FreeTurn.Windows.csproj") -Raw)
$appVersion = $projectFile.Project.PropertyGroup.Version
Compress-Archive -LiteralPath ($packagePaths + (Join-Path $output "SHA256SUMS.txt")) -DestinationPath (Join-Path $nativeRoot "artifacts/FreeTurn-Windows-$appVersion-preview-win-x64.zip") -Force
Write-Output "Built unsigned Windows preview: $output"
Write-Output "No services installed, no tunnel started, no network settings changed."
