#requires -Version 7.0
$ErrorActionPreference = 'Stop'
$delivery = Join-Path $env:GITHUB_WORKSPACE 'delivery'
$null = New-Item -ItemType Directory -Force -Path $delivery
$packages = @(Get-ChildItem source/FlClash-DNS/dist -Recurse -File -Filter '*windows*amd64*.zip' | Where-Object { $_.Name -like '*dns2*' })
if ($packages.Count -ne 1) { throw 'Expected one native Windows client ZIP.' }
Copy-Item -LiteralPath $packages[0].FullName -Destination $delivery
$package = Get-Item (Join-Path $delivery $packages[0].Name)
$unpacked = Join-Path $env:RUNNER_TEMP 'dns2-client-verification'
Expand-Archive -LiteralPath $package.FullName -DestinationPath $unpacked
$apps = @(Get-ChildItem $unpacked -Recurse -File -Filter FlClash.exe)
if ($apps.Count -ne 1) { throw 'The client ZIP must contain exactly one FlClash.exe.' }
$bundle = $apps[0].Directory.FullName
foreach ($name in @('FlClash.exe', 'FlClashCore.exe', 'FlClashHelperService.exe', 'flutter_windows.dll', 'manifest.json', 'data/icudtl.dat', 'data/app.so', 'data/flutter_assets')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bundle $name))) { throw ('Incomplete native client: ' + $name) }
}
foreach ($name in @('FlClash.exe', 'FlClashCore.exe', 'FlClashHelperService.exe', 'flutter_windows.dll')) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $bundle $name))
    if ($bytes[0] -ne 77 -or $bytes[1] -ne 90) { throw ('Missing Windows PE header: ' + $name) }
}
$coreManifest = Get-Content (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
$coreHash = (Get-FileHash (Join-Path $bundle 'FlClashCore.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($coreHash -ne $coreManifest.coreSha256) { throw 'Core binary and Helper manifest do not match.' }
Get-ChildItem $bundle -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object -Property @('Path', 'Hash') | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $delivery 'client-file-hashes.json')
Copy-Item build/source-manifest.json (Join-Path $delivery 'source-input.json')
$sha = (Get-FileHash $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
($sha + '  ' + $package.Name) | Set-Content (Join-Path $delivery 'SHA256SUMS.txt')
[ordered]@{
    schema_version = 1
    build_id = '0.9.2-dns2.1'
    package = $package.Name
    package_sha256 = $sha
    core_sha256 = $coreHash
    complete_client = $true
    native_windows_build = 'passed'
    gui_startup = 'not_performed'
    helper_scm_runtime = 'not_performed'
    wfp_runtime = 'not_performed'
    physical_dns_leak_acceptance = 'not_performed'
} | ConvertTo-Json | Set-Content (Join-Path $delivery 'package-verification.json')
