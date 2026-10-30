#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory = '')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or [IntPtr]::Size -ne 8 -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Native Windows x64 and a 64-bit PowerShell process are required.'
}
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'delivery-dns2' }
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$logs = Join-Path $OutputDirectory 'build-logs'
$null = New-Item -ItemType Directory -Force -Path $logs
$env:CI = 'true'
$env:BOT = 'true'
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'

function Invoke-BuildStep([string]$Name, [string]$Command, [string[]]$Arguments) {
    Write-Host ('Running ' + $Name)
    $log = Join-Path $logs ($Name + '.log')
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Command @Arguments 2>&1 | Tee-Object -FilePath $log | Out-Host
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($code -ne 0) { throw ($Name + ' failed, exit code ' + $code + '; see ' + $log) }
}

$success = $false
Push-Location $repo
try {
    foreach ($command in @('flutter', 'dart', 'go', 'cargo', 'rustc', 'git')) {
        $null = Get-Command $command -ErrorAction Stop
    }
    $flutter = (& flutter --version --machine | Out-String) | ConvertFrom-Json
    $go = (& go version | Out-String).Trim()
    $rust = (& rustc --version | Out-String).Trim()
    if ($flutter.frameworkVersion -ne '3.47.6') { throw 'Flutter 3.47.6 is required.' }
    if ($go -notmatch 'go1\.27\.1 windows/amd64') { throw 'Go 1.27.1 for windows/amd64 is required.' }
    if ($rust -notmatch '^rustc 1\.99\.1 ') { throw 'Rust 1.99.1 is required.' }
    if ((Get-Content pubspec.yaml -Raw) -notmatch 'version: 0\.9\.2-dns2\+2026103002') {
        throw 'This script must run from the dns2 source tree.'
    }
    $ca = 'core/Clash.Meta/component/ca/ca-certificates.crt'
    if (-not (Test-Path -LiteralPath $ca)) {
        Invoke-WebRequest -UseBasicParsing -Uri 'https://curl.se/ca/cacert-2026-09-25.pem' -OutFile $ca
    }
    if ((Get-FileHash $ca -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505') {
        throw 'Pinned CA bundle is missing or has changed.'
    }
    Invoke-BuildStep 'doctor' 'flutter' @('doctor', '-v')
    Invoke-BuildStep 'pub-get' 'flutter' @('pub', 'get')
    Invoke-BuildStep 'generation' 'dart' @('run', 'build_runner', 'build', '--delete-conflicting-outputs')
    Invoke-BuildStep 'localization' 'dart' @('run', 'intl_utils:generate')
    Invoke-BuildStep 'format-localization' 'dart' @('format', 'lib/l10n')
    Invoke-BuildStep 'analyze' 'flutter' @('analyze', '--no-fatal-infos')
    $env:CGO_ENABLED = '0'
    Invoke-BuildStep 'go-test' 'go' @('-C', 'core', 'test', '-timeout', '120s', '.')
    Invoke-BuildStep 'helper-test' 'cargo' @('test', '--locked', '--manifest-path', 'services/helper/Cargo.toml', '--features', 'windows-service')
    Invoke-BuildStep 'flutter-test' 'flutter' @(
        'test', '--reporter', 'expanded',
        'test/common/dns_protection_test.dart', 'test/common/dns_protection_log_test.dart',
        'test/common/dns_protection_probe_test.dart', 'test/common/http_test.dart',
        'test/core/controller_test.dart', 'test/core/service_test.dart', 'test/core/protocol_contract_test.dart',
        'test/core/desktop/helper_client_test.dart', 'test/providers/setup_action_test.dart',
        'test/manager/core_manager_test.dart', 'test/views/dns_protection_test.dart',
        'test/l10n', 'test/lint/dynamic_message_key_test.dart'
    )
    $buildStarted = [DateTime]::UtcNow
    Invoke-BuildStep 'native-windows-build' 'dart' @('run', 'setup.dart', 'windows', '--targets', 'zip', '--env', 'pre')
    $packages = @(Get-ChildItem -Path dist -Recurse -File -Filter '*windows*amd64*.zip' |
        Where-Object { $_.Name -like '*dns2*' -and $_.LastWriteTimeUtc -ge $buildStarted })
    if ($packages.Count -eq 0) { throw 'The native build did not produce a dns2 Windows amd64 ZIP.' }
    foreach ($package in $packages) { Copy-Item -LiteralPath $package.FullName -Destination $OutputDirectory -Force }
    $packages | Get-FileHash -Algorithm SHA256 | Format-List | Out-File (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding utf8
    $success = $true
} finally {
    $summary = [ordered]@{
        schema_version = 1
        build_id = '0.9.2-dns2'
        finished_utc = [DateTime]::UtcNow.ToString('o')
        host_platform = 'windows'
        build_mode = 'native'
        native_build_succeeded = $success
        gui_startup = 'not_performed'
        helper_scm_runtime = 'not_performed'
        wfp_runtime = 'not_performed'
        physical_packet_capture = 'not_performed'
        authoritative_dns_egress = 'not_performed'
    }
    $summary | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputDirectory 'native-build-result.json') -Encoding utf8
    Pop-Location
}
Write-Host ('Native build results: ' + $OutputDirectory)
Write-Host 'A successful build does not certify startup, Helper/WFP behavior or DNS leak protection.'
