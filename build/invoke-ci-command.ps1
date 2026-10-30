#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]+$')][string]$Name,
    [Parameter(Mandatory = $true)][ValidateSet('flutter', 'dart', 'go', 'cargo')][string]$Command,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [string]$WorkingDirectory = '.',
    [string]$LogDirectory = "$env:GITHUB_WORKSPACE/check-logs"
)
$ErrorActionPreference = 'Stop'
$null = New-Item -ItemType Directory -Force -Path $LogDirectory
$log = Join-Path (Resolve-Path $LogDirectory) ($Name + '.log')
Push-Location $WorkingDirectory
try {
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 2>&1 | Tee-Object -FilePath $log | Out-Host
    $code = $LASTEXITCODE
} finally { Pop-Location }
if ($code -ne 0) { throw ($Name + ' failed, exit code ' + $code + '; see ' + $log) }
