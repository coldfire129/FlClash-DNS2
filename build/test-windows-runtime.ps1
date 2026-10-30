#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$packages = @(Get-ChildItem $ArtifactDirectory -File -Filter '*windows*amd64*.zip')
if ($packages.Count -ne 1) { throw 'Expected exactly one native Windows client ZIP.' }
$unpacked = Join-Path $env:RUNNER_TEMP ('dns2-runtime-' + [Guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $packages[0].FullName -DestinationPath $unpacked
$apps = @(Get-ChildItem $unpacked -Recurse -File -Filter FlClash.exe)
if ($apps.Count -ne 1) { throw 'Expected exactly one FlClash.exe.' }
$bundle = $apps[0].Directory.FullName
$helperPath = Join-Path $bundle 'FlClashHelperService.exe'
$corePath = Join-Path $bundle 'FlClashCore.exe'
$coreManifest = Get-Content (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
$coreHash = (Get-FileHash $corePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($coreHash -ne $coreManifest.coreSha256) { throw 'Native Core does not match manifest.' }
$result = [ordered]@{
    schema_version = 1
    build_id = '0.9.2-dns2'
    environment = 'GitHub hosted Windows VM'
    runtime_script_revision = $env:DNS2_RUNTIME_SCRIPT_SHA
    native_build_run_id = $env:DNS2_NATIVE_BUILD_RUN
    native_package_sha256 = (Get-FileHash $packages[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    core_sha256 = $coreHash
    helper_scm = 'not_performed'
    helper_protocol = 'not_performed'
    helper_owned_core_ipc = 'not_performed'
    wfp_dynamic_sublayer_lifecycle = 'not_performed'
    journal_system_owner_and_acl = 'not_performed'
    legacy_admin_owner_repair = 'not_performed'
    gui_process_startup = 'not_performed'
    gui_window_created = $false
    human_gui_acceptance = 'not_performed'
    tun_dns_connectivity = 'not_performed'
    physical_dns_leak_acceptance = 'not_performed'
    authoritative_dns_egress = 'not_performed'
}
$errors = [Collections.Generic.List[string]]::new()
$installed = $false
$pipe = $null
$base = $null
$ownedSession = $false
$environmentClean = $false
$sublayerNotFound = [Convert]::ToUInt32('80320007', 16)
$sessionId = [Guid]::NewGuid().ToString('N')
$journal = Join-Path $env:ProgramData 'FlClashDnsProtection'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class Dns2NativeCheck {
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string server, uint authn, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr layer);
    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint processId);
    public static uint QueryGuardSubLayer() {
        IntPtr engine;
        uint code = FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine);
        if (code != 0) throw new Win32Exception(unchecked((int)code));
        try {
            Guid key = new Guid("5b3b80a6-4e39-48e5-9f6c-2cc01ddb9821");
            IntPtr layer = IntPtr.Zero;
            code = FwpmSubLayerGetByKey0(engine, ref key, out layer);
            if (layer != IntPtr.Zero) FwpmFreeMemory0(ref layer);
            return code;
        } finally { FwpmEngineClose0(engine); }
    }
}
'@

function Invoke-Helper([string]$Path, [hashtable]$Body) {
    Invoke-RestMethod -Uri ($base + $Path) -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -NoProxy -TimeoutSec 10
}

function Assert-SystemJournal {
    $acl = Get-Acl -LiteralPath $journal
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-18') { throw ('Journal is not SYSTEM-owned: ' + $owner) }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw ('Unexpected journal ACL identity: ' + $sid) }
    }
    if (-not (Test-Path (Join-Path $journal 'guard.jsonl'))) { throw 'Helper journal was not created.' }
}

try {
    if (Get-Service FlClashHelperService -ErrorAction SilentlyContinue) { throw 'Refusing to replace an existing Helper service.' }
    if (Test-Path -LiteralPath $journal) { throw 'Refusing to modify an existing journal directory.' }
    if ([Dns2NativeCheck]::QueryGuardSubLayer() -ne $sublayerNotFound) { throw 'Unexpected pre-existing Guard WFP state.' }
    $environmentClean = $true
    & $helperPath install --owner-pid $PID 2>&1 | Out-File (Join-Path $OutputDirectory 'helper-install.log')
    $installCode = $LASTEXITCODE
    $service = Get-CimInstance Win32_Service -Filter "Name='FlClashHelperService'"
    $installed = $service -and $service.PathName.IndexOf($helperPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
    if ($installCode -ne 0) { throw ('Helper install failed: ' + $installCode) }
    if ($service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem' -or $service.PathName.IndexOf($helperPath, [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw 'Unexpected SCM service identity, executable or state.' }
    $result.helper_scm = 'passed'
    $result.helper_service_pid = $service.ProcessId
    $port = (Get-ItemProperty 'HKLM:/SYSTEM/CurrentControlSet/Services/FlClashHelperService/Runtime').Port
    $base = 'http://127.0.0.1:' + $port
    $ping = Invoke-WebRequest -Uri ($base + '/ping?coreSha256=' + $coreHash) -NoProxy -TimeoutSec 10
    if ([int]$ping.StatusCode -ne 200 -or @($ping.Headers['x-flclash-helper-protocol'])[0] -ne '9') { throw 'Helper ping protocol or Core hash verification failed.' }
    $result.helper_protocol = 'passed'
    $pipeName = 'FlClashCore_' + $sessionId
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($pipeName, [IO.Pipes.PipeDirection]::InOut, 1, [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
    $connection = $pipe.WaitForConnectionAsync()
    $started = Invoke-Helper '/start' @{ address = ('\\.\pipe\' + $pipeName); sessionId = $sessionId }
    $ownedSession = $true
    if ($started.sessionId -ne $sessionId -or -not $connection.Wait(10000)) { throw 'Helper-owned Core failed to connect to the native pipe.' }
    [uint32]$clientPid = 0
    if (-not [Dns2NativeCheck]::GetNamedPipeClientProcessId($pipe.SafePipeHandle.DangerousGetHandle(), [ref]$clientPid) -or $clientPid -ne $started.pid) { throw 'Native IPC peer PID does not match the Helper-owned Core.' }
    $result.helper_owned_core_ipc = 'passed'
    $result.core_pid = $clientPid
    $armed = Invoke-Helper '/dns-protection' @{ sessionId = $sessionId; enabled = $true }
    if (-not $armed.armed -or $armed.errorCode -or $armed.bound -or $armed.diagnosticError) { throw 'Guard did not enter the expected armed/no-TUN state with working diagnostics.' }
    if ([Dns2NativeCheck]::QueryGuardSubLayer() -ne 0) { throw 'Guard WFP sublayer is missing after arm.' }
    Assert-SystemJournal
    $result.journal_system_owner_and_acl = 'passed'
    $released = Invoke-Helper '/dns-protection' @{ sessionId = $sessionId; enabled = $false }
    if ($released.armed -or [Dns2NativeCheck]::QueryGuardSubLayer() -ne $sublayerNotFound) { throw 'Guard did not remove its dynamic WFP sublayer after release.' }
    $result.wfp_dynamic_sublayer_lifecycle = 'passed'
    try {
        $legacyAcl = Get-Acl -LiteralPath $journal
        $legacyAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        Set-Acl -LiteralPath $journal -AclObject $legacyAcl
    } catch {
        $result.legacy_admin_owner_repair = 'not_performed_fixture_permission_denied'
    }
    if ($result.legacy_admin_owner_repair -eq 'not_performed') {
        $legacy = Invoke-Helper '/dns-protection' @{ sessionId = $sessionId; enabled = $true }
        if (-not $legacy.armed -or $legacy.diagnosticError) { throw 'Helper could not repair the trusted Administrators-owned journal.' }
        Assert-SystemJournal
        $null = Invoke-Helper '/dns-protection' @{ sessionId = $sessionId; enabled = $false }
        $result.legacy_admin_owner_repair = 'passed'
    }
    Copy-Item (Join-Path $journal 'guard.jsonl') (Join-Path $OutputDirectory 'guard.jsonl')
    (Get-Acl $journal).Sddl | Set-Content (Join-Path $OutputDirectory 'journal-sddl.txt')
} catch {
    $errors.Add($_.Exception.Message)
} finally {
    if ($ownedSession -and $base) {
        try { $null = Invoke-Helper '/dns-protection' @{ sessionId = $sessionId; enabled = $false } } catch { $errors.Add('Guard cleanup: ' + $_.Exception.Message) }
    }
    if ($pipe) { $pipe.Dispose(); $pipe = $null }
    if ($ownedSession -and $base) {
        try { $null = Invoke-Helper '/stop' @{ sessionId = $sessionId } } catch { $errors.Add('Core cleanup: ' + $_.Exception.Message) }
    }
    if ($installed) {
        try {
            & $helperPath uninstall 2>&1 | Out-File (Join-Path $OutputDirectory 'helper-uninstall.log')
            if ($LASTEXITCODE -ne 0) { throw ('Helper uninstall failed: ' + $LASTEXITCODE) }
            if (Get-Service FlClashHelperService -ErrorAction SilentlyContinue) { throw 'Helper SCM registration remains after uninstall.' }
            if ([Dns2NativeCheck]::QueryGuardSubLayer() -ne $sublayerNotFound) { throw 'Guard WFP sublayer remains after cleanup.' }
            $result.helper_cleanup = 'passed'
        } catch { $errors.Add('Helper cleanup: ' + $_.Exception.Message) }
    }
}

$app = $null
$children = @()
try {
    if (-not $environmentClean -or (Get-Service FlClashHelperService -ErrorAction SilentlyContinue)) { throw 'Refusing GUI startup in an unclean test environment.' }
    $app = Start-Process -FilePath $apps[0].FullName -WorkingDirectory $bundle -PassThru -RedirectStandardOutput (Join-Path $OutputDirectory 'app-stdout.log') -RedirectStandardError (Join-Path $OutputDirectory 'app-stderr.log')
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 500
        $app.Refresh()
        if ($app.HasExited) { throw ('FlClash exited during startup, code ' + $app.ExitCode) }
        if ($app.MainWindowHandle -ne [IntPtr]::Zero) { break }
    }
    $children = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $app.Id) | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($bundle, [StringComparison]::OrdinalIgnoreCase) })
    $result.gui_process_startup = 'passed'
    $result.gui_window_created = $app.MainWindowHandle -ne [IntPtr]::Zero
    $result.gui_pid = $app.Id
    $result.windows_session_id = $app.SessionId
    $result.user_interactive = [Environment]::UserInteractive
} catch {
    $errors.Add('GUI startup: ' + $_.Exception.Message)
} finally {
    if ($app -and -not $app.HasExited) {
        $null = $app.CloseMainWindow()
        if (-not $app.WaitForExit(3000)) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue }
    }
    foreach ($child in $children) {
        $running = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
        if ($running -and $running.Path -eq $child.ExecutablePath) { Stop-Process -Id $child.ProcessId -Force }
    }
}
$result.errors = $errors.ToArray()
$result.finished_utc = [DateTime]::UtcNow.ToString('o')
$result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'windows-runtime-result.json')
if ($errors.Count -gt 0) { throw ($errors -join '; ') }
