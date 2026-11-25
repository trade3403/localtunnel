param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$Evidence
)
$ErrorActionPreference = "Stop"
$source = (Resolve-Path -LiteralPath $Executable).Path
$name = "LocalTunnelPreview-" + [guid]::NewGuid().ToString("N")
$dir = Join-Path $env:ProgramData $name
$exe = Join-Path $dir "localtunnel-desktop.exe"
$report = [ordered]@{ scope = "SCM lifecycle only; no tunnel or credential provisioning"; registered = $false; started = $false; stopped = $false; deleted = $false; account = "NT AUTHORITY\LocalService" }
$created = $false
function Invoke-Sc {
    param([string[]]$Arguments)
    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failed with exit $LASTEXITCODE" }
}
function Wait-ServiceState {
    param([string]$Expected)
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $service = Get-Service -Name $name
        if ($service.Status.ToString() -eq $Expected) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Service did not reach $Expected"
}
try {
    New-Item -ItemType Directory -Path $dir | Out-Null
    Copy-Item -LiteralPath $source -Destination $exe
    # Explicitly grant LocalService read/execute only. The test is isolated from
    # the normal per-user install and does not configure autostart.
    & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Service test directory ACL setup failed" }
    # New-Service's default account is LocalSystem, so use SCM directly with
    # explicit LocalService. Quoted executable, fixed mode, random service name.
    $binary = '"' + $exe + '" --service-host ' + $name
    Invoke-Sc -Arguments @('create', $name, 'binPath=', $binary, 'start=', 'demand', 'obj=', 'NT AUTHORITY\LocalService')
    $created = $true
    $report.registered = $true
    $record = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (!$record -or $record.StartMode -ne 'Manual' -or $record.StartName -notmatch '^(NT AUTHORITY\\)?LocalService$') { throw "Unexpected service identity/startup" }
    Invoke-Sc -Arguments @('start', $name)
    Wait-ServiceState -Expected Running
    $running = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (!$running -or $running.ProcessId -eq 0) { throw "No live service process" }
    $report.started = $true
    $report.process_id = $running.ProcessId
    Invoke-Sc -Arguments @('stop', $name)
    Wait-ServiceState -Expected Stopped
    $report.stopped = $true
    # Release handles before deletion; the SCM can defer deletion until close.
    $record = $null
    $running = $null
    Invoke-Sc -Arguments @('delete', $name)
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service -Name $name -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "Service remains after delete" }
    $created = $false
    $report.deleted = $true
} finally {
    if ($created) {
        & "$env:SystemRoot\System32\sc.exe" stop $name 2>$null | Out-Null
        & "$env:SystemRoot\System32\sc.exe" delete $name 2>$null | Out-Null
    }
    $report | ConvertTo-Json | Set-Content -LiteralPath $Evidence -Encoding utf8
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop }
}
