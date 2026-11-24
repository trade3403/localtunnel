param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [Parameter(Mandatory=$true)][string]$Evidence
)
$ErrorActionPreference = "Stop"
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$installDir = Join-Path $env:RUNNER_TEMP ("localtunnel-install-" + [guid]::NewGuid().ToString("N"))
$report = [ordered]@{ installed = $false; window_started = $false; uninstalled = $false; scope = "isolated installer smoke, not GUI interaction or public tunnel E2E" }
$app = $null
try {
    $setup = Start-Process -FilePath $installerPath -ArgumentList "/S /D=$installDir" -PassThru
    if (!$setup.WaitForExit(120000)) { $setup.Kill(); throw "Installer timed out" }
    if ($setup.ExitCode -ne 0) { throw "Installer failed: $($setup.ExitCode)" }
    $exe = Join-Path $installDir "localtunnel-desktop.exe"
    if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Installed application not found" }
    $report.installed = $true
    $app = Start-Process -FilePath $exe -PassThru
    $deadline = (Get-Date).AddSeconds(40)
    do {
        Start-Sleep -Milliseconds 500
        $app.Refresh()
        if ($app.HasExited) { throw "Desktop exited before showing a window: $($app.ExitCode)" }
        if ($app.MainWindowHandle -ne [IntPtr]::Zero) { $report.window_started = $true; break }
    } while ((Get-Date) -lt $deadline)
    if (!$report.window_started) { throw "No native application window detected" }
    # No engine is started in this test; normal tray exit is a separate GUI test.
    Stop-Process -Id $app.Id -Force
    if (!$app.WaitForExit(10000)) { throw "Application did not exit" }
    $uninstaller = Join-Path $installDir "uninstall.exe"
    if (!(Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw "Uninstaller missing" }
    $remove = Start-Process -FilePath $uninstaller -ArgumentList "/S" -PassThru
    if (!$remove.WaitForExit(120000)) { $remove.Kill(); throw "Uninstaller timed out" }
    if ($remove.ExitCode -ne 0) { throw "Uninstaller failed: $($remove.ExitCode)" }
    # NSIS normally copies its uninstaller to TEMP and starts a child. The
    # original process may return before the child removes installed files.
    # Preserve the removal gate: wait for evidence, never delete the app ourselves.
    $report.uninstaller_launcher_exit_code = $remove.ExitCode
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ((Test-Path -LiteralPath $exe) -and $watch.Elapsed.TotalSeconds -lt 60) {
        Start-Sleep -Milliseconds 250
    }
    $report.removal_wait_ms = $watch.ElapsedMilliseconds
    if (Test-Path -LiteralPath $exe) { throw "Application remains after uninstall (60-second completion window)" }
    $report.uninstalled = $true
} finally {
    if ($app -and !$app.HasExited) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue }
    $report | ConvertTo-Json | Set-Content -LiteralPath $Evidence -Encoding utf8
}
