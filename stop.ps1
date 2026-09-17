$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ProjectRoot ".runtime\server.pid"
$ExpectedServerPath = (Join-Path $ProjectRoot "server.py")

if (-not (Test-Path -LiteralPath $PidFile)) {
    Write-Host "Port Console is not running."
    exit 0
}

$ServerPid = [int](Get-Content -LiteralPath $PidFile -Raw)
$process = Get-CimInstance Win32_Process -Filter "ProcessId = $ServerPid" -ErrorAction SilentlyContinue
if (-not $process) {
    Remove-Item -LiteralPath $PidFile -Force
    Write-Host "The process no longer exists. The stale PID file was removed."
    exit 0
}

if ([string]$process.CommandLine -notlike "*$ExpectedServerPath*") {
    throw "PID $ServerPid does not belong to this Port Console server.py. Stop was refused."
}

Stop-Process -Id $ServerPid -Force
Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "Port Console stopped."
