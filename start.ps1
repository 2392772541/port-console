$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPath = Join-Path $ProjectRoot "server.py"
$Url = "http://127.0.0.1:8787"
$HealthUrl = "$Url/api/health"

try {
    $health = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
    if ($health.ok) {
        Write-Host "Port Console is already running: $Url"
        Start-Process $Url
        exit 0
    }
} catch {
    # The service is not running yet.
}

$occupied = Get-NetTCPConnection -State Listen -LocalPort 8787 -ErrorAction SilentlyContinue
if ($occupied) {
    throw "Port 8787 is already occupied. PID: $($occupied.OwningProcess -join ', ')"
}

$Python = Get-Command python -ErrorAction Stop
$env:PORT_CONSOLE_HOST = "127.0.0.1"
$env:PORT_CONSOLE_PORT = "8787"

$process = Start-Process `
    -FilePath $Python.Source `
    -ArgumentList @($ServerPath) `
    -WorkingDirectory $ProjectRoot `
    -WindowStyle Hidden `
    -PassThru

$deadline = (Get-Date).AddSeconds(15)
do {
    Start-Sleep -Milliseconds 300
    if ($process.HasExited) {
        throw "Port Console exited early. Exit code: $($process.ExitCode)"
    }
    try {
        $health = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 1
        if ($health.ok) {
            Write-Host "Port Console started: $Url"
            Start-Process $Url
            exit 0
        }
    } catch {
        # Keep waiting for the health endpoint.
    }
} while ((Get-Date) -lt $deadline)

throw "Port Console startup timed out. Check $ProjectRoot\logs\actions.log"
