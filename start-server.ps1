# ============================================================================
# 1-Click Server Launcher: Runs Entirely on M: Drive with Zero C: Drive Writes
# ============================================================================

$root = $PSScriptRoot

# Load M: drive isolation
. "$root\env-m-drive.ps1"

Write-Host "Starting Banking ATM Middleware on M: drive..." -ForegroundColor Cyan
Set-Location "$root\backend-go"

# Run the pre-compiled native binary (runs in RAM, zero disk temp files)
.\atm-auth.exe
