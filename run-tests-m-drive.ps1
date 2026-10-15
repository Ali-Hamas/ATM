# ============================================================================
# 1-Click Automated Test Runner: Isolated on M: Drive (Zero C: Drive Writes)
# ============================================================================

$root = $PSScriptRoot

# Load M: drive isolation
. "$root\env-m-drive.ps1"

Write-Host "Running Go Automated Security & Pen-Test Suite on M: drive..." -ForegroundColor Cyan
Set-Location "$root\backend-go"

# Run tests using the M: drive GOCACHE and TEMP
go test ./... -v
