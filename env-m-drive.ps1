# ============================================================================
# Environment Isolation Script: Force All Temp Files & Caches to M: Drive
# ============================================================================

$root = $PSScriptRoot

# 1. Create dedicated folders on M: drive
$tmpDir = Join-Path $root ".tmp"
$cacheDir = Join-Path $root ".cache"

New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $cacheDir "go-build") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $cacheDir "go") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $cacheDir "npm") -Force | Out-Null

# 2. Redirect Windows Temp to M: drive
$env:TEMP = $tmpDir
$env:TMP = $tmpDir

# 3. Redirect Go build cache & modules to M: drive
$env:GOCACHE = Join-Path $cacheDir "go-build"
$env:GOPATH = Join-Path $cacheDir "go"

# 4. Redirect NPM cache to M: drive
$env:npm_config_cache = Join-Path $cacheDir "npm"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  M: Drive Environment Active (Zero C: Drive Writes)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TEMP / TMP     -> $env:TEMP" -ForegroundColor Yellow
Write-Host "  Go Build Cache -> $env:GOCACHE" -ForegroundColor Yellow
Write-Host "  Go Path        -> $env:GOPATH" -ForegroundColor Yellow
Write-Host "  NPM Cache      -> $env:npm_config_cache" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
