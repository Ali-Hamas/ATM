# ============================================================================
# Bank mTLS Certificate Authority & Key Generation Utility
# Target: Windows PowerShell / Local Staging & Pen-Test Verification
# ============================================================================

$targetDir = "$PSScriptRoot\certs"
if (!(Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Bank Mutual TLS (mTLS) Certificate Generator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check for OpenSSL (system PATH or Git distribution)
$opensslPath = "openssl"
if (!(Get-Command openssl -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
        $opensslPath = "C:\Program Files\Git\usr\bin\openssl.exe"
    } else {
        Write-Warning "OpenSSL command not found. Please install OpenSSL or Git."
        exit 0
    }
}

Push-Location $targetDir

try {
    # 1. Generate Bank Private Root CA
    Write-Host "[1/4] Generating Private Bank Root CA (4096-bit RSA)..." -ForegroundColor Yellow
    & $opensslPath genrsa -out bank_ca.key 4096 2>$null
    & $opensslPath req -x509 -new -nodes -key bank_ca.key -sha256 -days 1825 `
        -subj "/C=GB/O=DemoBank International/OU=Security Operations/CN=DemoBank-Root-CA" `
        -out bank_ca.crt 2>$null

    # 2. Generate Server Certificate (Nginx Reverse Proxy)
    Write-Host "[2/4] Generating Nginx Gateway Server Certificate..." -ForegroundColor Yellow
    & $opensslPath genrsa -out server.key 2048 2>$null
    & $opensslPath req -new -key server.key `
        -subj "/C=GB/O=DemoBank International/OU=ATM Switch/CN=atm.internal.bank.net" `
        -out server.csr 2>$null

    # Server SAN config
    $sanConfig = @"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = atm.internal.bank.net
DNS.2 = mobile.bank.net
DNS.3 = localhost
IP.1 = 127.0.0.1
"@
    Set-Content -Path "san.cnf" -Value $sanConfig

    & $opensslPath x509 -req -in server.csr -CA bank_ca.crt -CAkey bank_ca.key -CAcreateserial `
        -out server.crt -days 730 -sha256 -extfile san.cnf -extensions v3_req 2>$null
    Remove-Item "san.cnf", "server.csr" -Force -ErrorAction SilentlyContinue

    # 3. Generate Legitimate ATM Hardware Client Certificate
    Write-Host "[3/4] Generating Authorized ATM Hardware Client Certificate..." -ForegroundColor Yellow
    & $opensslPath genrsa -out atm-001.key 2048 2>$null
    & $opensslPath req -new -key atm-001.key `
        -subj "/C=GB/O=DemoBank International/OU=ATM Hardware Fleet/CN=ATM-HARDWARE-LONDON-001" `
        -out atm-001.csr 2>$null
    & $opensslPath x509 -req -in atm-001.csr -CA bank_ca.crt -CAkey bank_ca.key -CAcreateserial `
        -out atm-001.crt -days 365 -sha256 2>$null
    Remove-Item "atm-001.csr" -Force -ErrorAction SilentlyContinue

    # 4. Generate Rogue / Untrusted Certificate (For Pen-Test Demonstration)
    Write-Host "[4/4] Generating Untrusted Rogue Certificate (Pen-Test Control)..." -ForegroundColor Yellow
    & $opensslPath req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt -days 365 `
        -subj "/C=XX/O=Attacker Organization/CN=Rogue-Device" 2>$null

    Write-Host ""
    Write-Host "All certificates generated successfully in ${targetDir}:" -ForegroundColor Green
    Get-ChildItem -File | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
}
finally {
    Pop-Location
}
