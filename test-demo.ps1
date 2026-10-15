$ErrorActionPreference = "Stop"
$base = "http://localhost:4000"

Write-Host ""
Write-Host "=== 1. Creating session ===" -ForegroundColor Cyan
$s = Invoke-RestMethod -Uri "$base/api/session" -Method POST -ContentType "application/json" -Body "{}"
Write-Host "  sessionId : $($s.sessionId)"
Write-Host "  atmId     : $($s.atmId)"
Write-Host "  ttl       : $($s.ttlSeconds)s"

Write-Host ""
Write-Host "=== 2. Approving session (simulating phone scan) ===" -ForegroundColor Cyan
$body = @{ qrToken = $s.qrToken; deviceId = "phone-1"; customerRef = "Ali Hassan" } | ConvertTo-Json
$r = Invoke-RestMethod -Uri "$base/api/session/approve" -Method POST -ContentType "application/json" -Body $body
Write-Host "  status   : $($r.session.status)"
Write-Host "  customer : $($r.session.approvedByCustomerRef)"

Write-Host ""
Write-Host "=== 3. Audit log ===" -ForegroundColor Cyan
$audit = Invoke-RestMethod -Uri "$base/api/audit"
foreach ($e in $audit) {
    $t = [DateTimeOffset]::FromUnixTimeMilliseconds($e.ts).ToString("HH:mm:ss")
    Write-Host "  $t  $($e.event)  sid=$($e.sessionId.Substring(0,8))"
}

Write-Host ""
Write-Host "Done. Check your ATM browser tab at $base" -ForegroundColor Green
Write-Host ""
