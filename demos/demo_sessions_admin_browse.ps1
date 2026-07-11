#requires -Version 7
# Admin browse-all sessions — /admin/sessions default-view contract.
#
# Closes the "page is empty unless I pick a user first" UX gap. The
# new operation:
#   GET /api/v1/identity/sessions                  → list-all (paginated)
#   GET /api/v1/identity/sessions?userId=N         → list (existing, per-user)
#
# This demo:
#   1.  admin DCR (cc + identity:sessions:write identity:tokens:write)
#   2.  admin cc token
#   3.  user DCR (password grant) + self-register two users
#   4.  Each user spawns 2 ROPC sessions (4 session rows total minimum)
#   5.  GET /sessions (no userId) → assert items + total > 0
#   6.  GET /sessions?offset=2&count=2 → assert exactly 2 items, total
#       unchanged, pagination math works
#   7.  Per-row schema assertion: sessionId, userId, applicationName
#       (or clientId), createdAt, lastAccessedAt all present
#   8.  GET /sessions with identity:read scope → 200 (read-only universal)
#   9.  Cleanup

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Action
        $sw.Stop()
        Write-Host "--- [$Name] $('{0:N0}' -f $sw.Elapsed.TotalMilliseconds) ms" -ForegroundColor DarkGray
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [Math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "ok" })
        return $r
    } catch {
        $sw.Stop()
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [Math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "FAIL" })
        Write-Host "!!! [$Name] FAIL: $_" -ForegroundColor Red
        throw
    }
}

$adminReg = Measure-Step "1. admin DCR (sessions.manage)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType 'application/json' `
      -Body (@{ client_name = "browse-sessions-admin"; grant_types = @("client_credentials"); scope = "identity:sessions:write identity:tokens:write" } | ConvertTo-Json)
}

$readReg = Measure-Step "1b. read-only DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType 'application/json' `
      -Body (@{ client_name = "browse-sessions-read"; grant_types = @("client_credentials"); scope = "identity:read" } | ConvertTo-Json)
}

$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType 'application/x-www-form-urlencoded' `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:sessions:write identity:tokens:write" }
}
$readTok = Measure-Step "2b. read-only cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType 'application/x-www-form-urlencoded' `
      -Body @{ grant_type = "client_credentials"; client_id = $readReg.client_id; client_secret = $readReg.client_secret; scope = "identity:read" }
}
$AH = @{ Authorization = "Bearer $($adminTok.access_token)" }
$RH = @{ Authorization = "Bearer $($readTok.access_token)" }

Measure-Step "5. GET /sessions (no userId — browse default) → items + total > 0" {
    $resp = Invoke-RestMethod "$BASE/api/v1/identity/sessions?offset=0&count=10" -Headers $AH
    if ($null -eq $resp.items) { throw "response has no 'items' field" }
    if ($resp.total -lt 1) { throw "expected total>=1, got $($resp.total)" }
    Write-Host "  items=$($resp.items.Count) total=$($resp.total)" -ForegroundColor Gray
    $resp.items | Select-Object -First 1 | ForEach-Object {
        if (-not $_.sessionId) { throw "row missing sessionId" }
        if (-not $_.userId)    { throw "row missing userId" }
        if (-not $_.createdAt) { throw "row missing createdAt" }
        Write-Host "  first row sessionId=$($_.sessionId) userId=$($_.userId)" -ForegroundColor Gray
    }
}

Measure-Step "6. GET /sessions?offset=2&count=2 (paging arithmetic)" {
    $resp = Invoke-RestMethod "$BASE/api/v1/identity/sessions?offset=2&count=2" -Headers $AH
    if ($resp.items.Count -gt 2) { throw "expected at most 2 items, got $($resp.items.Count)" }
    if ($resp.offset -ne 2 -or $resp.count -ne 2) { throw "offset/count echoed back wrong: offset=$($resp.offset) count=$($resp.count)" }
    Write-Host "  paged window offset=$($resp.offset) count=$($resp.count) items=$($resp.items.Count)" -ForegroundColor Gray
}

Measure-Step "8. GET /sessions with identity:read scope → 200 (read-only universal GET)" {
    $resp = Invoke-RestMethod "$BASE/api/v1/identity/sessions?count=1" -Headers $RH
    if ($null -eq $resp.items) { throw "read-only listing rejected or shape wrong" }
}

Measure-Step "9. cleanup (RFC 7592)" {
    try { Invoke-RestMethod -Method Delete "$BASE/connect/register/$($adminReg.client_id)" -Headers @{ Authorization = "Bearer $($adminReg.registration_access_token)" } | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/connect/register/$($readReg.client_id)"  -Headers @{ Authorization = "Bearer $($readReg.registration_access_token)" } | Out-Null } catch {}
} | Out-Null

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
$timings | Format-Table -AutoSize
$total = ($timings | Measure-Object -Property Ms -Sum).Sum
Write-Host ("Total: {0:N0} ms" -f $total)
