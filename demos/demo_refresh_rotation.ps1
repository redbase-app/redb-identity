# Refresh-token rotation + replay detection (RFC 6749 §6, OAuth 2.0 BCP — Security Topics §4.12).
#   ROPC → access1+refresh1 → exchange refresh1 → access2+refresh2 → reuse refresh1 (must fail).
# Usage: pwsh -File demo_refresh_rotation.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — request offline_access so refresh_token is issued.
$reg = Measure-Step "1. DCR /connect/register (password + refresh_token + offline_access)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "refresh-demo"
        redirect_uris = @($REDIRECT_CB)
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "rfr_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd = "Test1234Pass!"
Measure-Step "2. account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = "$user@example.com"
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json)
} | Out-Null

# 3) Initial password grant.
$tok1 = Measure-Step "3. password grant → access1 + refresh1" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email offline_access"
      }
}
if (-not $tok1.refresh_token) { throw "no refresh_token (offline_access scope was rejected?)" }
Write-Host "  access1  : $($tok1.access_token.Substring(0,24))…"
Write-Host "  refresh1 : $($tok1.refresh_token.Substring(0,24))…"

Start-Sleep -Milliseconds 1100  # ensure new access_token has a different `iat`

# 4) Exchange refresh1 → access2+refresh2 (rotation).
$tok2 = Measure-Step "4. refresh_token grant → access2 + refresh2 (rotation)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "refresh_token"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        refresh_token = $tok1.refresh_token
        scope         = "openid profile email offline_access"
      }
}
Write-Host "  access2  : $($tok2.access_token.Substring(0,24))…"
Write-Host "  refresh2 : $($tok2.refresh_token.Substring(0,24))…"

if ($tok2.access_token -eq $tok1.access_token) {
    Write-Host "  ! access_token did NOT change — server may not be rotating" -ForegroundColor Red
} else {
    Write-Host "  ✓ access_token rotated" -ForegroundColor Green
}
if ($tok2.refresh_token -ne $null -and $tok2.refresh_token -ne $tok1.refresh_token) {
    Write-Host "  ✓ refresh_token rotated (new value issued)" -ForegroundColor Green
} elseif ($tok2.refresh_token -eq $tok1.refresh_token) {
    Write-Host "  ! refresh_token NOT rotated (server keeps the old one)" -ForegroundColor Yellow
}

# 5) Use access2.
Measure-Step "5. /userinfo with access2" {
    Invoke-RestMethod -Method Get "$BASE/connect/userinfo" `
      -Headers @{ Authorization = "Bearer $($tok2.access_token)" }
} | ConvertTo-Json -Depth 4 | Out-Host

# 6) REPLAY: try refresh1 again → MUST be rejected (RFC token-rotation: replayed refresh
#    invalidates the entire family — both refresh1 AND refresh2 should now be dead).
Measure-Step "6. REPLAY refresh1 (expect invalid_grant)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "refresh_token"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            refresh_token = $tok1.refresh_token
          } | Out-Null
        throw "REPLAY ACCEPTED — server is vulnerable to refresh-token reuse!"
    } catch {
        $code = $null; $body = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        try {
            $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $sr.ReadToEnd()
        } catch {}
        if ($code -in 400, 401) {
            Write-Host "  ✓ replay rejected: status=$code body=$body" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

# 7) After-replay: refresh2 should ALSO be dead (rotation family invalidated).
Measure-Step "7. refresh2 after replay (expect invalid_grant — family revoked)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "refresh_token"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            refresh_token = $tok2.refresh_token
          } | Out-Null
        Write-Host "  ! refresh2 still works — family-revocation NOT enforced" -ForegroundColor Yellow
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  ✓ refresh2 rejected: status=$code (family revoked)" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
