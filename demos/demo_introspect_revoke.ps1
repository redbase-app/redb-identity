# Token introspection (RFC 7662) + revocation (RFC 7009).
#   password grant → introspect (active=true) → revoke → introspect (active=false) → userinfo (rejected).
# Usage: pwsh -File demo_introspect_revoke.ps1

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

# 1) DCR — password grant client.
$reg = Measure-Step "1. DCR /connect/register (password)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "introspect-demo"
        redirect_uris = @($REDIRECT_CB)
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "intro_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "2. account/register" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
          -ContentType "application/json" `
          -Body (@{
            login       = $user
            email       = "$user@example.com"
            password    = "Test1234Pass!"
            displayName = $user
          } | ConvertTo-Json)
    } catch { Write-Host "  (already exists or non-fatal: $($_.Exception.Message))" -ForegroundColor Yellow }
} | Out-Null

# 3) password grant.
$tok = Measure-Step "3. password grant" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = "Test1234Pass!"
        scope         = "openid profile email offline_access"
      }
}
Write-Host "  access_token  : $($tok.access_token.Substring(0,32))…"
Write-Host "  refresh_token : $($tok.refresh_token.Substring(0,32))…"

# 4) Introspect — expect active=true.
$intro1 = Measure-Step "4. POST /connect/introspect (before revoke)" {
    Invoke-RestMethod -Method Post "$BASE/connect/introspect" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token         = $tok.access_token
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
      }
}
Write-Host ("  active = " + $intro1.active) -ForegroundColor (&{ if ($intro1.active) { 'Green' } else { 'Red' } })
$intro1 | ConvertTo-Json -Depth 5 | Out-Host

# 5) /connect/userinfo — should succeed with valid token.
Measure-Step "5. GET /connect/userinfo (before revoke)" {
    $h = @{ Authorization = "Bearer $($tok.access_token)" }
    Invoke-RestMethod -Method Get "$BASE/connect/userinfo" -Headers $h
} | ConvertTo-Json -Depth 5 | Out-Host

# 6) Revoke the access_token.
Measure-Step "6. POST /connect/revocation (access_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/revocation" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token           = $tok.access_token
        token_type_hint = "access_token"
        client_id       = $reg.client_id
        client_secret   = $reg.client_secret
      }
} | Out-Null
Write-Host "  (RFC 7009: revoke returns 200 with empty body on success)" -ForegroundColor DarkGray

# 7) Introspect again — expect either active=false (RFC 7662) or 401 invalid_token
#    (OpenIddict default: rejects revoked/inactive tokens at the introspection
#    handler instead of returning {active:false}). Both outcomes prove the
#    revocation took effect.
$intro2 = Measure-Step "7. POST /connect/introspect (after revoke)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/introspect" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            token         = $tok.access_token
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
          }
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -eq 401) {
            Write-Host "  401 invalid_token — token is no longer valid (revoke proven)" -ForegroundColor Green
            return [pscustomobject]@{ active = $false; revoked = $true }
        }
        throw
    }
}
$activeAfter = $false
if ($null -ne $intro2 -and $intro2.PSObject.Properties.Name -contains 'active') { $activeAfter = [bool]$intro2.active }
Write-Host ("  active = " + $activeAfter) -ForegroundColor (&{ if (-not $activeAfter) { 'Green' } else { 'Red' } })
$intro2 | ConvertTo-Json -Depth 5 | Out-Host

# 8) Userinfo — should now fail (401).
Measure-Step "8. GET /connect/userinfo (after revoke — expect 401)" {
    $h = @{ Authorization = "Bearer $($tok.access_token)" }
    try {
        $r = Invoke-WebRequest -Method Get "$BASE/connect/userinfo" -Headers $h -ErrorAction Stop
        Write-Host ("  UNEXPECTED success status={0}" -f $r.StatusCode) -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 401,403) {
            Write-Host ("  rejected as expected: {0}" -f $code) -ForegroundColor Green
        } else {
            throw "unexpected status $code"
        }
    }
} | Out-Null

# 9) Revoke refresh_token too (so the chain is fully closed).
Measure-Step "9. POST /connect/revocation (refresh_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/revocation" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token           = $tok.refresh_token
        token_type_hint = "refresh_token"
        client_id       = $reg.client_id
        client_secret   = $reg.client_secret
      }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
