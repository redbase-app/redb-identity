# Logout + RP-initiated end_session (OIDC Session Management + RFC 7009).
#   1. ROPC → access + id + refresh tokens.
#   2. Revoke refresh_token via /connect/revocation (RFC 7009).
#   3. POST /connect/logout (RP-initiated, id_token_hint).
#   4. GET  /connect/endsession (OIDC headless probe).
#   5. Verify revoked refresh_token no longer issues tokens.
#   6. Verify revoked access_token rejected at /connect/userinfo (if introspection active).
# Usage: pwsh -File demo_logout_endsession.ps1

$BASE    = "http://127.0.0.1:5002"
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

# 1) DCR — password + refresh_token + post_logout_redirect_uris.
$reg = Measure-Step "1. DCR /connect/register (password + post_logout_redirect_uris)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name               = "logout-demo"
        redirect_uris             = @("http://localhost:9999/cb")
        grant_types               = @("password","refresh_token")
        scope                     = "openid profile email offline_access identity:account"
        post_logout_redirect_uris = @("http://localhost:9999/post-logout")
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Seed user.
$user = "lgout_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
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

# 3) ROPC → access + id + refresh tokens.
$tok = Measure-Step "3. ROPC → access + id_token + refresh_token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email offline_access identity:account"
      }
}
$bearer = @{ Authorization = "Bearer $($tok.access_token)" }
Write-Host "  access_token  : $($tok.access_token.Substring(0,32))…"
if ($tok.id_token) {
    Write-Host "  id_token      : $($tok.id_token.Substring(0,32))…"
} else {
    Write-Host "  id_token      : (not issued — openid scope may not have been granted)" -ForegroundColor Yellow
}
Write-Host "  refresh_token : $($tok.refresh_token.Substring(0,32))…"

# 4) Sanity: userinfo works before any logout.
Measure-Step "4. GET /connect/userinfo (before logout — expect 200)" {
    Invoke-RestMethod -Method Get "$BASE/connect/userinfo" -Headers $bearer
} | ConvertTo-Json -Depth 3 | Out-Host

# 5) Revoke refresh_token via /connect/revocation (RFC 7009).
Measure-Step "5. POST /connect/revocation (refresh_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/revocation" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token             = $tok.refresh_token
        token_type_hint   = "refresh_token"
        client_id         = $reg.client_id
        client_secret     = $reg.client_secret
      }
    Write-Host "  ✓ RFC 7009 returns 200 even if token was already invalid" -ForegroundColor Green
} | Out-Null

# 6) Verify revoked refresh_token no longer issues tokens.
Measure-Step "6. refresh_token after revoke (expect 400/401)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "refresh_token"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            refresh_token = $tok.refresh_token
          } | Out-Null
        Write-Host "  ! revoked refresh_token still issued tokens" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 400,401) {
            Write-Host "  ✓ rejected: $code" -ForegroundColor Green
        } else {
            Write-Host "  unexpected status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 7) POST /connect/logout — RP-initiated with id_token_hint (OIDC Session §5).
Measure-Step "7. POST /connect/logout (id_token_hint)" {
    if (-not $tok.id_token) {
        Write-Host "  (skipped — no id_token was issued)" -ForegroundColor DarkGray
        return
    }
    try {
        $wr = Invoke-WebRequest -Method Post "$BASE/connect/logout" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            id_token_hint            = $tok.id_token
            client_id                = $reg.client_id
            post_logout_redirect_uri = "http://localhost:9999/post-logout"
            state                    = "s_$(Get-Random)"
          } `
          -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $code = $wr.StatusCode
        if ($code -in 200,204,302,303) {
            Write-Host "  ✓ logout accepted: $code" -ForegroundColor Green
        } else {
            Write-Host "  ! unexpected: $code" -ForegroundColor Yellow
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 200,204,302,303) {
            Write-Host "  ✓ logout: $code" -ForegroundColor Green
        } else {
            Write-Host "  status: $code — $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 8) GET /connect/endsession?id_token_hint=… (OIDC RP-initiated, headless).
Measure-Step "8. GET /connect/endsession?id_token_hint=…" {
    if (-not $tok.id_token) {
        Write-Host "  (skipped — no id_token)" -ForegroundColor DarkGray
        return
    }
    $esUrl = "$BASE/connect/endsession?id_token_hint=$([Uri]::EscapeDataString($tok.id_token))&post_logout_redirect_uri=$([Uri]::EscapeDataString('http://localhost:9999/post-logout'))&state=es_$(Get-Random)"
    try {
        $wr   = Invoke-WebRequest -Uri $esUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $code = $wr.StatusCode
        $loc  = $wr.Headers['Location']
        if ($code -in 200,302,303) {
            Write-Host "  ✓ endsession: $code" -ForegroundColor Green
            if ($loc) { Write-Host "  Location: $($loc.ToString().Substring(0,[Math]::Min(100,$loc.ToString().Length)))…" }
        } else {
            Write-Host "  ! unexpected: $code" -ForegroundColor Yellow
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 200,302,303) {
            Write-Host "  ✓ endsession: $code" -ForegroundColor Green
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 9) Also revoke the access_token explicitly.
Measure-Step "9. POST /connect/revocation (access_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/revocation" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        token           = $tok.access_token
        token_type_hint = "access_token"
        client_id       = $reg.client_id
        client_secret   = $reg.client_secret
      }
    Write-Host "  ✓ access_token revoke accepted" -ForegroundColor Green
} | Out-Null

# 10) /connect/userinfo after access_token revoke — self-contained JWTs survive until exp;
#     reference tokens or introspection-validated routes should return 401.
Measure-Step "10. GET /connect/userinfo after access_token revoke" {
    try {
        $ui = Invoke-RestMethod -Method Get "$BASE/connect/userinfo" -Headers $bearer
        Write-Host "  userinfo still accessible (self-contained JWT — lives until exp)" -ForegroundColor Yellow
        Write-Host "  sub: $($ui.sub)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 401) {
            Write-Host "  ✓ 401 — server rejects revoked access_token" -ForegroundColor Green
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
