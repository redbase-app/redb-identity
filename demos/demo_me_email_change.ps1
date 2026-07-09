# /me change-email cycle (request → confirm with wrong token → verify rejection).
#   Full cycle requires intercepting the email; this demo probes the endpoint
#   contracts without a real SMTP inbox:
#   1. Request email change → expect 200 + email sent.
#   2. Confirm with bogus token → expect 400.
#   3. Confirm for wrong email → expect 400 (no user enumeration).
#   4. Confirm after email already taken by another user → expect 409.
# Usage: pwsh -File demo_me_email_change.ps1

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

# 1) DCR + seed primary user.
$reg = Measure-Step "1. DCR /connect/register (password + identity:account)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "email-change-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access identity:account"
      } | ConvertTo-Json)
}

$user  = "echg_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd   = "Test1234Pass!"
$email = "$user@example.com"

Measure-Step "2. account/register (primary user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = $email
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json)
} | Out-Null

# 3) Seed a second user whose email we'll try to steal.
$user2  = "echg2_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$email2 = "$user2@example.com"
Measure-Step "3. account/register (second user — owns $email2)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user2
        email       = $email2
        password    = $pwd
        displayName = $user2
      } | ConvertTo-Json)
} | Out-Null

# 4) Login as primary user → access_token with identity:account scope.
$tok = Measure-Step "4. ROPC → access_token (identity:account)" {
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
Write-Host "  access_token: $($tok.access_token.Substring(0,32))…"

# 5) Request change to a fresh email address.
$newEmail = "new_$([Guid]::NewGuid().ToString('N').Substring(0,8))@example.com"
Measure-Step "5. POST /me/change-email/request (newEmail=$newEmail)" {
    try {
        $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/change-email/request" `
          -Headers $bearer `
          -ContentType "application/json" `
          -Body (@{ newEmail = $newEmail } | ConvertTo-Json)
        Write-Host "  ✓ accepted" -ForegroundColor Green
        $r | ConvertTo-Json | Out-Host
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
        Write-Host "  status: $code  body: $body" -ForegroundColor Yellow
    }
} | Out-Null

# 6) Confirm with bogus token → expect 400.
$bogusToken = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
Measure-Step "6. POST /me/change-email/confirm with bogus token (expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/change-email/confirm" `
          -Headers $bearer `
          -ContentType "application/json" `
          -Body (@{ newEmail = $newEmail; token = $bogusToken } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED success — bogus token accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
        if ($code -eq 400) {
            Write-Host "  ✓ rejected: 400" -ForegroundColor Green
            if ($body) { Write-Host "  body: $body" }
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 7) Try to change email to an address already owned by another user → expect 409/400.
Measure-Step "7. POST /me/change-email/request to already-taken email (expect 400/409)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/change-email/request" `
          -Headers $bearer `
          -ContentType "application/json" `
          -Body (@{ newEmail = $email2 } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED — email already owned by another user was accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
        if ($code -in 400,409,422) {
            Write-Host "  ✓ rejected: $code  (email conflict)" -ForegroundColor Green
            if ($body) { Write-Host "  body: $body" }
        } else {
            Write-Host "  status: $code  body: $body" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 8) Same request — attempt confirm with mismatched email (token/email mismatch).
Measure-Step "8. POST /me/change-email/confirm with email mismatch (expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/change-email/confirm" `
          -Headers $bearer `
          -ContentType "application/json" `
          -Body (@{
            newEmail = "wrong_$(Get-Random)@example.com"
            token    = $bogusToken
          } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED success" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 400) {
            Write-Host "  ✓ rejected: 400" -ForegroundColor Green
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 9) Unauthenticated request → expect 401.
Measure-Step "9. POST /me/change-email/request without token (expect 401)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/me/change-email/request" `
          -ContentType "application/json" `
          -Body (@{ newEmail = $newEmail } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED — unauthenticated request accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 401,403) {
            Write-Host "  ✓ rejected: $code" -ForegroundColor Green
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
Write-Host "(to complete full email change: grab the confirm token from server logs and run step 5 manually)" -ForegroundColor DarkGray
