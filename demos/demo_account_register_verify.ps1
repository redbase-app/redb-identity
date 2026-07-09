# Account registration + email-verification flow.
#   POST /account/register → try login before verify → request verify resend
#   → attempt confirm with wrong token (expect 400) → attempt confirm with
#   well-formed but bogus token → check error shape.
#
# Note: a real SMTP inbox is NOT required.  The demo probes endpoint contracts,
# timing, and error shapes.  Step 5 (confirm with correct token) is skipped
# because the token is delivered out-of-band via email; a human can run it
# manually using the token logged by the server.
# Usage: pwsh -File demo_account_register_verify.ps1

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

# 1) DCR — password grant for login checks.
$reg = Measure-Step "1. DCR /connect/register (password)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "verify-demo"
        redirect_uris = @("http://localhost:9999/cb")
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) POST /account/register — create a fresh user.
$user = "vrfy_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
$email = "$user@example.com"
$regResp = Measure-Step "2. POST /api/v1/identity/account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = $email
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json)
}
$regResp | ConvertTo-Json -Depth 3 | Out-Host

# 3) Try login before email verification — server may allow (config-dependent) or require verify.
Measure-Step "3. ROPC before email verify (accept 200 OR 400 emailNotVerified)" {
    try {
        $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email"
          }
        Write-Host "  ✓ login allowed before verification (email verify is optional on this server)" -ForegroundColor Green
        Write-Host "  token_type: $($t.token_type)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = $_.ErrorDetails.Message }
        if ($code -in 400,401) {
            Write-Host "  Server requires email verification before login ($code)" -ForegroundColor Yellow
            if ($body) { Write-Host "  error: $body" }
        } else { throw }
    }
} | Out-Null

# 4) POST /account/verify-email/send — request the verification email.
Measure-Step "4. POST /api/v1/identity/account/verify-email/send (resend)" {
    try {
        $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/verify-email/send" `
          -ContentType "application/json" `
          -Body (@{ email = $email } | ConvertTo-Json)
        Write-Host "  ✓ verify email send accepted" -ForegroundColor Green
        $r | ConvertTo-Json | Out-Host
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
        if ($code -eq 200) {
            Write-Host "  ✓ accepted" -ForegroundColor Green
        } elseif ($code -eq 400 -and $body -match "already.verified") {
            Write-Host "  (email already verified — server may auto-verify in dev mode)" -ForegroundColor DarkGray
        } else {
            Write-Host "  status: $code  body: $body" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 5) POST /account/verify-email/confirm with a syntactically-wrong token — expect 400.
Measure-Step "5. POST verify-email/confirm with bogus token (expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/verify-email/confirm" `
          -ContentType "application/json" `
          -Body (@{
            email = $email
            token = "BOGUS-TOKEN-$(Get-Random)"
          } | ConvertTo-Json) | Out-Null
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

# 6) POST /account/verify-email/confirm with a well-formed (Base64) but wrong token — expect 400.
$fakeToken = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
Measure-Step "6. POST verify-email/confirm with wrong-but-well-formed token (expect 400)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/verify-email/confirm" `
          -ContentType "application/json" `
          -Body (@{
            email = $email
            token = $fakeToken
          } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED success — random token accepted" -ForegroundColor Red
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

# 7) POST /account/verify-email/confirm for a non-existent email — expect 400 (no user enumeration).
Measure-Step "7. verify-email/confirm for unknown email (expect 400 — no user enumeration)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/verify-email/confirm" `
          -ContentType "application/json" `
          -Body (@{
            email = "ghost_$(Get-Random)@example.com"
            token = $fakeToken
          } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED success — unknown email accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
        if ($code -eq 400) {
            Write-Host "  ✓ rejected: 400  (error body should not hint user existence)" -ForegroundColor Green
            Write-Host "  body: $body"
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 8) Duplicate register — same login must be rejected.
Measure-Step "8. Duplicate register (same login — expect 400/409)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
          -ContentType "application/json" `
          -Body (@{
            login       = $user
            email       = "other_$email"
            password    = $pwd
            displayName = "$user dup"
          } | ConvertTo-Json) | Out-Null
        Write-Host "  ! UNEXPECTED — duplicate login accepted" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -in 400,409,422) {
            Write-Host "  ✓ duplicate rejected: $code" -ForegroundColor Green
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
Write-Host "(to complete email verify: run the confirm step manually with the token from server logs)" -ForegroundColor DarkGray
