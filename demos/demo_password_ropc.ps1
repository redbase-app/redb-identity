# Resource Owner Password Credentials grant (RFC 6749 §4.3) — opt-in via EnablePasswordFlow.
#   Bypasses the browser; useful for first-party apps and CLI tools. Surfaces ROPC_TIMING
#   in the server logs (auth=BCrypt verify, principal=BuildPrincipal, total).
# Usage: pwsh -File demo_password_ropc.ps1

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

# 1) DCR — ask for password + refresh_token grants.
$reg = Measure-Step "1. DCR /connect/register (password + refresh_token)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "ropc-demo"
        redirect_uris = @($REDIRECT_CB)
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}
$reg | Format-List client_id, client_secret

# 2) Seed user.
$user = "ropc_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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

# 3) Happy path — grant_type=password.
$tok = Measure-Step "3. ROPC happy path (grant=password)" {
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
$tok | Format-List access_token, refresh_token, token_type, expires_in, scope
if (-not $tok.access_token) { throw "no access_token returned" }
Write-Host "  access_token  : $($tok.access_token.Substring(0,32))…"
Write-Host "  refresh_token : $($tok.refresh_token.Substring(0,32))…"

# 4) Timing-equivalence: wrong password → invalid_grant. Should take ~same time as (3)
#    (SEC-A20: server runs a fake BCrypt.Verify on miss to defeat user enumeration).
Measure-Step "4. ROPC wrong password (expect access_denied; constant-time)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = "Bogus-$([Guid]::NewGuid())"
            scope         = "openid profile email"
          } | Out-Null
        throw "expected 4xx but request succeeded"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  rejected as expected: $code" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

# 5) Timing-equivalence: unknown user → also access_denied, ~same time
#    (no shortcut on user-miss — same fake BCrypt path).
Measure-Step "5. ROPC unknown user (expect access_denied; constant-time)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = "ghost_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
            password      = $pwd
            scope         = "openid profile email"
          } | Out-Null
        throw "expected 4xx but request succeeded"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  rejected as expected: $code" -ForegroundColor Green
        } else { throw }
    }
} | Out-Null

# 6) Use the access_token against /connect/userinfo.
Measure-Step "6. GET /connect/userinfo (Bearer)" {
    $h = @{ Authorization = "Bearer $($tok.access_token)" }
    Invoke-RestMethod -Method Get "$BASE/connect/userinfo" -Headers $h
} | ConvertTo-Json -Depth 5 | Out-Host

# 7) Run the happy path 5× to measure steady-state timing (for fast-path evidence).
Write-Host ""
Write-Host "=== [7. ROPC steady-state x5] ===" -ForegroundColor Cyan
$ms = @()
for ($i = 1; $i -le 5; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email"
      } | Out-Null
    $sw.Stop()
    $ms += [int]$sw.Elapsed.TotalMilliseconds
    Write-Host ("  iter {0}: {1,5} ms" -f $i, $ms[-1])
}
$avg = [int](($ms | Measure-Object -Average).Average)
$min = ($ms | Measure-Object -Minimum).Minimum
$max = ($ms | Measure-Object -Maximum).Maximum
Write-Host ("  avg={0} ms  min={1} ms  max={2} ms" -f $avg, $min, $max) -ForegroundColor Yellow
$timings.Add([pscustomobject]@{ Step="7. ROPC steady-state x5 (avg)"; Ms=$avg; Status="ok" })

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
Write-Host "(check Worker log for ROPC_TIMING auth=… principal=… total=… username=… fastPath=…)" -ForegroundColor DarkGray
