# /me profile + change password.
#   GET /me → PUT /me (displayName) → PUT /me/password → re-login with new password.
# Usage: pwsh -File demo_me_profile.ps1

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

$oldPwd = "Test1234Pass!"
$newPwd = "NewPass9876@@"

# 1) DCR — password grant, with identity:account scope so /me endpoints are authorized.
$reg = Measure-Step "1. DCR /connect/register (password + identity:account)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "me-demo"
        redirect_uris = @($REDIRECT_CB)
        grant_types   = @("password","refresh_token")
        scope         = "openid profile email offline_access identity:account"
      } | ConvertTo-Json)
}

# 2) Seed user.
$user = "me_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "2. account/register" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = "$user@example.com"
        password    = $oldPwd
        displayName = "$user (initial)"
      } | ConvertTo-Json)
} | Out-Null

# 3) password grant → access_token.
$tok = Measure-Step "3. password grant (old password)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $oldPwd
        scope         = "openid profile email offline_access identity:account"
      }
}
$bearer = @{ Authorization = "Bearer $($tok.access_token)" }

# 4) GET /me — current profile.
$me1 = Measure-Step "4. GET /api/v1/identity/me" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $bearer
}
$me1 | ConvertTo-Json -Depth 5 | Out-Host

# 5) PUT /me — rename displayName.
$newName = "$user (renamed)"
Measure-Step "5. PUT /api/v1/identity/me (rename)" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me" `
      -Headers $bearer `
      -ContentType "application/json" `
      -Body (@{ displayName = $newName } | ConvertTo-Json)
} | Out-Null

# 6) GET /me — confirm rename.
$me2 = Measure-Step "6. GET /api/v1/identity/me (after rename)" {
    Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $bearer
}
if ($me2.displayName -eq $newName) {
    Write-Host "  ✓ displayName persisted: $($me2.displayName)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: displayName not updated (got: $($me2.displayName))" -ForegroundColor Red
}

# 7) PUT /me/password — change password.
Measure-Step "7. PUT /api/v1/identity/me/password" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me/password" `
      -Headers $bearer `
      -ContentType "application/json" `
      -Body (@{
        oldPassword = $oldPwd
        newPassword = $newPwd
      } | ConvertTo-Json)
} | Out-Null

# 8) password grant with OLD password — must fail.
Measure-Step "8. password grant with OLD password (expect fail)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $oldPwd
            scope         = "openid"
          } -ErrorAction Stop | Out-Null
        Write-Host "  UNEXPECTED success — old password still works" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host ("  ✓ rejected: {0}" -f $code) -ForegroundColor Green
    }
} | Out-Null

# 9) password grant with NEW password — must succeed.
$tok2 = Measure-Step "9. password grant with NEW password" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $reg.client_id
        client_secret = $reg.client_secret
        username      = $user
        password      = $newPwd
        scope         = "openid profile email offline_access identity:account"
      }
}
Write-Host "  new access_token: $($tok2.access_token.Substring(0,32))…"
Write-Host "  ✓ new password works" -ForegroundColor Green

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
