# Admin-side password reset — bypasses OldPassword challenge.
#
# Operator with identity:users:write identity:groups:write identity:consents:write identity:mfa:write POSTs /users/{id}/admin-reset-password
# with just { NewPassword } — server side runs the same complexity policy as
# the user-self flow + revokes every session for the target user.
#
# Probes (all asserted):
#   1. Admin DCR (cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write)
#   2. Admin cc token
#   3. Seed a user
#   4. Sanity ROPC with the original password → 200
#   5. Admin: POST /users/{id}/admin-reset-password { NewPassword = "Reset…" }
#   6. ROPC with the OLD password → invalid_grant
#   7. ROPC with the NEW password → 200
#   8. Cleanup: delete user
#
# Usage: pwsh -File demo_admin_password_reset.ps1
#requires -Version 7

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

function Get-Ropc {
    param($ClientId, $ClientSecret, $Username, $Password)
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "password"
        client_id     = $ClientId
        client_secret = $ClientSecret
        username      = $Username
        password      = $Password
        scope         = "openid"
      }
}

function Assert-RopcDenied {
    param($ClientId, $ClientSecret, $Username, $Password, $Label)
    try {
        $body = Get-Ropc -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password
        throw "  ! ${Label}: expected invalid_grant, got token: $($body.access_token.Substring(0,16))…"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401) {
            Write-Host "  ✓ $Label → $code" -ForegroundColor Green
        } else { throw }
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# --- 1) Admin DCR cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write ---
$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "admin-pwd-reset"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write" } | ConvertTo-Json)
}

$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write" }
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# --- 3) Seed a user ---
$user = "pwdreset_" + [Guid]::NewGuid().ToString("N").Substring(0,8)
$oldPwd = "OldOldPass1234!"
$newPwd = "NewNewPass5678!"
$UserId = Measure-Step "3. seed user" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" `
      -Body (@{ login = $user; email = "$user@example.com"; password = $oldPwd; displayName = $user } | ConvertTo-Json)
    if (-not $r.success -or -not $r.userId) { throw "register failed: $($r | ConvertTo-Json)" }
    return [long]$r.userId
}

# --- 4) Also need a ROPC client to actually try logins ---
$ropcReg = Measure-Step "4a. DCR ropc client" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "pwdreset-ropc"; redirect_uris = @($REDIRECT_CB); grant_types = @("password","refresh_token"); scope = "openid" } | ConvertTo-Json)
}

Measure-Step "4b. ROPC with OLD password — expect 200" {
    $t = Get-Ropc -ClientId $ropcReg.client_id -ClientSecret $ropcReg.client_secret -Username $user -Password $oldPwd
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token: $($t.access_token.Substring(0,16))…" -ForegroundColor Green
} | Out-Null

# --- 5) Admin reset password ---
Measure-Step "5. admin: POST /users/$UserId/admin-reset-password" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users/$UserId/admin-reset-password" -Headers $ADMIN `
      -Body (@{ id = $UserId; newPassword = $newPwd } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ reset accepted" -ForegroundColor Green
} | Out-Null

# --- 6) Old password must fail ---
Measure-Step "6. ROPC with OLD password — expect invalid_grant" {
    Assert-RopcDenied -ClientId $ropcReg.client_id -ClientSecret $ropcReg.client_secret -Username $user -Password $oldPwd `
                      -Label "old password rejected"
} | Out-Null

# --- 7) New password must succeed ---
Measure-Step "7. ROPC with NEW password — expect 200" {
    $t = Get-Ropc -ClientId $ropcReg.client_id -ClientSecret $ropcReg.client_secret -Username $user -Password $newPwd
    if (-not $t.access_token) { throw "no access_token with new password" }
    Write-Host "  ✓ access_token: $($t.access_token.Substring(0,16))…" -ForegroundColor Green
} | Out-Null

# --- 8) Cleanup ---
Measure-Step "8. cleanup: delete user" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN | Out-Null }
    catch { Write-Host "  (cleanup) user delete returned: $($_.Exception.Message)" -ForegroundColor DarkGray }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
