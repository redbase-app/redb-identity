# Self-service password-change negative paths.
#   PUT /api/v1/identity/me/password — assert the server REJECTS:
#     1. wrong oldPassword                        (HTTP 400, generic — not "wrong password")
#     2. policy-violating newPassword             (HTTP 400, validation_error)
#         - too short              (PasswordPolicy.MinLength = 12)
#         - missing digit          (PasswordPolicy.RequireDigit = true)
#         - missing uppercase      (PasswordPolicy.RequireUppercase = true)
#         - missing lowercase      (PasswordPolicy.RequireLowercase = true)
#     3. history violation                         (HTTP 400, reused old password)
#     4. missing bearer token                      (HTTP 401)
#
# Positive path (old→new ROPC) is covered by demo_me_profile.ps1; this demo focuses
# purely on the rejection contract so we can spot regressions in the policy validator.
# Usage: pwsh -File demo_password_change_negatives.ps1
#requires -Version 7

$BASE = "http://127.0.0.1:5002"
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

# Helper: invoke /me/password expecting failure with a specific HTTP status.
function Invoke-Reject {
    param(
        [string]$Label,
        [hashtable]$Headers,
        [hashtable]$Body,
        [int[]]$ExpectStatus = @(400)
    )
    try {
        Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me/password" `
            -Headers $Headers `
            -ContentType "application/json" `
            -Body ($Body | ConvertTo-Json) `
            -ErrorAction Stop | Out-Null
        throw "  ! UNEXPECTED 2xx — server accepted forbidden mutation ($Label)"
    } catch {
        $resp = $_.Exception.Response
        $code = if ($resp) { [int]$resp.StatusCode } else { 0 }
        if ($ExpectStatus -contains $code) {
            $errBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
            Write-Host "  ✓ rejected: $code  ($Label)" -ForegroundColor Green
            if ($errBody) { Write-Host "    body: $errBody" -ForegroundColor DarkGray }
        } else {
            $errBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
            throw "  ! status=$code, expected $($ExpectStatus -join '/')  body=$errBody"
        }
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

$oldPwd  = "Test1234Pass!"
$newPwd  = "Brand-NewSecret77"

# 1) DCR — password grant.
$reg = Measure-Step "1. DCR /connect/register (password)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name   = "pwd-change-negatives"
            redirect_uris = @("http://localhost:9999/cb")
            grant_types   = @("password","refresh_token")
            scope         = "openid profile email offline_access identity:account"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register a fresh user.
$user = "pwdneg_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Measure-Step "2. self-register ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{
            login       = $user
            email       = "$user@example.com"
            password    = $oldPwd
            displayName = $user
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ user created" -ForegroundColor Green
} | Out-Null

# 3) Get an access token.
$tok = Measure-Step "3. ROPC token (identity:account)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $oldPwd
            scope         = "openid profile email offline_access identity:account"
        }
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}
$bearer = @{ Authorization = "Bearer $($tok.access_token)" }

# 4) Negative — wrong oldPassword
Measure-Step "4. wrong oldPassword (expect 400)" {
    Invoke-Reject -Label "wrong oldPassword" -Headers $bearer -Body @{
        oldPassword = "WrongPasswordZZ!"
        newPassword = $newPwd
    } -ExpectStatus 400,401
} | Out-Null

# 5) Negative — too short (MinLength=12)
Measure-Step "5. policy: too short (expect 400)" {
    Invoke-Reject -Label "too short" -Headers $bearer -Body @{
        oldPassword = $oldPwd
        newPassword = "Sh0rt!a"
    } -ExpectStatus 400
} | Out-Null

# 6) Negative — missing digit (RequireDigit=true)
Measure-Step "6. policy: missing digit (expect 400)" {
    Invoke-Reject -Label "missing digit" -Headers $bearer -Body @{
        oldPassword = $oldPwd
        newPassword = "NoDigitsAtAll!!"
    } -ExpectStatus 400
} | Out-Null

# 7) Negative — missing uppercase
Measure-Step "7. policy: missing uppercase (expect 400)" {
    Invoke-Reject -Label "missing uppercase" -Headers $bearer -Body @{
        oldPassword = $oldPwd
        newPassword = "lowercase4all123"
    } -ExpectStatus 400
} | Out-Null

# 8) Negative — missing lowercase
Measure-Step "8. policy: missing lowercase (expect 400)" {
    Invoke-Reject -Label "missing lowercase" -Headers $bearer -Body @{
        oldPassword = $oldPwd
        newPassword = "UPPERCASE4ALL123"
    } -ExpectStatus 400
} | Out-Null

# 9) Positive — change to a valid new password (so we can probe history).
Measure-Step "9. valid password change (positive)" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me/password" `
        -Headers $bearer -ContentType "application/json" `
        -Body (@{ oldPassword = $oldPwd; newPassword = $newPwd } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ password changed" -ForegroundColor Green
} | Out-Null

# 10) Refresh token after password change (old token may have been revoked).
$tok2 = Measure-Step "10. ROPC with new password" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $newPwd
            scope         = "openid profile email offline_access identity:account"
        }
    Write-Host "  ✓ new password works" -ForegroundColor Green
    return $t
}
$bearer2 = @{ Authorization = "Bearer $($tok2.access_token)" }

# 11) Negative — history: try to set the OLD password back (HistoryCount=5 means recent N forbidden).
Measure-Step "11. history: reuse previous password (expect 400)" {
    Invoke-Reject -Label "history reuse" -Headers $bearer2 -Body @{
        oldPassword = $newPwd
        newPassword = $oldPwd
    } -ExpectStatus 400
} | Out-Null

# 12) Negative — missing bearer
Measure-Step "12. missing bearer (expect 401)" {
    try {
        Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me/password" `
            -ContentType "application/json" `
            -Body (@{ oldPassword = $newPwd; newPassword = "AnotherNewOne7!" } | ConvertTo-Json) `
            -ErrorAction Stop | Out-Null
        throw "  ! UNEXPECTED 2xx — unauth call accepted"
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -eq 401) {
            Write-Host "  ✓ rejected: 401" -ForegroundColor Green
        } else {
            throw "  ! status=$code, expected 401"
        }
    }
} | Out-Null

# 13) RFC 7592 cleanup
Measure-Step "13. RFC 7592 DELETE registration" {
    if (-not $RAT) { Write-Host "  (no RAT → skip)" -ForegroundColor DarkGray; return }
    Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
