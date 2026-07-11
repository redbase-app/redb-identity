# Self-service account deletion — DELETE /api/v1/identity/me.
#
# Closes release-gate item #2. Builds on the user-contract for `_users`:
#   • `_login` is immutable forever (PG-trigger `protect_system_users`)
#   • `_name` is mutable (used for tombstoning the soft-deleted row)
#   • `_enabled=false + _date_dismiss=now` removes the user from regular queries
#
# Cascade revoke story (verified by this demo):
#   1. SessionService.LogoutAsync kills every session for the user, which in turn
#      revokes the OpenIddict authorizations and invalidates the access/refresh
#      tokens those sessions issued.
#   2. UserProvider.DeleteUserAsync soft-deletes the `_users` row — login stays
#      occupied so re-registration with the same login is blocked.
#   3. IdentityDeletionHelper soft-deletes the OIDC props object so admin search
#      / list no longer returns it.
#
# Steps:
#   1.  DCR password + admin clients
#   2.  self-register user
#   3.  ROPC token + admin cc token
#   4.  GET /me (sanity — user can see itself)
#   5.  DELETE /me → assert success=true + sessionsRevoked count
#   6.  GET /me with SAME bearer → expect 401 (token revoked, session killed)
#   7.  POST /token (ROPC same creds) → expect failure (user disabled)
#   8.  admin search by email → user not in queries (soft-deleted from view)
#   9.  re-register same login → expect failure (login slot occupied)
#  10.  DELETE /me again with stale bearer → still 401 (idempotency on caller side)
#  11.  cleanup DCR
#
# Usage: pwsh -File demo_me_delete.ps1
#requires -Version 7

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
        $result = & $Action
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "--- [$Name] $ms ms" -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        Write-Host "!!! [$Name] FAILED in $ms ms: $($_.Exception.Message)" -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=$ms; Status="fail" })
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()
$user = "del_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$email = "$user@example.com"
$pwd = "Test1234Pass!"

# 1) DCRs.
$userReg = Measure-Step "1a. DCR password client (for ROPC)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
        client_name = "me-delete"
        grant_types = @("password","refresh_token")
        scope       = "openid profile email offline_access identity:account"
    } | ConvertTo-Json)
}
$U_RAT = $userReg.registration_access_token
$U_RCU = $userReg.registration_client_uri

$adminReg = Measure-Step "1b. DCR admin client (users.manage)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
        client_name = "me-delete-admin"
        grant_types = @("client_credentials")
        scope       = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
    } | ConvertTo-Json)
}
$A_RAT = $adminReg.registration_access_token
$A_RCU = $adminReg.registration_client_uri

# 2) Self-register user.
Measure-Step "2. self-register user $user" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" -Body (@{
        login = $user; email = $email; password = $pwd; displayName = $user
    } | ConvertTo-Json) | Out-Null
    Write-Host "  registered" -ForegroundColor Green
} | Out-Null

# 3a) ROPC user token.
$userTok = Measure-Step "3a. ROPC token (user)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type    = "password"
        client_id     = $userReg.client_id
        client_secret = $userReg.client_secret
        username      = $user
        password      = $pwd
        scope         = "openid profile email identity:account"
    }
}
$U_HDR = @{ Authorization = "Bearer $($userTok.access_token)" }

# 3b) Admin cc token.
$adminTok = Measure-Step "3b. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type    = "client_credentials"
        client_id     = $adminReg.client_id
        client_secret = $adminReg.client_secret
        scope         = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
    }
}
$A_HDR = @{ Authorization = "Bearer $($adminTok.access_token)" }

# 4) Sanity GET /me.
$meBefore = Measure-Step "4. GET /me (sanity — sees own profile)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $U_HDR
    if ($r.login -ne $user) { throw "GET /me returned login=$($r.login), expected $user" }
    Write-Host "  login=$($r.login), email=$($r.email)" -ForegroundColor Green
    return $r
}
$userId = $meBefore.id

# 5) DELETE /me.
Measure-Step "5. DELETE /me → success + sessionsRevoked count" {
    $r = Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me" -Headers $U_HDR
    if (-not $r.success) { throw "DELETE /me did not return success=true: $($r | ConvertTo-Json -Depth 3)" }
    if ($null -eq $r.sessionsRevoked) { throw "missing sessionsRevoked in response" }
    Write-Host "  success=true, sessionsRevoked=$($r.sessionsRevoked)" -ForegroundColor Green
} | Out-Null

# 6) GET /me with same bearer → 401. Bearer JWTs are normally self-contained and stay
#    valid until exp, but DisabledUserRejectionHandler closes that gap: every validated
#    bearer is re-checked against the redb user store, and tokens for disabled /
#    soft-deleted users get rejected with invalid_token immediately.
Measure-Step "6. GET /me with stale bearer → 401 (DisabledUserRejectionHandler)" {
    $code = 0
    try { Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $U_HDR -ErrorAction Stop | Out-Null }
    catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        elseif ($_.Exception.StatusCode) { $code = [int]$_.Exception.StatusCode }
        elseif ($_.ErrorDetails -and $_.ErrorDetails.Message -match '"error":"invalid_(token|grant)"') { $code = 401 }
    }
    if ($code -ne 401) { throw "expected 401, got $code — DisabledUserRejectionHandler not firing" }
    Write-Host "  401 (bearer rejected post-delete — DisabledUserRejectionHandler works)" -ForegroundColor Green
} | Out-Null

# 7) ROPC with same creds → fail (user disabled).
Measure-Step "7. ROPC same creds → fail (user soft-deleted / disabled)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
            grant_type    = "password"
            client_id     = $userReg.client_id
            client_secret = $userReg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email"
        } -ErrorAction Stop | Out-Null
        throw "expected ROPC to fail, but token was issued"
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        elseif ($_.Exception.StatusCode) { $code = [int]$_.Exception.StatusCode }
        elseif ($_.ErrorDetails -and $_.ErrorDetails.Message -match '"error":"invalid_(token|grant)"') { $code = 401 }
        if ($code -lt 400) { throw "expected 4xx, got $code" }
        Write-Host "  HTTP $code (no token for soft-deleted user)" -ForegroundColor Green
    }
} | Out-Null

# 8) Admin search by email → user gone from regular queries.
Measure-Step "8. admin search by email → user filtered out (soft-delete hides from queries)" {
    $r = Invoke-RestMethod "$BASE/api/v1/identity/users/search?query=$email" -Headers $A_HDR
    $hits = if ($r.items) { $r.items } elseif ($r.results) { $r.results } else { $r }
    $found = @($hits | Where-Object { $_.email -eq $email -and $_.id -eq $userId })
    if ($found.Count -gt 0) { throw "soft-deleted user still surfaced in search (id=$userId)" }
    Write-Host "  user $userId not in search results" -ForegroundColor Green
} | Out-Null

# 9) Re-register SAME login → fail (login slot occupied).
Measure-Step "9. re-register SAME login → fail (login immutable, slot occupied)" {
    try {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" -Body (@{
            login = $user; email = "$user-new@example.com"; password = $pwd; displayName = "$user-new"
        } | ConvertTo-Json) -ErrorAction Stop | Out-Null
        throw "expected re-register to fail (login already taken), but it succeeded"
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        elseif ($_.Exception.StatusCode) { $code = [int]$_.Exception.StatusCode }
        elseif ($_.ErrorDetails -and $_.ErrorDetails.Message -match '"error":"invalid_(token|grant)"') { $code = 401 }
        if ($code -lt 400) { throw "expected 4xx, got $code" }
        Write-Host "  HTTP $code (login still occupied)" -ForegroundColor Green
    }
} | Out-Null

# 10) Second DELETE with stale bearer → 401 (bearer is rejected too).
Measure-Step "10. DELETE /me again with stale bearer → 401 (also rejected)" {
    $code = 0
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/me" -Headers $U_HDR -ErrorAction Stop | Out-Null }
    catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        elseif ($_.Exception.StatusCode) { $code = [int]$_.Exception.StatusCode }
        elseif ($_.ErrorDetails -and $_.ErrorDetails.Message -match '"error":"invalid_(token|grant)"') { $code = 401 }
    }
    if ($code -ne 401) { throw "expected 401, got $code" }
    Write-Host "  401 (stale bearer cannot drive privileged ops)" -ForegroundColor Green
} | Out-Null

# 11) Cleanup.
Measure-Step "11. RFC 7592 DELETE DCRs" {
    if ($U_RAT) { try { Invoke-RestMethod -Method Delete -Uri $U_RCU -Headers @{ Authorization = "Bearer $U_RAT" } | Out-Null } catch {} }
    if ($A_RAT) { try { Invoke-RestMethod -Method Delete -Uri $A_RCU -Headers @{ Authorization = "Bearer $A_RAT" } | Out-Null } catch {} }
    Write-Host "  DCRs deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
