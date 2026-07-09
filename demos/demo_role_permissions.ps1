# B.3 — permission picker probe.
#
# Verifies:
#   1. admin DCR
#   2. create custom scope 'shop:orders.read'
#   3. create role 'shop-staff'
#   4. attach the scope to the role
#   5. create user, assign user to role
#   6. DCR a ROPC client that's ALLOWED 'shop:orders.read'
#   7. ROPC scope='openid email' (deliberately NOT requesting shop:orders.read)
#   8. introspect access_token, assert scope contains 'shop:orders.read'
#   9. detach scope, re-ROPC, assert 'shop:orders.read' gone
#   10. cleanup
#
#requires -Version 7

$BASE = "http://127.0.0.1:5002"
$timings = [System.Collections.Generic.List[object]]::new()
$totalSw = [System.Diagnostics.Stopwatch]::StartNew()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""; Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Action; $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $r
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

# Admin
$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "rolperm-admin"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$H = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

$suffix = [Guid]::NewGuid().ToString('N').Substring(0,6)
$scopeName = "shop-orders-$suffix"
$roleName = "shop-staff-$suffix"
$userLogin = "rolperm_$suffix"

# Step 3 — create the custom scope (stored as ScopeProps in redb).
$scope = Measure-Step "3. POST /scopes '$scopeName'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/scopes" -Headers $H `
      -Body (@{ name = $scopeName; description = "Shop orders permission" } | ConvertTo-Json)
}
$ScopeId = [long]$scope.id

# Step 4 — create role
$role = Measure-Step "4. POST /roles '$roleName' (org-audience)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles" -Headers $H `
      -Body (@{ name = $roleName; audience = "organization" } | ConvertTo-Json)
}
$RoleId = [long]$role.id

# Step 5 — attach scope to role
Measure-Step "5. POST /roles/$RoleId/scopes (attach $ScopeId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles/$RoleId/scopes" -Headers $H `
      -Body (@{ scopeId = $ScopeId } | ConvertTo-Json) | Out-Null
} | Out-Null

# Step 6 — verify list-scopes
Measure-Step "6. GET /roles/$RoleId/scopes" {
    $attached = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/roles/$RoleId/scopes" -Headers $H
    if (@($attached).Count -lt 1) { throw "expected 1 attached scope" }
    Write-Host "  attached.scopeName = $($attached[0].scopeName)" -ForegroundColor Gray
} | Out-Null

# Step 7 — create user
$user = Measure-Step "7. POST /users '$userLogin'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $H `
      -Body (@{ login = $userLogin; password = "Test1234Pass!"; displayName = $userLogin } | ConvertTo-Json)
}
$UserId = [long]$user.id

# Step 8 — assign user to role
Measure-Step "8. POST /roles/$RoleId/users (assign $UserId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles/$RoleId/users" -Headers $H `
      -Body (@{ userId = $UserId } | ConvertTo-Json) | Out-Null
} | Out-Null

# Step 9 — DCR ROPC client allowed to ask for this scope
# Use admin /applications POST (not DCR) to register a client whose allowed-scope
# list includes our custom $scopeName — DCR's DynamicRegistrationAllowedScopes is a
# STATIC config array (openid/profile/email/phone/address/offline_access/groups/roles)
# and custom scopes aren't auto-eligible. The admin path goes through
# IOpenIddictApplicationManager so the client is properly registered in OpenIddict's
# store and the BCrypt hashing matches what ValidateClientSecretAsync expects.
$ropcClientId = "rolperm-ropc-$suffix"
$ropcSecret = "PermTest!$suffix"
$ropcReg = Measure-Step "9. POST /applications (ROPC client + scp:$scopeName allowed)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/applications" -Headers $H `
      -Body (@{
        clientId = $ropcClientId
        clientSecret = $ropcSecret
        displayName = "rolperm-ropc-$suffix"
        clientType = "confidential"
        consentType = "implicit"
        permissions = @(
            "ept:token",
            "ept:introspection",
            "gt:password",
            "gt:refresh_token",
            "scp:openid",
            "scp:profile",
            "scp:email",
            "scp:offline_access",
            "scp:$scopeName"
        )
      } | ConvertTo-Json) | Out-Null
    return @{ client_id = $ropcClientId; client_secret = $ropcSecret }
}

# Step 10 — ROPC NOT requesting the role-attached scope; expect server to ADD it
# Token endpoint response carries the granted scope set verbatim — including
# anything our AttachRoleRegistryClaims handler added via SetScopes on the
# principal. Asserting here (vs introspect) avoids depending on OpenIddict's
# default introspect-payload narrowing for scope.
Measure-Step "10. ROPC scope='openid profile email' (no $scopeName in request)" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $ropcReg.client_id; client_secret = $ropcReg.client_secret;
               username = $userLogin; password = "Test1234Pass!"; scope = "openid profile email" }
    Write-Host "  granted scope = $($tok.scope)" -ForegroundColor Gray
    if ($tok.scope -notmatch [Regex]::Escape($scopeName)) {
        throw "expected '$scopeName' in granted scope (auto-added by role attachment)"
    }
} | Out-Null

# Step 11 — detach + re-ROPC; should be gone
Measure-Step "11. DELETE /roles/$RoleId/scopes/$ScopeId (detach)" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/roles/$RoleId/scopes/$ScopeId" -Headers $H | Out-Null
} | Out-Null

Measure-Step "12. ROPC after detach; expect '$scopeName' GONE from granted set" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $ropcReg.client_id; client_secret = $ropcReg.client_secret;
               username = $userLogin; password = "Test1234Pass!"; scope = "openid profile email" }
    Write-Host "  granted scope = $($tok.scope)" -ForegroundColor Gray
    if ($tok.scope -match [Regex]::Escape($scopeName)) {
        throw "scope '$scopeName' still present after detach"
    }
} | Out-Null

# Cleanup
Measure-Step "13. cleanup" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$UserId" -Headers $H | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/roles/$RoleId" -Headers $H | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/scopes/$ScopeId" -Headers $H | Out-Null } catch {}
} | Out-Null

$totalSw.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $totalSw.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
