# P1 #9 — `groups` / `roles` scope→claim probe (admin-bootstrapped).
#
# Closes the last GAP in OIDC scope→claim coverage. The `groups` and `roles` scopes
# are emitted by GroupClaimsResolver:
#   `groups` claim  = direct group names + tree-ancestor names (transitive membership)
#   `roles`/`role` claim = per-membership Role label (NOT inherited via tree)
#
# Probes (all asserted):
#   1.  admin DCR (client_credentials + identity:users:write identity:groups:write identity:consents:write identity:mfa:write)
#   2.  admin token (mint via client_credentials)
#   3.  user-facing DCR (password grant + groups/roles user-info scopes)
#   4.  self-register user
#   5.  ROPC user token + lookup numeric user id from /me
#   6.  admin creates "developers" team group
#   7.  admin creates "engineering" organisation group (parent of developers)
#   8.  admin moves developers under engineering (tree)
#   9.  admin adds user to "developers" with role="senior"
#  10. ROPC again with scope including groups + roles
#  11. assert id_token.groups contains BOTH "developers" AND ancestor "engineering"
#  12. assert id_token.role(s) contains "senior"
#  13. /connect/userinfo carries the same groups + role
#  14. admin updates role to "lead" → re-ROPC → id_token.role contains "lead", NOT "senior"
#  15. admin removes user from developers → re-ROPC → groups/role claims gone
#  16. RFC 7592 cleanup (delete both DCR'd clients) + delete groups
#
# Usage: pwsh -File demo_groups_roles_claims.ps1
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
        # Avoid -f format operator here: $Name may contain literal {…} from REST path
        # templates (e.g. /groups/{dev}/move) which the format parser interprets as
        # placeholders and aborts with "Failure to parse near offset N".
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

function Get-JwtBody([string]$jwt) {
    $parts = $jwt.Split('.')
    if ($parts.Count -lt 2) { throw "JWT does not have 3 segments" }
    $b64 = $parts[1].Replace('-','+').Replace('_','/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    return $json | ConvertFrom-Json -Depth 12
}

function Get-RopcToken {
    param([string]$ClientId, [string]$ClientSecret, [string]$Username, [string]$Password, [string]$Scope)
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $ClientId
            client_secret = $ClientSecret
            username      = $Username
            password      = $Password
            scope         = $Scope
        }
}

# Normalise a single-or-multi claim into a string[] (JWT array shape).
function To-Array($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [Array]) { return $v }
    return @($v)
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Admin DCR — client_credentials + identity:users:write identity:groups:write identity:consents:write identity:mfa:write (group/member mutations).
$adminReg = Measure-Step "1. admin DCR (cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "groups-roles-admin"
            grant_types = @("client_credentials")
            scope       = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "admin DCR no client_id" }
    Write-Host "  ✓ admin client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$ADMIN_RAT = $adminReg.registration_access_token
$ADMIN_RCU = $adminReg.registration_client_uri

# 2) Admin token.
$adminTok = Measure-Step "2. admin client_credentials token" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $adminReg.client_id
            client_secret = $adminReg.client_secret
            scope         = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write"
        }
    if (-not $t.access_token) { throw "no admin access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)" }

# 3) User DCR — password grant + groups/roles scopes.
$userReg = Measure-Step "3. user-facing DCR (password + groups/roles)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "groups-roles-user"
            grant_types = @("password","refresh_token")
            scope       = "openid profile email offline_access groups roles identity:account"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "user DCR no client_id" }
    Write-Host "  ✓ user client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$USER_RAT = $userReg.registration_access_token
$USER_RCU = $userReg.registration_client_uri

# 4) Self-register user.
$user = "grp_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "4. self-register ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{
            login = $user; email = "$user@example.com"; password = $pwd; displayName = $user
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ user created" -ForegroundColor Green
} | Out-Null

# 5) ROPC + /me to grab numeric user id (admin path needs the bigint userId).
$userId = Measure-Step "5. ROPC + GET /me → numeric userId" {
    $t = Get-RopcToken -ClientId $userReg.client_id -ClientSecret $userReg.client_secret `
                       -Username $user -Password $pwd `
                       -Scope "openid profile email offline_access identity:account"
    $bearer = @{ Authorization = "Bearer $($t.access_token)" }
    $me = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $bearer
    # /me may surface id under different shapes; pick first non-empty numeric.
    $id = $null
    foreach ($p in 'id','userId','user_id','Id') {
        $v = $me.PSObject.Properties[$p]
        if ($v -and $v.Value) { $id = [long]$v.Value; break }
    }
    if (-not $id) { throw "could not extract numeric userId from /me (shape: $($me | ConvertTo-Json -Depth 3))" }
    Write-Host "  ✓ userId = $id" -ForegroundColor Green
    return $id
}

# 6) Create "developers" (team) group.
$devGroup = Measure-Step "6. admin: POST /groups (developers, team)" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups" -Headers $ADMIN `
        -ContentType "application/json" `
        -Body (@{ name = "developers-$user"; groupType = "team"; description = "p7 probe team" } | ConvertTo-Json)
    if (-not $r.id) { throw "no group id in response: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  ✓ developers groupId = $($r.id)" -ForegroundColor Green
    return $r
}

# 7) Create "engineering" (organization) group.
$engGroup = Measure-Step "7. admin: POST /groups (engineering, organization)" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups" -Headers $ADMIN `
        -ContentType "application/json" `
        -Body (@{ name = "engineering-$user"; groupType = "organization"; description = "p7 probe org" } | ConvertTo-Json)
    if (-not $r.id) { throw "no group id" }
    Write-Host "  ✓ engineering groupId = $($r.id)" -ForegroundColor Green
    return $r
}

# 8) Move developers under engineering — tree parent_id wiring.
Measure-Step "8. admin: POST /groups/{dev}/move (parent = engineering)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups/$($devGroup.id)/move" -Headers $ADMIN `
        -ContentType "application/json" `
        -Body (@{ newParentGroupId = [long]$engGroup.id } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ developers parent_id = engineering" -ForegroundColor Green
} | Out-Null

# 9) Admin adds user to developers with role="senior".
Measure-Step "9. admin: POST /groups/{dev}/members (userId, role=senior)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups/$($devGroup.id)/members" -Headers $ADMIN `
        -ContentType "application/json" `
        -Body (@{ userId = $userId; role = "senior" } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ membership created" -ForegroundColor Green
} | Out-Null

# 10) ROPC with groups + roles scopes.
$tok10 = Measure-Step "10. ROPC user token (scope includes groups + roles)" {
    Get-RopcToken -ClientId $userReg.client_id -ClientSecret $userReg.client_secret `
                  -Username $user -Password $pwd `
                  -Scope "openid profile email offline_access groups roles identity:account"
}

# 11) Assert groups claim on id_token — both direct AND ancestor names.
Measure-Step "11. assert id_token.groups contains [developers-$user, engineering-$user]" {
    $claims = Get-JwtBody $tok10.id_token
    $groups = To-Array $claims.groups
    Write-Host "  groups claim: $($groups -join ', ')" -ForegroundColor DarkGray
    if ($groups -notcontains "developers-$user") { throw "groups missing 'developers-$user'" }
    if ($groups -notcontains "engineering-$user") {
        throw "groups missing ancestor 'engineering-$user' — tree ancestor expansion broken"
    }
    Write-Host "  ✓ direct + ancestor present" -ForegroundColor Green
} | Out-Null

# 12) Assert roles/role claim — "senior".
Measure-Step "12. assert id_token role(s) contains 'senior'" {
    $claims = Get-JwtBody $tok10.id_token
    # Some emitters use 'roles' (array), others 'role' (single/multi-claim).
    $roles = @()
    if ($claims.PSObject.Properties['roles']) { $roles += (To-Array $claims.roles) }
    if ($claims.PSObject.Properties['role'])  { $roles += (To-Array $claims.role) }
    Write-Host "  role claim(s): $($roles -join ', ')" -ForegroundColor DarkGray
    if ($roles -notcontains "senior") {
        throw "role claim does not carry 'senior' (got: $($roles -join ','))"
    }
    Write-Host "  ✓ role 'senior' present" -ForegroundColor Green
} | Out-Null

# 13) /connect/userinfo carries same surface.
Measure-Step "13. GET /connect/userinfo carries groups + role" {
    $ui = Invoke-RestMethod -Method Get "$BASE/connect/userinfo" `
        -Headers @{ Authorization = "Bearer $($tok10.access_token)" }
    $g = To-Array $ui.groups
    if ($g -notcontains "developers-$user") { throw "userinfo.groups missing developers" }
    $r = @()
    if ($ui.PSObject.Properties['roles']) { $r += (To-Array $ui.roles) }
    if ($ui.PSObject.Properties['role'])  { $r += (To-Array $ui.role) }
    if ($r -notcontains "senior") { throw "userinfo missing role 'senior' (got: $($r -join ','))" }
    Write-Host "  ✓ groups + role on userinfo parity with id_token" -ForegroundColor Green
} | Out-Null

# 14) Update membership role to "lead", re-ROPC, assert new role.
Measure-Step "14. admin updates role → 'lead', re-ROPC, assert id_token.role == 'lead' (and NOT 'senior')" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/groups/$($devGroup.id)/members/$userId" -Headers $ADMIN `
        -ContentType "application/json" `
        -Body (@{ role = "lead" } | ConvertTo-Json) | Out-Null
    $tok14 = Get-RopcToken -ClientId $userReg.client_id -ClientSecret $userReg.client_secret `
                           -Username $user -Password $pwd `
                           -Scope "openid profile email offline_access groups roles identity:account"
    $claims = Get-JwtBody $tok14.id_token
    $roles = @()
    if ($claims.PSObject.Properties['roles']) { $roles += (To-Array $claims.roles) }
    if ($claims.PSObject.Properties['role'])  { $roles += (To-Array $claims.role) }
    if ($roles -notcontains "lead") { throw "role claim does not carry new 'lead' (got: $($roles -join ','))" }
    if ($roles -contains "senior") { throw "role claim still carries old 'senior' — update did not propagate" }
    Write-Host "  ✓ role rotated senior → lead" -ForegroundColor Green
} | Out-Null

# 15) Remove user from developers — groups + role claims disappear.
Measure-Step "15. admin removes user from developers → groups/role claims gone" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/groups/$($devGroup.id)/members/$userId" -Headers $ADMIN | Out-Null
    $tok15 = Get-RopcToken -ClientId $userReg.client_id -ClientSecret $userReg.client_secret `
                           -Username $user -Password $pwd `
                           -Scope "openid profile email offline_access groups roles identity:account"
    $claims = Get-JwtBody $tok15.id_token
    $groups = To-Array $claims.groups
    if ($groups -contains "developers-$user") { throw "groups still carries 'developers-$user' after Remove" }
    $roles = @()
    if ($claims.PSObject.Properties['roles']) { $roles += (To-Array $claims.roles) }
    if ($claims.PSObject.Properties['role'])  { $roles += (To-Array $claims.role) }
    if ($roles -contains "lead") { throw "role still carries 'lead' after Remove" }
    Write-Host "  ✓ groups/role claims cleared on remove" -ForegroundColor Green
} | Out-Null

# 16) Cleanup — delete both groups + both DCR clients.
Measure-Step "16. cleanup (delete groups + RFC 7592 DELETE registrations)" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/groups/$($devGroup.id)" -Headers $ADMIN | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/groups/$($engGroup.id)" -Headers $ADMIN | Out-Null } catch {}
    if ($ADMIN_RAT) { Invoke-RestMethod -Method Delete -Uri $ADMIN_RCU -Headers @{ Authorization = "Bearer $ADMIN_RAT" } | Out-Null }
    if ($USER_RAT)  { Invoke-RestMethod -Method Delete -Uri $USER_RCU  -Headers @{ Authorization = "Bearer $USER_RAT"  } | Out-Null }
    Write-Host "  ✓ cleaned up" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
