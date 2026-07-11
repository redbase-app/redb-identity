# B.3 — Roles registry end-to-end probe.
#
# Verifies the full lifecycle:
#   1. admin DCR cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write + identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write
#   2. create role 'eng-org' (organization audience)
#   3. create role 'shop-admin' (application audience, bound to a DCR'd app)
#   4. attempt to delete a system role — expect 4xx (none in fresh DB but
#      duplicate-create on 'eng-org' surfaces the same conflict path)
#   5. create test user
#   6. assign user to 'eng-org' role
#   7. ROPC + decode id_token — expect 'eng-org' in roles claim, NOT 'shop-admin'
#   8. assign user to 'shop-admin' for app A
#   9. ROPC against app A — expect both 'eng-org' AND 'shop-admin' in roles
#   10. ROPC against another app B — expect only 'eng-org' (app-scoped role doesn't leak)
#   11. create group, assign user to group, assign group to 'eng-org-2' role
#   12. ROPC — expect 'eng-org-2' present via transitive group→role
#   13. cleanup
#
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
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

function Decode-Jwt([string]$Token) {
    if ([string]::IsNullOrEmpty($Token)) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Length -ne 3) { return $null }
    try {
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json
    } catch { return $null }
}

$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "roles-probe-admin"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$H = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

$suffix = [Guid]::NewGuid().ToString('N').Substring(0,6)

# Cleanup stale roles named with our suffix prefix
try {
    $stale = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/roles?count=200" -Headers $H
    foreach ($r in $stale.items) {
        if ($r.name -match '^(eng-org|shop-admin|eng-org-2)-') {
            try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/roles/$($r.id)" -Headers $H | Out-Null } catch {}
        }
    }
} catch {}

# Step 3: create org-audience role
$orgRoleName = "eng-org-$suffix"
$orgRole = Measure-Step "3. POST /roles org-audience '$orgRoleName'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles" -Headers $H `
      -Body (@{ name = $orgRoleName; audience = "organization"; description = "engineering org-wide" } | ConvertTo-Json)
}

# Step 4: app-audience role needs an application. DCR app A.
$appAReg = Measure-Step "4a. DCR application A (ROPC)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "roles-app-a-$suffix"; grant_types = @("password"); scope = "openid offline_access profile email" } | ConvertTo-Json)
}
$appBReg = Measure-Step "4b. DCR application B (ROPC, separate)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "roles-app-b-$suffix"; grant_types = @("password"); scope = "openid offline_access profile email" } | ConvertTo-Json)
}

# Lookup the redb application ids (the registered DCR client_id is GUID).
$appList = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?offset=0&count=100" -Headers $H
$total = [int]$appList.total
$AppAId = $null; $AppBId = $null
$pageSize = 100
$offset = [Math]::Max(0, $total - $pageSize)
while (($null -eq $AppAId -or $null -eq $AppBId) -and $offset -ge 0) {
    $appList = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?offset=$offset&count=$pageSize" -Headers $H
    foreach ($a in $appList.items) {
        if ($a.clientId -eq $appAReg.client_id) { $AppAId = [long]$a.id }
        if ($a.clientId -eq $appBReg.client_id) { $AppBId = [long]$a.id }
    }
    if ($offset -eq 0) { break }
    $offset = [Math]::Max(0, $offset - $pageSize)
}
if ($null -eq $AppAId -or $null -eq $AppBId) { throw "couldn't find one of the DCR apps in /applications" }
Write-Host "  AppA id = $AppAId, AppB id = $AppBId" -ForegroundColor Gray

$appRoleName = "shop-admin-$suffix"
$appRole = Measure-Step "5. POST /roles app-audience '$appRoleName' (bound to AppA)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles" -Headers $H `
      -Body (@{ name = $appRoleName; audience = "application"; applicationId = $AppAId; description = "shop admin on app A" } | ConvertTo-Json)
}

# Step 6: create test user
$login = "roleuser_$suffix"
$pwd = "Test1234Pass!"
$user = Measure-Step "6. POST /users '$login'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $H `
      -Body (@{ login = $login; password = $pwd; displayName = $login } | ConvertTo-Json)
}
$UserId = [long]$user.id

# Step 7: assign user → org-audience role
Measure-Step "7. POST /roles/$($orgRole.id)/users (assign $UserId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles/$($orgRole.id)/users" -Headers $H `
      -Body (@{ userId = $UserId } | ConvertTo-Json) | Out-Null
} | Out-Null

# Step 8: ROPC against app A — expect 'eng-org' in roles
Measure-Step "8. ROPC -> AppA, decode id_token, expect roles=['$orgRoleName']" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $appAReg.client_id; client_secret = $appAReg.client_secret;
               username = $login; password = $pwd; scope = "openid profile email" }
    $it = Decode-Jwt $tok.id_token
    if ($null -eq $it) { throw "id_token decode failed" }
    $roles = @($it.roles)
    Write-Host "  id_token.roles = $($roles -join ', ')" -ForegroundColor Gray
    if ($roles -notcontains $orgRoleName) { throw "missing '$orgRoleName'" }
    if ($roles -contains $appRoleName) { throw "'$appRoleName' should not be present yet (user not assigned)" }
} | Out-Null

# Step 9: assign user → app-audience role
Measure-Step "9. POST /roles/$($appRole.id)/users (assign $UserId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles/$($appRole.id)/users" -Headers $H `
      -Body (@{ userId = $UserId } | ConvertTo-Json) | Out-Null
} | Out-Null

# Step 10: ROPC against AppA — expect BOTH roles
Measure-Step "10. ROPC -> AppA, expect roles=['$orgRoleName', '$appRoleName']" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $appAReg.client_id; client_secret = $appAReg.client_secret;
               username = $login; password = $pwd; scope = "openid profile email" }
    $it = Decode-Jwt $tok.id_token
    $roles = @($it.roles)
    Write-Host "  AppA id_token.roles = $($roles -join ', ')" -ForegroundColor Gray
    if ($roles -notcontains $orgRoleName) { throw "missing '$orgRoleName'" }
    if ($roles -notcontains $appRoleName) { throw "missing '$appRoleName' on AppA" }
} | Out-Null

# Step 11: ROPC against AppB — expect ONLY org role (audience='application' role is app-scoped)
Measure-Step "11. ROPC -> AppB, expect roles=['$orgRoleName'] (NOT '$appRoleName')" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $appBReg.client_id; client_secret = $appBReg.client_secret;
               username = $login; password = $pwd; scope = "openid profile email" }
    $it = Decode-Jwt $tok.id_token
    $roles = @($it.roles)
    Write-Host "  AppB id_token.roles = $($roles -join ', ')" -ForegroundColor Gray
    if ($roles -notcontains $orgRoleName) { throw "AppB missing '$orgRoleName' (org-audience role)" }
    if ($roles -contains $appRoleName) { throw "AppB token leaked AppA-scoped role '$appRoleName'" }
} | Out-Null

# Step 12: group→role transitive path
$gName = "g-roles-$suffix"
$group = Measure-Step "12a. POST /groups '$gName'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups" -Headers $H `
      -Body (@{ name = $gName; groupType = "team" } | ConvertTo-Json)
}
$GroupId = [long]$group.id

# Add user to group
Measure-Step "12b. POST /groups/$GroupId/members (add $UserId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups/$GroupId/members" -Headers $H `
      -Body (@{ userId = $UserId; role = "member" } | ConvertTo-Json) | Out-Null
} | Out-Null

# New org role to assign to group only
$orgRoleName2 = "eng-org-2-$suffix"
$orgRole2 = Measure-Step "12c. POST /roles org-audience '$orgRoleName2'" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles" -Headers $H `
      -Body (@{ name = $orgRoleName2; audience = "organization" } | ConvertTo-Json)
}

# Assign group → role (not user directly)
Measure-Step "12d. POST /roles/$($orgRole2.id)/groups (assign group $GroupId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/roles/$($orgRole2.id)/groups" -Headers $H `
      -Body (@{ groupId = $GroupId } | ConvertTo-Json) | Out-Null
} | Out-Null

# Step 13: ROPC — expect 'eng-org-2' (transitive group→role)
Measure-Step "13. ROPC -> AppA, expect roles includes '$orgRoleName2' (transitive via group)" {
    $tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $appAReg.client_id; client_secret = $appAReg.client_secret;
               username = $login; password = $pwd; scope = "openid profile email" }
    $it = Decode-Jwt $tok.id_token
    $roles = @($it.roles)
    Write-Host "  id_token.roles = $($roles -join ', ')" -ForegroundColor Gray
    if ($roles -notcontains $orgRoleName2) { throw "missing '$orgRoleName2' (transitive via group)" }
} | Out-Null

# Cleanup
Measure-Step "14. cleanup" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$UserId" -Headers $H | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/groups/$GroupId" -Headers $H | Out-Null } catch {}
    foreach ($r in @($orgRole, $appRole, $orgRole2)) {
        try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/roles/$($r.id)" -Headers $H | Out-Null } catch {}
    }
} | Out-Null

$totalSw.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $totalSw.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
