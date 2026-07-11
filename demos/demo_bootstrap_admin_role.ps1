#requires -Version 7
# Bootstrap admin ⇄ admin role wiring assertion.
#
# Pinned by the architectural fix in commit 12b2fcaf — the B1 bootstrap
# previously put the admin user only in the "admins" group (carrying
# scope identity:admin) but NOT in the B.3 "admin" role. Role-centric
# UI surfaces (/admin/roles/{adminRoleId} Users tab) misleadingly
# rendered empty. Fix is two-track: BootstrapAdminProcessor mirrors
# the new user into the admin role at create-time, and
# BootstrapAdminBackfillListener walks every startup to catch old
# installs where the role had no assignee.
#
# This demo:
#   1.  Admin DCR (cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write + identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write)
#   2.  Admin cc token
#   3.  GET /roles?name=admin → resolve admin role id
#   4.  GET /roles/{adminRoleId}/users → ASSERT contains at least one
#       user (the bootstrap admin) and their login is non-empty
#       (regression on commit 32f089ae's per-id lookup fix).
#   5.  RFC 7592 cleanup.
#
# A green run means: (a) seeded admin role exists, (b) bootstrap or
# the backfill listener wired at least one user into it, (c) server-
# side assignee enumeration resolves the login correctly at any
# user-count.
#
# Usage: pwsh -File demo_bootstrap_admin_role.ps1

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
        Write-Host "--- [$Name] $('{0:N0}' -f $sw.Elapsed.TotalMilliseconds) ms" -ForegroundColor DarkGray
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [Math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "ok" })
        return $result
    } catch {
        $sw.Stop()
        $timings.Add([pscustomobject]@{ Step = $Name; Ms = [Math]::Round($sw.Elapsed.TotalMilliseconds, 0); Status = "FAIL" })
        Write-Host "!!! [$Name] FAIL: $_" -ForegroundColor Red
        throw
    }
}

# 1. DCR
$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType 'application/json' `
      -Body (@{ client_name = "bootstrap-admin-role-probe"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}

# 2. cc token
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType 'application/x-www-form-urlencoded' `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$H = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# 3. Resolve admin role id (name=admin, audience=organization). The system
#    role was seeded by SeedSystemRolesListener on first startup.
$adminRoleId = Measure-Step "3. GET /roles?name=admin" {
    $list = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/roles?name=admin" -Headers $H
    $admin = $list.items | Where-Object { $_.name -eq "admin" -and $_.audience -eq "organization" } | Select-Object -First 1
    if (-not $admin) { throw "system admin role not seeded — SeedSystemRolesListener didn't run?" }
    Write-Host "  admin role id = $($admin.id)" -ForegroundColor Gray
    return [long]$admin.id
}

# 4. List assignees. After the fix, the bootstrap admin user must be in
#    the list AND their login must resolve correctly (per-id lookup from
#    commit 32f089ae).
$adminUserLogin = Measure-Step "4. GET /roles/$adminRoleId/assignees (assert non-empty + logins resolved)" {
    $users = @(Invoke-RestMethod -Method Get "$BASE/api/v1/identity/roles/$adminRoleId/assignees" -Headers $H)
    if ($users.Count -lt 1) {
        throw "admin role has no assignees — BootstrapAdminBackfillListener didn't run, or no admin user is in 'admins' group"
    }
    Write-Host "  admin role assignees: $($users.Count)" -ForegroundColor Gray
    foreach ($u in $users) {
        if (-not $u.subjectLabel) {
            throw "assignee $($u.subjectId) has no subjectLabel — RoleManagementProcessor.ListAssignees regression on commit 32f089ae"
        }
        Write-Host "    - $($u.subjectId) → $($u.subjectLabel)" -ForegroundColor Gray
    }
    # Sanity: the FIRST assignee is a real user, not the never-assigned
    # sentinel id 0. On the SQL-seeded canonical admin the user id is 1 —
    # treat anything > 0 as legitimate. The role MUST contain the seed
    # admin (login matches RedbIdentityOptions.SeedAdmin.Login).
    if ($users[0].subjectId -le 0) {
        throw "first assignee user_id=$($users[0].subjectId) is not a real user"
    }
    if (-not ($users.subjectLabel -contains "admin")) {
        throw "expected the seed admin user (login=admin) to be one of the assignees; got: $($users.subjectLabel -join ', ')"
    }
    return $users[0].subjectLabel
}

# 5. RFC 7592 cleanup.
Measure-Step "5. RFC 7592 DELETE registration" {
    try {
        Invoke-RestMethod -Method Delete "$BASE/connect/register/$($adminReg.client_id)" `
          -Headers @{ Authorization = "Bearer $($adminReg.registration_access_token)" } | Out-Null
    } catch {}
} | Out-Null

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
$timings | Format-Table -AutoSize
$total = ($timings | Measure-Object -Property Ms -Sum).Sum
Write-Host ("Total: {0:N0} ms" -f $total)
Write-Host ""
Write-Host "Verified: bootstrap admin user '$adminUserLogin' is a member of the admin role." -ForegroundColor Green
