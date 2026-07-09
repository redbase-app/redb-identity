# β — per-application group whitelist (ApplicationProps.AllowedGroups).
#
# RFC-compliance probe for RestrictApplicationByGroupMembershipHandler.
# When ApplicationProps.AllowedGroups is non-empty, only users who are a
# member of at least one listed group may authenticate against that
# application. Failures yield OAuth `access_denied`.
#
# Probes (all asserted):
#   1.  DCR a confidential ROPC client (grants password + refresh_token + openid)
#   2.  Seed a user with a known password (login = ropc_NNN, pwd = Test1234Pass!)
#   3.  Sanity: ROPC against the freshly created app (no whitelist) → 200
#   4.  Admin: create group "beta-allowed-NNN"
#   5.  Admin: PUT the application with AllowedGroups = ["beta-allowed-NNN"]
#   6.  ROPC with the same user (still NOT in the group) → access_denied
#   7.  Admin: add the user to the group
#   8.  ROPC again → 200 (user is now allowed)
#   9.  Admin: PUT the application with AllowedGroups = []  (clear whitelist)
#   10. ROPC again → 200 (no whitelist, default behaviour restored)
#   11. Cleanup: delete application, group
#
# Usage: pwsh -File demo_application_allowed_groups.ps1
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

function Get-Ropc {
    param($ClientId, $ClientSecret, $Username, $Password, $Scope)
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

function Assert-RopcDenied {
    param($ClientId, $ClientSecret, $Username, $Password, $Scope, $Label)
    try {
        $body = Get-Ropc -ClientId $ClientId -ClientSecret $ClientSecret `
                        -Username $Username -Password $Password -Scope $Scope
        throw "  ! ${Label}: expected access_denied, got token: $($body.access_token.Substring(0,16))…"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 401, 403) {
            $errBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
            Write-Host "  ✓ $Label → $code" -ForegroundColor Green
            if ($errBody) { Write-Host "    body: $errBody" -ForegroundColor DarkGray }
        } else { throw }
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# --- 0) Admin DCR + token (granular scopes; master identity:manage is not
#        DCR-allowed by design — only granular sub-scopes are). The probe
#        touches users (register + group membership), groups, and
#        applications, so we ask for the union.
$adminReg = Measure-Step "0a. admin DCR cc + users.manage + applications.manage" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name = "beta-allowed-groups-admin"
        grant_types = @("client_credentials")
        scope       = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write"
      } | ConvertTo-Json)
}

$adminTok = Measure-Step "0b. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{
        grant_type    = "client_credentials"
        client_id     = $adminReg.client_id
        client_secret = $adminReg.client_secret
        scope         = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write"
      }
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# --- 1) Admin: create ROPC client directly (so we get the internal id back
#        immediately without paginating a 4 K+ application list to find a
#        freshly DCR'd one).
$ropcSecret = "S-" + [Guid]::NewGuid().ToString("N")
$ropcClientId = "beta-app-" + [Guid]::NewGuid().ToString("N").Substring(0,8)

$ropcReg = Measure-Step "1. admin: POST /applications (confidential ROPC client)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/applications" -Headers $ADMIN `
      -Body (@{
        clientId       = $ropcClientId
        clientSecret   = $ropcSecret
        displayName    = $ropcClientId
        clientType     = "confidential"
        applicationType= "web"
        redirectUris   = @("http://localhost:9999/cb")
        permissions    = @(
            "ept:token",
            "ept:authorization",
            "gt:password",
            "gt:refresh_token",
            "scp:openid",
            "scp:offline_access"
        )
      } | ConvertTo-Json)
}
$RopcClient = $ropcClientId
$RopcSecret = $ropcSecret
$AppId = "$($ropcReg.id)"
Write-Host "  ✓ app id = $AppId" -ForegroundColor Green

# --- 2) Seed a user — account/register returns the internal userId directly.
$user = "beta_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
$UserId = Measure-Step "2. account/register" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = "$user@example.com"
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json)
    if (-not $r.success -or -not $r.userId) { throw "register failed: $($r | ConvertTo-Json)" }
    Write-Host "  ✓ user id = $($r.userId)" -ForegroundColor Green
    return [long]$r.userId
}

# --- 3) Sanity check — ROPC works before any whitelist ---------------------
Measure-Step "3. ROPC happy path (no whitelist yet)" {
    $t = Get-Ropc -ClientId $RopcClient -ClientSecret $RopcSecret `
                  -Username $user -Password $pwd -Scope "openid"
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token: $($t.access_token.Substring(0,16))…" -ForegroundColor Green
} | Out-Null

# --- 4) Create a group ------------------------------------------------------
$groupName = "beta-allowed-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$group = Measure-Step "4. admin: POST /groups $groupName" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups" -Headers $ADMIN `
      -Body (@{ name = $groupName; groupType = "team"; description = "beta probe" } | ConvertTo-Json)
}
$GroupId = [long]$group.id

# --- 5) PUT application with AllowedGroups = [groupName] -------------------
Measure-Step "5. admin: PUT /applications/$AppId  AllowedGroups=[$groupName]" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/applications/$AppId" -Headers $ADMIN `
      -Body (@{
        id            = "$AppId"
        allowedGroups = @($groupName)
      } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ whitelist applied" -ForegroundColor Green
} | Out-Null

# --- 6) ROPC must now be DENIED (user not in group) ------------------------
Measure-Step "6. ROPC (user NOT in group) — expect access_denied" {
    Assert-RopcDenied -ClientId $RopcClient -ClientSecret $RopcSecret `
                      -Username $user -Password $pwd -Scope "openid" `
                      -Label "denied: not a group member"
} | Out-Null

# --- 7) Add user to group --------------------------------------------------
Measure-Step "7. admin: POST /groups/$GroupId/members (userId=$UserId)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups/$GroupId/members" -Headers $ADMIN `
      -Body (@{ userId = $UserId; role = "member" } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ membership created" -ForegroundColor Green
} | Out-Null

# --- 8) ROPC must succeed now ---------------------------------------------
Measure-Step "8. ROPC (user IS in group) — expect 200" {
    $t = Get-Ropc -ClientId $RopcClient -ClientSecret $RopcSecret `
                  -Username $user -Password $pwd -Scope "openid"
    if (-not $t.access_token) { throw "no access_token after adding to group" }
    Write-Host "  ✓ access_token after membership: $($t.access_token.Substring(0,16))…" -ForegroundColor Green
} | Out-Null

# --- 9) Clear whitelist ----------------------------------------------------
Measure-Step "9. admin: PUT /applications/$AppId  AllowedGroups=[]" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/applications/$AppId" -Headers $ADMIN `
      -Body (@{
        id            = "$AppId"
        allowedGroups = @()
      } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ whitelist cleared" -ForegroundColor Green
} | Out-Null

# --- 10) ROPC should still work (whitelist cleared) -----------------------
Measure-Step "10. ROPC (whitelist cleared) — expect 200" {
    $t = Get-Ropc -ClientId $RopcClient -ClientSecret $RopcSecret `
                  -Username $user -Password $pwd -Scope "openid"
    if (-not $t.access_token) { throw "no access_token after clearing whitelist" }
    Write-Host "  ✓ access_token after clear: $($t.access_token.Substring(0,16))…" -ForegroundColor Green
} | Out-Null

# --- 11) Cleanup ----------------------------------------------------------
Measure-Step "11. admin: DELETE /applications/$AppId" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/applications/$AppId" -Headers $ADMIN | Out-Null }
    catch { Write-Host "  (cleanup) application delete returned: $($_.Exception.Message)" -ForegroundColor DarkGray }
} | Out-Null

Measure-Step "11b. admin: DELETE /groups/$GroupId" {
    try {
        Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/groups/$GroupId" -Headers $ADMIN | Out-Null
    }
    catch { Write-Host "  (cleanup) group delete returned: $($_.Exception.Message)" -ForegroundColor DarkGray }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
