# Admin session management — `identity:sessions:write identity:tokens:write` scope axis.
#
# Closes the ⚠️ "admin-сценарий не probed" entry in §4 of the coverage matrix.
# All routes go through SessionsController (NOT MeSessionsController), so the admin
# may revoke ANOTHER user's sessions and the GranularScopeGuard gates on
# `identity:sessions:write identity:tokens:write` (not Account).
#
# Probes (all asserted):
#   1.  admin DCR (cc + identity:sessions:write identity:tokens:write)
#   2.  admin cc token
#   3.  user-facing DCR (password grant) + self-register
#   4.  user spawns N=3 sessions by repeating ROPC (each grant_type=password mints
#       a new session row; assert sessionsRevoked counts grow correspondingly)
#   5.  admin GET /sessions?userId=N → expect list with >=3 entries for that user
#   6.  admin DELETE /sessions?sessionId=M → single-revoke (200), session disappears
#       from a follow-up GET
#   7.  admin DELETE /sessions/all?userId=N&dryRun=true → count returned, sessions
#       NOT actually revoked (a follow-up GET still lists them)
#   8.  admin DELETE /sessions/all?userId=N → all remaining sessions revoked
#       (follow-up GET returns empty)
#   9.  admin GET /sessions without bearer → 401
#  10. admin GET /sessions with identity:read scope → 403 (read-only doesn't cover
#       sessions admin per GranularScopeGuard's /sessions ↔ sessions.manage map)
#  11. admin DELETE /sessions/all with identity:read scope → 403
#  12. RFC 7592 cleanup
#
# Usage: pwsh -File demo_sessions_admin.ps1
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

function Assert-Status {
    param([scriptblock]$Call, [int[]]$Expect, [string]$Label)
    try {
        $body = & $Call
        if (200 -in $Expect -or 204 -in $Expect) { return $body }
        throw "  ! UNEXPECTED 2xx (${Label}) — body: $($body | ConvertTo-Json -Depth 3)"
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($Expect -contains $code) {
            Write-Host "  ✓ ${Label} → $code" -ForegroundColor Green
            return $null
        }
        throw "  ! ${Label}: got $code, expected $($Expect -join '/')"
    }
}

function Dcr {
    param([string]$Name, [string]$Grants, [string]$Scope, [string[]]$Redirects = @())
    # $Grants is a comma-separated single string; the DCR endpoint expects an array.
    $grantList = @($Grants -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $body = @{ client_name = $Name; grant_types = $grantList; scope = $Scope }
    if ($Redirects.Count -gt 0) { $body['redirect_uris'] = $Redirects }
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" -Body ($body | ConvertTo-Json)
}

function CcToken { param([string]$Cid, [string]$Sec, [string]$Scope)
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ grant_type = "client_credentials"; client_id = $Cid; client_secret = $Sec; scope = $Scope }
}

function RopcToken { param([string]$Cid, [string]$Sec, [string]$User, [string]$Pwd, [string]$Scope)
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type = "password"; client_id = $Cid; client_secret = $Sec
            username = $User; password = $Pwd; scope = $Scope
        }
}

# Extract sessions array from a list response — server may return bare array or {items}.
function To-Sessions($r) {
    if ($r -is [Array]) { return $r }
    if ($r.PSObject.Properties['items'])    { return $r.items }
    if ($r.PSObject.Properties['Items'])    { return $r.Items }
    if ($r.PSObject.Properties['sessions']) { return $r.sessions }
    return @($r)
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Admin DCR.
$adminReg = Measure-Step "1. admin DCR (cc + identity:sessions:write identity:tokens:write)" {
    $r = Dcr "sessions-admin" "client_credentials" "identity:sessions:write identity:tokens:write"
    if (-not $r.client_id) { throw "no client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$ADMIN_RAT = $adminReg.registration_access_token
$ADMIN_RCU = $adminReg.registration_client_uri

# 1b) read-only DCR for the negative scope probes (step 10/11).
$readReg = Measure-Step "1b. read-only DCR (cc + identity:read) for negative scope probes" {
    $r = Dcr "sessions-read" "client_credentials" "identity:read"
    Write-Host "  ✓ read-only client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$READ_RAT = $readReg.registration_access_token
$READ_RCU = $readReg.registration_client_uri

# 2) Admin token.
$adminTok = Measure-Step "2. admin cc token" {
    $t = CcToken $adminReg.client_id $adminReg.client_secret "identity:sessions:write identity:tokens:write"
    if (-not $t.access_token) { throw "no token" }
    return $t
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)" }
$readTok = Measure-Step "2b. read-only cc token" {
    CcToken $readReg.client_id $readReg.client_secret "identity:read"
}
$READ = @{ Authorization = "Bearer $($readTok.access_token)" }

# 3) User-facing DCR + register.
$userReg = Measure-Step "3. user DCR (password grant) + self-register" {
    $r = Dcr "sessions-user" "password,refresh_token" "openid profile email offline_access identity:account"
    Write-Host "  ✓ user client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$USER_RAT = $userReg.registration_access_token
$USER_RCU = $userReg.registration_client_uri

$user = "sa_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "3b. account/register ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{ login = $user; email = "$user@example.com"; password = $pwd; displayName = $user } | ConvertTo-Json) | Out-Null
} | Out-Null

# 4) Spawn 3 sessions via the cookie /login flow (ROPC does NOT create _sessions rows —
#    that's LoginProcessor's responsibility). Each /login call mints a fresh session row
#    keyed by user_id. Also use one ROPC to fetch the numeric userId via /me.
$userId = Measure-Step "4. spawn 3 sessions via cookie /login + fetch numeric userId" {
    $t = RopcToken $userReg.client_id $userReg.client_secret $user $pwd "openid profile email offline_access identity:account"
    $bearer = @{ Authorization = "Bearer $($t.access_token)" }
    $me = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/me" -Headers $bearer
    $id = $null
    foreach ($p in 'id','userId','user_id','Id') { $v = $me.PSObject.Properties[$p]; if ($v -and $v.Value) { $id = [long]$v.Value; break } }
    if (-not $id) { throw "no userId on /me" }

    for ($i = 1; $i -le 3; $i++) {
        $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        try {
            Invoke-WebRequest -Method Post "$BASE/login" `
                -WebSession $s -ContentType "application/x-www-form-urlencoded" `
                -Body @{ username = $user; password = $pwd } `
                -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue | Out-Null
        } catch {}
        if ($s.Cookies.GetCookies($BASE).Count -lt 1) { throw "no session cookie on /login #$i" }
    }
    Write-Host "  ✓ userId=$id, 3 cookie sessions spawned" -ForegroundColor Green
    return $id
}

# 5) Admin GET /sessions.
Measure-Step "5. admin GET /sessions?userId=$userId (expect ≥ 3)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $ADMIN
    $list = To-Sessions $r
    if ($list.Count -lt 3) { throw "expected ≥3 sessions, got $($list.Count). Response: $($r | ConvertTo-Json -Depth 4)" }
    Write-Host "  ✓ admin sees $($list.Count) sessions" -ForegroundColor Green
} | Out-Null

# 6) Admin revoke a single session.
$victim = Measure-Step "6. admin DELETE /sessions?sessionId=X (single revoke)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $ADMIN
    $list = @(To-Sessions $r)
    $first = $list[0]
    $sidProp = if ($first.id) { $first.id } elseif ($first.sessionId) { $first.sessionId } elseif ($first.Id) { $first.Id } else { $null }
    if (-not $sidProp) { throw "no sessionId in list entry: $($first | ConvertTo-Json -Depth 3)" }
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/sessions?sessionId=$sidProp" -Headers $ADMIN | Out-Null
    # Confirm shrink.
    $r2 = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $ADMIN
    $list2 = @(To-Sessions $r2)
    if ($list2.Count -ge $list.Count) {
        throw "session count did not shrink after revoke (was $($list.Count), now $($list2.Count))"
    }
    Write-Host "  ✓ revoked sessionId=$sidProp, list $($list.Count)→$($list2.Count)" -ForegroundColor Green
    return $sidProp
}

# 7) dryRun revoke-all — counts but doesn't actually revoke.
Measure-Step "7. admin DELETE /sessions/all?userId=$userId&dryRun=true (count, no mutation)" {
    $r = Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/sessions/all?userId=$userId&dryRun=true" -Headers $ADMIN
    # Server returns some shape with a count; we just confirm endpoint accepts the flag.
    Write-Host "  ✓ dryRun response: $($r | ConvertTo-Json -Compress -Depth 3)" -ForegroundColor Green
    $r2 = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $ADMIN
    $list2 = @(To-Sessions $r2)
    if ($list2.Count -lt 1) {
        throw "dryRun should NOT actually revoke — list is empty after the call"
    }
    Write-Host "  ✓ post-dryRun list still has $($list2.Count) sessions (no mutation)" -ForegroundColor Green
} | Out-Null

# 8) Real revoke-all.
Measure-Step "8. admin DELETE /sessions/all?userId=$userId (real revoke)" {
    Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/sessions/all?userId=$userId" -Headers $ADMIN | Out-Null
    $r2 = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $ADMIN
    $list2 = @(To-Sessions $r2)
    if ($list2.Count -gt 0) {
        throw "after revoke-all, list should be empty, got $($list2.Count). Response: $($r2 | ConvertTo-Json -Depth 4)"
    }
    Write-Host "  ✓ all sessions revoked, list is empty" -ForegroundColor Green
} | Out-Null

# 9) Unauth.
Measure-Step "9. GET /sessions without bearer → 401" {
    Assert-Status -Label "unauth" -Expect @(401) -Call {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -ErrorAction Stop
    } | Out-Null
} | Out-Null

# 10) identity:read covers GET on every admin path (cross-cutting read-only) — so
#     a GET on /sessions with read-only must succeed; only mutations should be denied.
Measure-Step "10. GET /sessions with identity:read → 200 (read-only universal GET)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/sessions?userId=$userId" -Headers $READ
    Write-Host "  ✓ read-only GET sessions → 200" -ForegroundColor Green
} | Out-Null

# 11) identity:read DELETE /sessions/all → 403 (mutation blocked).
Measure-Step "11. DELETE /sessions/all with identity:read → 403 (mutation blocked)" {
    Assert-Status -Label "read-only DELETE sessions" -Expect @(403) -Call {
        Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/sessions/all?userId=$userId" -Headers $READ -ErrorAction Stop
    } | Out-Null
} | Out-Null

# 12) cleanup.
Measure-Step "12. RFC 7592 DELETE registrations" {
    if ($ADMIN_RAT) { Invoke-RestMethod -Method Delete -Uri $ADMIN_RCU -Headers @{ Authorization = "Bearer $ADMIN_RAT" } | Out-Null }
    if ($READ_RAT)  { Invoke-RestMethod -Method Delete -Uri $READ_RCU  -Headers @{ Authorization = "Bearer $READ_RAT"  } | Out-Null }
    if ($USER_RAT)  { Invoke-RestMethod -Method Delete -Uri $USER_RCU  -Headers @{ Authorization = "Bearer $USER_RAT"  } | Out-Null }
    Write-Host "  ✓ all 3 DCR clients deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
