# P1 #10 — granular admin scopes probe.
#
# Two complementary scope axes from `IdentityScopes`:
#   `identity:read`        — read-only admin: GET on any admin path; mutations → 403
#   `identity:audit:read`  — narrowest granular scope: only /audit GET passes; other admin paths → 403
#
# Closes the GAP in §4 of the coverage matrix (identity:read / identity:audit:read).
# The asserts demonstrate the per-method (read-only) and per-path (granular) sides of
# `GranularScopeGuardProcessor` (HTTP facade) without relying on a master admin token.
#
# Probes (all asserted):
#   1.  DCR client_credentials + identity:read
#   2.  cc token (scope=identity:read)
#   3.  GET /users  → 200 (read-only OK)
#   4.  GET /groups → 200 (read-only OK)
#   5.  GET /applications → 200 (read-only OK)
#   6.  GET /audit  → 200 (read-only OK)
#   7.  POST /groups (mutation) → 403 insufficient_scope (read-only rejected)
#   8.  POST /users  (mutation) → 403 insufficient_scope
#   9.  DCR client_credentials + identity:audit:read
#  10. cc token (scope=identity:audit:read)
#  11. GET /audit          → 200 (granular OK)
#  12. GET /users          → 403 (audit.read does NOT grant /users)
#  13. GET /applications   → 403
#  14. GET /audit?eventType=UserCreated → 200, results well-shaped
#  15. /audit without bearer → 401
#  16. /audit with garbage bearer → 401
#  17. RFC 7592 cleanup
#
# Usage: pwsh -File demo_admin_scopes.ps1
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

# Expect a specific HTTP status from a request. Returns response body on match,
# or throws (with body snippet) on mismatch.
function Assert-Status {
    param([scriptblock]$Call, [int[]]$Expect, [string]$Label)
    try {
        $body = & $Call
        if (200 -in $Expect) { return $body }
        throw "  ! UNEXPECTED 2xx ($Label) — body: $($body | ConvertTo-Json -Depth 3)"
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($Expect -contains $code) {
            $errBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
            Write-Host "  ✓ $Label → $code" -ForegroundColor Green
            if ($errBody) { Write-Host "    body: $errBody" -ForegroundColor DarkGray }
            return $null
        }
        throw "  ! ${Label}: got $code, expected $($Expect -join '/')"
    }
}

function DcrCc([string]$ClientName, [string]$Scope) {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = $ClientName
            grant_types = @("client_credentials")
            scope       = $Scope
        } | ConvertTo-Json)
}

function CcToken([string]$ClientId, [string]$ClientSecret, [string]$Scope) {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# ── Axis 1: identity:read (cross-path, GET-only) ──────────────────────────────

$rdReg = Measure-Step "1. DCR (cc + identity:read)" {
    $r = DcrCc "admin-scopes-read" "identity:read"
    if (-not $r.client_id) { throw "no client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$READ_RAT = $rdReg.registration_access_token
$READ_RCU = $rdReg.registration_client_uri

$rdTok = Measure-Step "2. cc token (scope=identity:read)" {
    $t = CcToken $rdReg.client_id $rdReg.client_secret "identity:read"
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}
$RD = @{ Authorization = "Bearer $($rdTok.access_token)" }

# Helper: probe a paged endpoint and report whatever the server actually returns.
# The bare admin list endpoints currently return a JSON array; /audit returns
# { total, offset, count, items[] }. Either is fine — we just want the GET to succeed.
function Describe-Response($r) {
    if ($r -is [Array]) { return "array len=$($r.Count)" }
    if ($r.PSObject.Properties['total']) { return "total=$($r.total) items=$($r.items.Count)" }
    if ($r.PSObject.Properties['Total']) { return "Total=$($r.Total) Items=$($r.Items.Count)" }
    return "object keys=$(($r.PSObject.Properties.Name -join ','))"
}

Measure-Step "3. GET /users (identity:read → expect 200)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/users?offset=0&count=1" -Headers $RD
    Write-Host "  ✓ /users readable, $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "4. GET /groups (identity:read → expect 200)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/groups?offset=0&count=1" -Headers $RD
    Write-Host "  ✓ /groups readable, $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "5. GET /applications (identity:read → expect 200)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?offset=0&count=1" -Headers $RD
    Write-Host "  ✓ /applications readable, $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "6. GET /audit (identity:read → expect 200, ReadOnly covers /audit)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/audit?count=1" -Headers $RD
    Write-Host "  ✓ /audit readable, $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "7. POST /groups (identity:read → expect 403 insufficient_scope)" {
    Assert-Status -Label "create group on read-only" -Expect @(403) -Call {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/groups" -Headers $RD `
            -ContentType "application/json" `
            -Body (@{ name = "scope-probe-$([Guid]::NewGuid().ToString('N').Substring(0,6))"; groupType = "team" } | ConvertTo-Json) -ErrorAction Stop
    } | Out-Null
} | Out-Null

Measure-Step "8. POST /users (identity:read → expect 403 insufficient_scope)" {
    Assert-Status -Label "create user on read-only" -Expect @(403) -Call {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $RD `
            -ContentType "application/json" `
            -Body (@{ login = "scope_probe_$([Guid]::NewGuid().ToString('N').Substring(0,6))"; email = "x@example.com"; password = "Test1234Pass!"; displayName = "x" } | ConvertTo-Json) -ErrorAction Stop
    } | Out-Null
} | Out-Null

# ── Axis 2: identity:audit:read (single-path granular) ───────────────────────

$auReg = Measure-Step "9. DCR (cc + identity:audit:read)" {
    $r = DcrCc "admin-scopes-audit" "identity:audit:read"
    if (-not $r.client_id) { throw "no client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$AUD_RAT = $auReg.registration_access_token
$AUD_RCU = $auReg.registration_client_uri

$auTok = Measure-Step "10. cc token (scope=identity:audit:read)" {
    $t = CcToken $auReg.client_id $auReg.client_secret "identity:audit:read"
    if (-not $t.access_token) { throw "no access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}
$AU = @{ Authorization = "Bearer $($auTok.access_token)" }

Measure-Step "11. GET /audit (audit.read → expect 200)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/audit?count=5" -Headers $AU
    Write-Host "  ✓ /audit readable on granular scope, $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "12. GET /users (audit.read → expect 403 insufficient_scope)" {
    Assert-Status -Label "users on audit.read" -Expect @(403) -Call {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/users?count=1" -Headers $AU -ErrorAction Stop
    } | Out-Null
} | Out-Null

Measure-Step "13. GET /applications (audit.read → expect 403)" {
    Assert-Status -Label "applications on audit.read" -Expect @(403) -Call {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?count=1" -Headers $AU -ErrorAction Stop
    } | Out-Null
} | Out-Null

Measure-Step "14. GET /audit?eventType=UserCreated (shape probe)" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/audit?eventType=UserCreated&count=3" -Headers $AU
    # AuditQueryResponse → { total, offset, count, items[] }. Items may be empty if
    # nothing has happened recently, but the envelope itself must always carry
    # the pagination keys.
    $hasTotal = $r.PSObject.Properties['total'] -or $r.PSObject.Properties['Total']
    $hasItems = $r.PSObject.Properties['items'] -or $r.PSObject.Properties['Items']
    if (-not $hasTotal -or -not $hasItems) {
        throw "audit response shape: missing total/items. Got: $($r | ConvertTo-Json -Depth 3)"
    }
    Write-Host "  ✓ filtered query well-shaped: $(Describe-Response $r)" -ForegroundColor Green
} | Out-Null

Measure-Step "15. GET /audit without bearer (expect 401)" {
    Assert-Status -Label "audit unauth" -Expect @(401) -Call {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/audit?count=1" -ErrorAction Stop
    } | Out-Null
} | Out-Null

Measure-Step "16. GET /audit with garbage bearer (expect 401)" {
    Assert-Status -Label "audit garbage bearer" -Expect @(401) -Call {
        Invoke-RestMethod -Method Get "$BASE/api/v1/identity/audit?count=1" `
            -Headers @{ Authorization = "Bearer NOT.A.JWT" } -ErrorAction Stop
    } | Out-Null
} | Out-Null

# ── Cleanup ──
Measure-Step "17. RFC 7592 DELETE registrations" {
    if ($READ_RAT) { Invoke-RestMethod -Method Delete -Uri $READ_RCU -Headers @{ Authorization = "Bearer $READ_RAT" } | Out-Null }
    if ($AUD_RAT)  { Invoke-RestMethod -Method Delete -Uri $AUD_RCU  -Headers @{ Authorization = "Bearer $AUD_RAT"  } | Out-Null }
    Write-Host "  ✓ both DCR clients deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
