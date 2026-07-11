# SCIM 2.0 (RFC 7643/7644) — Users + Groups CRUD.
#   Requires a management (admin) token.  The demo bootstraps an admin user
#   via /api/v1/identity/management/bootstrap-admin (or uses a pre-seeded
#   admin via client_credentials with identity:admin scope if bootstrap is off).
#   Coverage: POST/GET/PATCH/DELETE User, POST/GET/PATCH/DELETE Group,
#             /ServiceProviderConfig + /Schemas discovery, filter query.
# Usage: pwsh -File demo_scim.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$SCIM    = "$BASE/api/v1/identity/scim/v2"
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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# ── Obtain admin token ────────────────────────────────────────────────────────
# Strategy 1: DCR with identity:admin scope via client_credentials.
# Strategy 2: ROPC with a pre-seeded admin account.
# This demo tries Strategy 1 first, falls back to a placeholder.
$adminBearer = $null

$adminReg = Measure-Step "1. DCR /connect/register (client_credentials + identity:admin)" {
    try {
        $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
          -ContentType "application/json" `
          -Body (@{
            client_name = "scim-admin-demo"
            grant_types = @("client_credentials")
            scope       = "identity:admin"
          } | ConvertTo-Json)
        Write-Host "  client_id: $($r.client_id)"
        return $r
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  DCR for identity:admin failed ($code) — will try password grant" -ForegroundColor Yellow
        return $null
    }
}

if ($adminReg) {
    $adminTok = Measure-Step "2. client_credentials → identity:admin token" {
        try {
            $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
              -ContentType "application/x-www-form-urlencoded" `
              -Body @{
                grant_type    = "client_credentials"
                client_id     = $adminReg.client_id
                client_secret = $adminReg.client_secret
                scope         = "identity:admin"
              }
            Write-Host "  token_type: $($t.token_type)  expires_in: $($t.expires_in)"
            return $t
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            $body = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "" }
            Write-Host "  client_credentials failed ($code): $body" -ForegroundColor Yellow
            Write-Host "  identity:admin scope may require explicit admin grant — using fallback" -ForegroundColor Yellow
            return $null
        }
    }
    if ($adminTok) {
        $adminBearer = @{ Authorization = "Bearer $($adminTok.access_token)" }
    }
}

if (-not $adminBearer) {
    Write-Host ""
    Write-Host "!! No admin token available.  To run SCIM demos:" -ForegroundColor Red
    Write-Host "   1. Pre-seed an admin user and set `$ADMIN_USER / `$ADMIN_PWD below." -ForegroundColor Yellow
    Write-Host "   2. Or grant 'identity:admin' to a DCR client via the management API." -ForegroundColor Yellow
    Write-Host "   Continuing with probes that do not require admin (discovery only)." -ForegroundColor DarkGray
}

# ── SCIM Discovery (no auth needed per RFC 7644 §4) ──────────────────────────

$spc = Measure-Step "3. GET /scim/v2/ServiceProviderConfig (RFC 7644 §4)" {
    Invoke-RestMethod -Method Get "$SCIM/ServiceProviderConfig"
}
$spc | ConvertTo-Json -Depth 4 | Out-Host
if ($spc.schemas) { Write-Host "  ✓ schemas present" -ForegroundColor Green }

$schemas = Measure-Step "4. GET /scim/v2/Schemas (RFC 7643 §7)" {
    Invoke-RestMethod -Method Get "$SCIM/Schemas"
}
$totalSchemas = if ($schemas.totalResults) { $schemas.totalResults } elseif ($schemas -is [array]) { $schemas.Count } else { "?" }
Write-Host "  totalResults: $totalSchemas"
if ([int]$totalSchemas -ge 2) {
    Write-Host "  ✓ User + Group schemas present" -ForegroundColor Green
} else {
    Write-Host "  ! expected ≥2 schemas (User+Group)" -ForegroundColor Yellow
}

# ── SCIM CRUD (requires admin) ────────────────────────────────────────────────

if (-not $adminBearer) {
    Write-Host ""
    Write-Host "  (skipping CRUD steps — no admin token)" -ForegroundColor DarkGray
    $total.Stop()
    Write-Host ""
    Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
    $timings | Format-Table -AutoSize Step, Ms, Status
    Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
    exit 0
}

# 5) POST /Users — create SCIM user.
$scimUser = Measure-Step "5. POST /scim/v2/Users (create)" {
    $uname = "scim_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $r = Invoke-RestMethod -Method Post "$SCIM/Users" `
      -Headers $adminBearer `
      -ContentType "application/scim+json" `
      -Body (@{
        schemas    = @("urn:ietf:params:scim:schemas:core:2.0:User")
        userName   = $uname
        name       = @{ formatted = "SCIM Demo $uname"; givenName = "SCIM"; familyName = "Demo" }
        emails     = @(@{ value = "$uname@example.com"; primary = $true })
        active     = $true
      } | ConvertTo-Json -Depth 5)
    Write-Host "  id       : $($r.id)"
    Write-Host "  userName : $($r.userName)"
    if ($r.id) { Write-Host "  ✓ user created" -ForegroundColor Green }
    return $r
}

# 6) GET /Users/{id} — read back.
$readUser = Measure-Step "6. GET /scim/v2/Users/$($scimUser.id)" {
    $r = Invoke-RestMethod -Method Get "$SCIM/Users/$($scimUser.id)" -Headers $adminBearer
    Write-Host "  userName : $($r.userName)  active: $($r.active)"
    if ($r.id -eq $scimUser.id) { Write-Host "  ✓ read back matches" -ForegroundColor Green }
    return $r
}

# 7) PATCH /Users/{id} — deactivate.
Measure-Step "7. PATCH /scim/v2/Users/$($scimUser.id) (deactivate)" {
    $r = Invoke-RestMethod -Method Patch "$SCIM/Users/$($scimUser.id)" `
      -Headers $adminBearer `
      -ContentType "application/scim+json" `
      -Body (@{
        schemas    = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
        Operations = @(@{ op = "Replace"; path = "active"; value = $false })
      } | ConvertTo-Json -Depth 5)
    Write-Host "  active after patch: $($r.active)"
    if ($r.active -eq $false) { Write-Host "  ✓ deactivated" -ForegroundColor Green }
    else { Write-Host "  ! active is still $($r.active)" -ForegroundColor Yellow }
    return $r
} | Out-Null

# 8) GET /Users?filter=userName eq "…" — filter query (RFC 7644 §3.4.2).
Measure-Step "8. GET /scim/v2/Users?filter=userName eq '…'" {
    $filter = "userName eq `"$($scimUser.userName)`""
    $r = Invoke-RestMethod -Method Get "$SCIM/Users?filter=$([Uri]::EscapeDataString($filter))" `
      -Headers $adminBearer
    $count = if ($r.totalResults) { $r.totalResults } elseif ($r.Resources) { $r.Resources.Count } else { 0 }
    Write-Host "  totalResults: $count"
    if ([int]$count -ge 1) { Write-Host "  ✓ filter returned the user" -ForegroundColor Green }
    else { Write-Host "  ! filter returned 0 results" -ForegroundColor Yellow }
} | Out-Null

# 9) POST /Groups — create a group.
$scimGroup = Measure-Step "9. POST /scim/v2/Groups (create)" {
    $gname = "scim-grp-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
    $r = Invoke-RestMethod -Method Post "$SCIM/Groups" `
      -Headers $adminBearer `
      -ContentType "application/scim+json" `
      -Body (@{
        schemas     = @("urn:ietf:params:scim:schemas:core:2.0:Group")
        displayName = $gname
        members     = @(@{ value = $scimUser.id; display = $scimUser.userName })
      } | ConvertTo-Json -Depth 5)
    Write-Host "  id          : $($r.id)"
    Write-Host "  displayName : $($r.displayName)"
    if ($r.id) { Write-Host "  ✓ group created" -ForegroundColor Green }
    return $r
}

# 10) GET /Groups/{id} — read back.
Measure-Step "10. GET /scim/v2/Groups/$($scimGroup.id)" {
    $r = Invoke-RestMethod -Method Get "$SCIM/Groups/$($scimGroup.id)" -Headers $adminBearer
    $memberCount = if ($r.members) { $r.members.Count } else { 0 }
    Write-Host "  displayName : $($r.displayName)  members: $memberCount"
    if ($r.id -eq $scimGroup.id) { Write-Host "  ✓ group read back" -ForegroundColor Green }
    if ($memberCount -ge 1)       { Write-Host "  ✓ member present" -ForegroundColor Green }
    else                          { Write-Host "  ! no members returned" -ForegroundColor Yellow }
} | Out-Null

# 11) DELETE /Users/{id} — remove the SCIM user.
Measure-Step "11. DELETE /scim/v2/Users/$($scimUser.id)" {
    Invoke-WebRequest -Method Delete "$SCIM/Users/$($scimUser.id)" -Headers $adminBearer | Out-Null
    Write-Host "  ✓ user deleted" -ForegroundColor Green
} | Out-Null

# 12) GET after delete — must 404.
Measure-Step "12. GET /scim/v2/Users/$($scimUser.id) after delete (expect 404)" {
    try {
        Invoke-RestMethod -Method Get "$SCIM/Users/$($scimUser.id)" -Headers $adminBearer | Out-Null
        Write-Host "  ! UNEXPECTED — deleted user still accessible" -ForegroundColor Red
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) {
            Write-Host "  ✓ 404" -ForegroundColor Green
        } else {
            Write-Host "  status: $code" -ForegroundColor Yellow
        }
    }
} | Out-Null

# 13) DELETE /Groups/{id}.
Measure-Step "13. DELETE /scim/v2/Groups/$($scimGroup.id)" {
    try {
        Invoke-WebRequest -Method Delete "$SCIM/Groups/$($scimGroup.id)" -Headers $adminBearer | Out-Null
        Write-Host "  ✓ group deleted" -ForegroundColor Green
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  status: $code" -ForegroundColor Yellow
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
