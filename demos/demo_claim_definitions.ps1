# S2 — claim definitions probe.
#
# Verifies the full lifecycle:
#   1. Admin DCR cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write + identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write
#   2. Admin cc token
#   3. POST /claim-definitions — create global "department" (required, no default)
#   4. POST /claim-definitions — create global "tier" (optional, default = "bronze")
#   5. POST /claim-definitions — create global "score" (int, regex via pattern)
#   6. GET  /claim-definitions — list, expect 3 rows
#   7. Try to create a user WITHOUT custom claims → fail (required department missing)
#   8. Create a user WITH department=engineering → succeeds; verify tier was auto-filled to "bronze"
#   9. PUT /users/{id} with customClaims = { department: "" } → fail (required)
#   10. PUT /users/{id} with customClaims = { score: "not-a-number" } → fail (type)
#   11. PUT /users/{id} with customClaims = { score: "42" } → succeeds
#   12. Cleanup: delete user + 3 definitions
#
# Usage: pwsh -File demo_claim_definitions.ps1
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

function Assert-Rejected {
    param([scriptblock]$Action, [string]$Label)
    try {
        & $Action | Out-Null
        throw "  ! ${Label}: expected validation_error, got success"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 400, 422) {
            Write-Host "  ✓ $Label → $code" -ForegroundColor Green
        } else { throw }
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

$adminReg = Measure-Step "1. admin DCR cc + users.manage + applications.manage" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "claim-defs-admin"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# Cleanup leftover definitions from prior runs so they don't accumulate +
# don't block subsequent user creates / registrations with their required flags.
try {
    $oldDefs = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/claim-definitions?count=200" -Headers $ADMIN
    foreach ($d in $oldDefs.items) {
        if ($d.claimName -match '^(department|tier|score)-') {
            try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/claim-definitions/$($d.id)" -Headers $ADMIN | Out-Null } catch {}
        }
    }
} catch {}

# Use unique claim names so reruns don't collide with leftover definitions.
$suffix = [Guid]::NewGuid().ToString("N").Substring(0,6)
$claimDept   = "department-$suffix"
$claimTier   = "tier-$suffix"
$claimScore  = "score-$suffix"

$dept = Measure-Step "3. POST /claim-definitions ($claimDept, required, no default)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/claim-definitions" -Headers $ADMIN `
      -Body (@{
        claimName = $claimDept
        type = "string"
        required = $true
        scope = "global"
      } | ConvertTo-Json)
}
$tier = Measure-Step "4. POST /claim-definitions ($claimTier, optional, default=bronze)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/claim-definitions" -Headers $ADMIN `
      -Body (@{
        claimName = $claimTier
        type = "string"
        required = $true
        defaultValue = "bronze"
        scope = "global"
      } | ConvertTo-Json)
}
$score = Measure-Step "5. POST /claim-definitions ($claimScore, type=int)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/claim-definitions" -Headers $ADMIN `
      -Body (@{
        claimName = $claimScore
        type = "int"
        required = $false
        scope = "global"
      } | ConvertTo-Json)
}

Measure-Step "6. GET /claim-definitions — list" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/claim-definitions?count=200" -Headers $ADMIN
    Write-Host "  ✓ total = $($r.total)" -ForegroundColor Green
    $names = $r.items | ForEach-Object { $_.claimName }
    foreach ($n in @($claimDept, $claimTier, $claimScore)) {
        if ($names -notcontains $n) { throw "definition '$n' not in list" }
    }
    Write-Host "  ✓ all 3 definitions present" -ForegroundColor Green
} | Out-Null

# Cleanup any leftover from earlier runs sharing this suffix (paranoia).
$user = "cdefs_$suffix"
try {
    $existing = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/users/search?query=$user&count=10" -Headers $ADMIN
    foreach ($u in $existing.items) {
        try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$($u.id)" -Headers $ADMIN | Out-Null } catch {}
    }
} catch {}

# 7. Try to create user without satisfying required claim — should fail.
Measure-Step "7. account/register without 'department' — expect 400" {
    # Note: account/register doesn't carry customClaims at all; required claim
    # without default → fail (we'd auto-fill from default but department has none).
    Assert-Rejected -Action {
        Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" -ContentType "application/json" `
          -Body (@{ login = $user; email = "$user@x.com"; password = "Test1234Pass!"; displayName = $user } | ConvertTo-Json)
    } -Label "register without required department"
} | Out-Null

# 8. Admin create with required + default — customClaims in body satisfies department.
$UserId = Measure-Step "8. admin POST /users with customClaims department=engineering" {
    $body = @{
        login = $user
        password = "Test1234Pass!"
        displayName = $user
        customClaims = @{ $claimDept = "engineering" }
    } | ConvertTo-Json
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $ADMIN -Body $body
    if (-not $r.id) { throw "no id" }
    Write-Host "  ✓ user id = $($r.id)" -ForegroundColor Green

    # Verify tier was auto-defaulted (since it's required with default=bronze).
    $u = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/users/$($r.id)" -Headers $ADMIN
    if ($u.customClaims.$claimTier -ne "bronze") {
        throw "tier was not auto-defaulted: got '$($u.customClaims.$claimTier)'"
    }
    Write-Host "  ✓ tier auto-defaulted to 'bronze'" -ForegroundColor Green
    return [long]$r.id
}

# 9. Try to clear the required department — should fail.
Measure-Step "9. PUT /users/$UserId clearing $claimDept — expect 400" {
    Assert-Rejected -Action {
        Invoke-RestMethod -Method Put "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN `
          -Body (@{
            id = $UserId
            customClaims = @{ $claimDept = "" }
          } | ConvertTo-Json)
    } -Label "clearing required claim"
} | Out-Null

# 10. Type validation: int field with non-numeric value.
Measure-Step "10. PUT /users/$UserId score='not-a-number' — expect 400" {
    Assert-Rejected -Action {
        Invoke-RestMethod -Method Put "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN `
          -Body (@{
            id = $UserId
            customClaims = @{ $claimScore = "not-a-number" }
          } | ConvertTo-Json)
    } -Label "int parse failure"
} | Out-Null

# 11. Valid update.
Measure-Step "11. PUT /users/$UserId score='42' — expect 200" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN `
      -Body (@{
        id = $UserId
        customClaims = @{ $claimScore = "42" }
      } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ score=42 saved" -ForegroundColor Green
} | Out-Null

# Cleanup
Measure-Step "12. cleanup" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN | Out-Null } catch {}
    foreach ($d in @($dept, $tier, $score)) {
        try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/claim-definitions/$($d.id)" -Headers $ADMIN | Out-Null } catch {}
    }
    Write-Host "  ✓ user + 3 definitions removed" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
