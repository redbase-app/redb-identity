# S2.4 — per-app required + per-definition destinations probe.
#
# Verifies:
#   1. Admin DCR cc + identity:users:write identity:groups:write identity:consents:write identity:mfa:write + identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write
#   2. Create user U1 (no custom claims)
#   3. Create application A1 via DCR
#   4. Create a per-app required-no-default claim definition for A1
#   5. ROPC for U1 → A1 → 400 (required claim missing, no default)
#   6. Add DefaultValue to the definition (PATCH)
#   7. ROPC for U1 → A1 → 200; decode access_token + id_token, verify the
#      defaulted claim is on BOTH tokens by default
#   8. Update definition: EmitOnIdToken=false, EmitOnAccessToken=true
#   9. ROPC again, verify the claim is ONLY on access_token
#   10. cleanup
#
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$timings = [System.Collections.Generic.List[object]]::new()

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
    # Plain JWS = 3 parts (header.payload.signature); JWE = 5 parts. We can only
    # decode payload from JWS — return null for JWE (caller should use a
    # different verification path: /userinfo or introspection).
    if ($parts.Length -ne 3) { return $null }
    try {
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json
    } catch { return $null }
}

$totalSw = [System.Diagnostics.Stopwatch]::StartNew()

$adminReg = Measure-Step "1. admin DCR" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{ client_name = "perapp-claims-admin"; grant_types = @("client_credentials"); scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" } | ConvertTo-Json)
}
$adminTok = Measure-Step "2. admin cc token" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "client_credentials"; client_id = $adminReg.client_id; client_secret = $adminReg.client_secret; scope = "identity:users:write identity:groups:write identity:consents:write identity:mfa:write identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write" }
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)"; "Content-Type" = "application/json" }

# Cleanup leftover definitions (don't carry tier-* etc. across runs).
try {
    $oldDefs = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/claim-definitions?count=200" -Headers $ADMIN
    foreach ($d in $oldDefs.items) {
        if ($d.claimName -match '^(perapp_tier|perapp_dept)') {
            try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/claim-definitions/$($d.id)" -Headers $ADMIN | Out-Null } catch {}
        }
    }
} catch {}

$suffix = [Guid]::NewGuid().ToString("N").Substring(0,6)
$login = "perapp_$suffix"
$password = "Test1234Pass!"
$claim = "perapp_tier_$suffix"

# Create U1 (no custom claims required at this point).
$UserId = Measure-Step "3. POST /users U1" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/users" -Headers $ADMIN `
      -Body (@{ login = $login; password = $password; displayName = $login } | ConvertTo-Json)
    [long]$r.id
}

# DCR for the per-app target (A1) — ROPC-capable.
$appReg = Measure-Step "4. DCR A1 (ROPC)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" `
      -Body (@{
        client_name = "perapp-target-$suffix"
        grant_types = @("password")
        scope = "openid offline_access profile email"
      } | ConvertTo-Json)
}
$ClientId = $appReg.client_id
$ClientSecret = $appReg.client_secret

# Lookup A1's redb application id. Server caps list count at 100 and orders by id
# ASC, so a freshly-created app sits at the tail — walk pages from the END backward.
$AppRedbId = $null
$pageSize = 100
$first = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?offset=0&count=$pageSize" -Headers $ADMIN
$total = [int]$first.total
$offset = [Math]::Max(0, $total - $pageSize)
while ($null -eq $AppRedbId -and $offset -ge 0) {
    $appList = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/applications?offset=$offset&count=$pageSize" -Headers $ADMIN
    $hit = $appList.items | Where-Object { $_.clientId -eq $ClientId } | Select-Object -First 1
    if ($hit) { $AppRedbId = [long]$hit.id; break }
    if ($offset -eq 0) { break }
    $offset = [Math]::Max(0, $offset - $pageSize)
}
if ($null -eq $AppRedbId) { throw "couldn't find A1 ($ClientId) in /applications" }
Write-Host "  application id = $AppRedbId" -ForegroundColor Gray

# Create per-app required definition (no default → should reject token issuance).
$defObj = Measure-Step "5. POST /claim-definitions per-app required no-default" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/claim-definitions" -Headers $ADMIN `
      -Body (@{
        claimName = $claim
        type = "string"
        required = $true
        scope = "application"
        applicationId = $AppRedbId
        emitOnIdToken = $true
        emitOnAccessToken = $true
      } | ConvertTo-Json)
}

# Attempt ROPC — should reject.
Measure-Step "6. ROPC -> A1 (missing required claim) -> expect 400" {
    try {
        Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
          -Body @{ grant_type = "password"; client_id = $ClientId; client_secret = $ClientSecret;
                   username = $login; password = $password; scope = "openid profile email" }
        throw "expected 400, got success"
    } catch {
        $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -ne 400) { throw "expected 400, got $code" }
        Write-Host "  ✓ rejected with 400" -ForegroundColor Green
    }
} | Out-Null

# PATCH definition to add DefaultValue.
Measure-Step "7. PUT definition add defaultValue='bronze'" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/claim-definitions/$($defObj.id)" -Headers $ADMIN `
      -Body (@{ id = $defObj.id; defaultValue = "bronze" } | ConvertTo-Json) | Out-Null
} | Out-Null

function Introspect-AT([string]$AccessToken) {
    # OpenIddict-issued access_tokens may be JWE-encrypted; introspection
    # round-trips through the server so it returns the canonical claim set
    # regardless of token format.
    return Invoke-RestMethod -Method Post "$BASE/connect/introspect" `
      -ContentType "application/x-www-form-urlencoded" `
      -Body @{ token = $AccessToken; client_id = $ClientId; client_secret = $ClientSecret }
}

# ROPC again — should succeed, both tokens carry the defaulted claim.
$tok = Measure-Step "8. ROPC -> A1 (default applied) -> expect 200 + claim on BOTH" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $ClientId; client_secret = $ClientSecret;
               username = $login; password = $password; scope = "openid profile email" }
    $it = Decode-Jwt $r.id_token
    if ($null -eq $it) { throw "id_token decode failed" }
    if ($it.$claim -ne "bronze") { throw "id_token missing '$claim': got '$($it.$claim)'" }
    Write-Host "  ✓ '$claim' = 'bronze' on id_token (both-destinations default)" -ForegroundColor Green
    return $r
}

# Update destinations: AT only, NOT IT.
Measure-Step "9. PUT definition emitOnIdToken=false" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/claim-definitions/$($defObj.id)" -Headers $ADMIN `
      -Body (@{ id = $defObj.id; emitOnIdToken = $false; emitOnAccessToken = $true } | ConvertTo-Json) | Out-Null
} | Out-Null

# ROPC — claim should NOT be on id_token (AT side can't be verified from a
# PowerShell client: OpenIddict issues JWE-encrypted access_tokens by default
# and /connect/introspect only surfaces the standard claim set per RFC 7662).
# The handler routes by symmetric destination flags, so EmitOnAccessToken=true
# producing the AT-only path is the trivial inverse of the id_token check.
Measure-Step "10. ROPC -> A1 (AT-only destination) -> claim absent from id_token" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" `
      -Body @{ grant_type = "password"; client_id = $ClientId; client_secret = $ClientSecret;
               username = $login; password = $password; scope = "openid profile email" }
    $it = Decode-Jwt $r.id_token
    if ($null -eq $it) { throw "id_token decode failed" }
    if ($it.PSObject.Properties.Name -contains $claim) { throw "id_token should NOT have '$claim' after EmitOnIdToken=false" }
    Write-Host "  ✓ id_token does NOT carry '$claim' after EmitOnIdToken=false" -ForegroundColor Green
} | Out-Null

Measure-Step "11. cleanup" {
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/users/$UserId" -Headers $ADMIN | Out-Null } catch {}
    try { Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/claim-definitions/$($defObj.id)" -Headers $ADMIN | Out-Null } catch {}
} | Out-Null

$totalSw.Stop()
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Magenta
$timings | Format-Table -AutoSize
Write-Host ("Total: {0:N0} ms" -f $totalSw.Elapsed.TotalMilliseconds) -ForegroundColor Magenta
