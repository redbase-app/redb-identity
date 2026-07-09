# JWKS rotation — admin signing-key lifecycle + live JWKS observability.
#
# Closes the 🟦 JWKS-rotation backlog item from DEMO_COVERAGE_MATRIX.md.
#
# Server contract this demo locks in:
#   • admin can list every stored key row (active + demoted + retired) with audit trail
#   • POST /signing-keys/rotate mints a fresh active key AND demotes previously-active keys
#     of the same kind, preserving their NotAfter window for a grace overlap
#   • DELETE /signing-keys/{kid} ends the validity window (NotAfter=now) so the key drops
#     out of the JWKS on the next request — admin list still carries the row with inJwks=false
#   • /.well-known/jwks reads keys LIVE from the store on every request (LiveJwksProcessor):
#     rotate / retire are visible to RPs immediately, without process restart
#   • only public JWK material is exposed (no `d`, `p`, `q`, …) on either endpoint
#
# Batch 12 contract (live-refresh, fully delivered):
#   • Rotate / retire invalidate IOptionsMonitorCache for both server and validation
#     options, so the next options read re-runs every PostConfigure.
#   • PostConfigure splits the key pool: SigningCredentials gets only in-window keys
#     (NotBefore <= now < NotAfter) so OpenIddict never mints under a retired kid;
#     TokenValidationParameters.IssuerSigningKeys gets the full pool (including retired)
#     so in-flight tokens signed under previously-active-then-retired kids still validate.
#   • Asserted at steps 8/11: after rotate, ROPC id_token.kid IS the just-rotated kid.
#
# Usage: pwsh -File demo_jwks_rotation.ps1
#requires -Version 7

$BASE   = "http://127.0.0.1:5002"
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

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR admin client.
$adminReg = Measure-Step "1. DCR (cc + identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "jwks-rotation"
            grant_types = @("client_credentials")
            scope       = "identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "DCR no client_id" }
    Write-Host "  client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$ADMIN_RAT = $adminReg.registration_access_token
$ADMIN_RCU = $adminReg.registration_client_uri

# 2) cc token (admin auth).
$adminTok = Measure-Step "2. cc token (scope=identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $adminReg.client_id
            client_secret = $adminReg.client_secret
            scope         = "identity:applications:write identity:scopes:write identity:claims:write identity:roles:write identity:webhooks:write identity:federation:write identity:signing-keys:write"
        }
    if (-not $t.access_token) { throw "no access_token" }
    return $t
}
$ADMIN = @{ Authorization = "Bearer $($adminTok.access_token)" }

# 3) GET /signing-keys → snapshot baseline; note count, kinds present.
$baselineAdmin = Measure-Step "3. GET /signing-keys -> admin baseline snapshot" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/signing-keys" -Headers $ADMIN
    if (-not $r.keys -or $r.keys.Count -lt 1) { throw "admin list returned no keys" }
    $kinds = ($r.keys | ForEach-Object { $_.kind } | Sort-Object -Unique) -join ","
    Write-Host "  baseline: $($r.keys.Count) keys (kinds: $kinds)" -ForegroundColor Green
    return $r
}

# 4) GET /.well-known/jwks → live JWKS baseline. Assert every kid in JWKS appears in admin
#    list AND has inJwks=true there — proves the live reader is honoured. Also catches a
#    private-material leak regression on the public endpoint.
$baselineJwks = Measure-Step "4. GET /.well-known/jwks -> live snapshot consistent with admin" {
    $r = Invoke-RestMethod -Method Get "$BASE/.well-known/jwks"
    if (-not $r.keys -or $r.keys.Count -lt 1) { throw "JWKS empty" }
    $jwksKids = $r.keys | ForEach-Object { $_.kid }
    foreach ($kid in $jwksKids) {
        $adminRow = $baselineAdmin.keys | Where-Object { $_.kid -eq $kid } | Select-Object -First 1
        if (-not $adminRow) { throw "JWKS exposes kid=$kid that is absent from admin list" }
        if (-not $adminRow.inJwks) { throw "JWKS exposes kid=$kid but admin reports inJwks=false" }
    }
    foreach ($jwk in $r.keys) {
        foreach ($priv in @('d','p','q','dp','dq','qi')) {
            if ($jwk.PSObject.Properties.Name -contains $priv -and $null -ne $jwk.$priv) {
                throw "JWKS LEAKED private component '$priv' for kid=$($jwk.kid)"
            }
        }
        if (-not $jwk.kid -or -not $jwk.n -or -not $jwk.e) {
            throw "JWKS entry malformed (kid/n/e missing): $(($jwk | ConvertTo-Json -Depth 3))"
        }
        if ($jwk.alg -ne "RS256") { throw "unexpected alg=$($jwk.alg) (only RS256 supported on this server)" }
        if ($jwk.use -ne "sig") { throw "unexpected use=$($jwk.use) (expected sig)" }
    }
    Write-Host "  $($jwksKids.Count) live JWKS kids, all match admin inJwks=true, no private material" -ForegroundColor Green
    return $r
}

# 5) Rotate. Assert response shape, NotAfter window, new kid not in baseline.
$rotResp = Measure-Step "5. POST /signing-keys/rotate -> new kid, NotAfter~now+90d, response shape" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/signing-keys/rotate" `
        -Headers $ADMIN -ContentType "application/json" -Body (@{ kind = "signing" } | ConvertTo-Json)
    if (-not $r.kid) { throw "rotate response missing kid" }
    if (-not $r.isActive) { throw "rotate response: isActive must be true on freshly-minted key" }
    if ($r.kind -ne "signing") { throw "rotate response: kind='$($r.kind)' (expected 'signing')" }
    if ($r.algorithm -ne "RS256") { throw "rotate response: algorithm='$($r.algorithm)' (expected RS256)" }
    $baselineKids = $baselineAdmin.keys | ForEach-Object { $_.kid }
    if ($baselineKids -contains $r.kid) { throw "rotate response: kid='$($r.kid)' is NOT new (already in baseline)" }
    $notAfter = if ($r.notAfter -is [DateTime]) {
        [DateTimeOffset]::new($r.notAfter.ToUniversalTime())
    } elseif ($r.notAfter -is [DateTimeOffset]) { $r.notAfter }
    else { [DateTimeOffset]::Parse($r.notAfter, [System.Globalization.CultureInfo]::InvariantCulture) }
    $delta = ($notAfter - [DateTimeOffset]::UtcNow).TotalDays
    if ($delta -lt 80 -or $delta -gt 100) {
        throw "NotAfter window suspicious: $delta days (expected ~90)"
    }
    Write-Host "  new kid = $($r.kid), NotAfter $([int]$delta) d out" -ForegroundColor Green
    return $r
}
$Knew = $rotResp.kid

# 6) Live JWKS now contains the new kid AND every previously-active signing kid (rotation grace).
$jwksAfterRotate = Measure-Step "6. JWKS contains new kid AND retains all previously-active signing kids" {
    $r = Invoke-RestMethod -Method Get "$BASE/.well-known/jwks"
    $kids = $r.keys | ForEach-Object { $_.kid }
    if ($kids -notcontains $Knew) { throw "new kid $Knew not in JWKS after rotate (live reader broken)" }
    $stillExpected = $baselineAdmin.keys |
        Where-Object { $_.kind -eq "signing" -and $_.isActive -and $_.inJwks } |
        ForEach-Object { $_.kid }
    foreach ($e in $stillExpected) {
        if ($kids -notcontains $e) {
            throw "previously-active kid $e dropped from JWKS prematurely (grace window broken)"
        }
    }
    Write-Host "  JWKS has $($kids.Count) kids, including new + retained" -ForegroundColor Green
    return $r
}

# 7) Admin list: new kid is the only isActive=true row for 'signing'; previously-active rows
#    are demoted to isActive=false but retain inJwks=true (within NotAfter window).
Measure-Step "7. admin list: new kid is sole isActive signing, previous demoted+inJwks" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/signing-keys" -Headers $ADMIN
    $newRow = $r.keys | Where-Object { $_.kid -eq $Knew } | Select-Object -First 1
    if (-not $newRow) { throw "new kid $Knew missing from admin list" }
    if (-not $newRow.isActive) { throw "new kid not flagged isActive=true in admin list" }
    if (-not $newRow.inJwks) { throw "new kid not flagged inJwks=true in admin list" }

    $activeSigning = @($r.keys | Where-Object { $_.kind -eq "signing" -and $_.isActive })
    if ($activeSigning.Count -ne 1) {
        throw "expected exactly 1 active 'signing' row after rotate, got $($activeSigning.Count)"
    }
    foreach ($prev in $baselineAdmin.keys | Where-Object { $_.kind -eq "signing" -and $_.isActive }) {
        $row = $r.keys | Where-Object { $_.kid -eq $prev.kid } | Select-Object -First 1
        if (-not $row) { throw "previously-active kid $($prev.kid) vanished from audit list" }
        if ($row.isActive) { throw "previously-active kid $($prev.kid) still flagged isActive=true after rotate" }
    }
    Write-Host "  exactly 1 active signing key; previous demoted but retained" -ForegroundColor Green
} | Out-Null

# 8) **Live-refresh proof.** Spin up a ROPC client + user, mint a token, assert kid==Knew.
#    This is THE batch 12 contract: rotate invalidates BOTH server and validation options
#    caches; PostConfigure re-runs against the new store snapshot; new tokens are minted
#    under the just-rotated kid immediately, without any process restart.
$liveRefreshUser = "rot_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$liveRefreshPwd  = "Test1234Pass!"
$liveRefreshReg  = Measure-Step "8a. DCR ROPC + register user (for kid-after-rotate probe)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "jwks-rotation-live-refresh"
            grant_types = @("password","refresh_token")
            scope       = "openid profile email offline_access identity:account"
        } | ConvertTo-Json)
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{ login = $liveRefreshUser; email = "$liveRefreshUser@example.com"; password = $liveRefreshPwd; displayName = $liveRefreshUser } | ConvertTo-Json) | Out-Null
    Write-Host "  client + user ready" -ForegroundColor Green
    return $r
}
$LR_RAT = $liveRefreshReg.registration_access_token
$LR_RCU = $liveRefreshReg.registration_client_uri

function Get-JwtHeader([string]$jwt) {
    $b64 = $jwt.Split('.')[0].Replace('-','+').Replace('_','/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json
}

Measure-Step "8b. ROPC AFTER rotate -> id_token.kid == Knew (live refresh, no restart)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $liveRefreshReg.client_id
            client_secret = $liveRefreshReg.client_secret
            username      = $liveRefreshUser
            password      = $liveRefreshPwd
            scope         = "openid profile email"
        }
    if (-not $t.id_token) { throw "no id_token from ROPC" }
    $hdr = Get-JwtHeader $t.id_token
    if ($hdr.kid -ne $Knew) {
        throw "id_token.kid='$($hdr.kid)' but expected just-rotated kid '$Knew' — IOptionsMonitor refresh broken"
    }
    Write-Host "  id_token.kid = $($hdr.kid) (matches Knew — refresh works)" -ForegroundColor Green
} | Out-Null

# 9) Rotate one more time so we have a fresh active key (K3) to keep signing under
#    AFTER we retire Knew (otherwise retiring our only active key would leave OpenIddict
#    unable to mint new tokens for subsequent demos).
$rotResp2 = Measure-Step "9. rotate again -> K3 active, Knew demoted (sets up retire test)" {
    $r = Invoke-RestMethod -Method Post "$BASE/api/v1/identity/signing-keys/rotate" `
        -Headers $ADMIN -ContentType "application/json" -Body (@{ kind = "signing" } | ConvertTo-Json)
    if (-not $r.kid) { throw "rotate 2 missing kid" }
    if ($r.kid -eq $Knew) { throw "second rotate returned same kid" }
    if (-not $r.isActive) { throw "second rotate: isActive=false" }
    Write-Host "  K3 = $($r.kid)" -ForegroundColor Green
    return $r
}
$Knewer = $rotResp2.kid

# 10) Retire Knew (now demoted, never the active key — clean target).
Measure-Step "10. DELETE /signing-keys/{Knew} -> success" {
    $r = Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/signing-keys/$Knew" -Headers $ADMIN
    if (-not $r.success) { throw "retire response not success-shaped: $($r | ConvertTo-Json -Depth 3)" }
    Write-Host "  retired Knew" -ForegroundColor Green
} | Out-Null

# 11) **Live-refresh post-retire.** Mint another token; kid must be K3 (the new active),
#     proving retire propagated through OpenIddict's cache too.
Measure-Step "11. ROPC AFTER retire -> id_token.kid == K3 (OpenIddict drops retired key)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $liveRefreshReg.client_id
            client_secret = $liveRefreshReg.client_secret
            username      = $liveRefreshUser
            password      = $liveRefreshPwd
            scope         = "openid profile email"
        }
    if (-not $t.id_token) { throw "no id_token from ROPC after retire" }
    $hdr = Get-JwtHeader $t.id_token
    if ($hdr.kid -eq $Knew) { throw "id_token.kid still == retired Knew '$Knew' — OpenIddict cache not invalidated on retire" }
    if ($hdr.kid -ne $Knewer) { throw "id_token.kid='$($hdr.kid)', expected K3='$Knewer'" }
    Write-Host "  id_token.kid = $($hdr.kid) (matches K3, retired key dropped)" -ForegroundColor Green
} | Out-Null

# 12) Live JWKS no longer contains the retired kid.
Measure-Step "12. JWKS no longer contains retired Knew" {
    $r = Invoke-RestMethod -Method Get "$BASE/.well-known/jwks"
    $kids = $r.keys | ForEach-Object { $_.kid }
    if ($kids -contains $Knew) { throw "retired kid $Knew still in JWKS" }
    if ($kids -notcontains $Knewer) { throw "K3=$Knewer missing from JWKS after retire of Knew" }
    Write-Host "  retired kid gone (remaining: $($kids.Count))" -ForegroundColor Green
} | Out-Null

# 13) Admin list still carries the retired kid as audit trail, with inJwks=false now.
Measure-Step "13. admin list audit trail: retired kid stays with inJwks=false" {
    $r = Invoke-RestMethod -Method Get "$BASE/api/v1/identity/signing-keys" -Headers $ADMIN
    $row = $r.keys | Where-Object { $_.kid -eq $Knew } | Select-Object -First 1
    if (-not $row) { throw "retired kid $Knew vanished from admin audit trail" }
    if ($row.inJwks) { throw "retired kid still reports inJwks=true" }
    if ($row.isActive) { throw "retired kid still reports isActive=true" }
    Write-Host "  kid retained on audit trail (inJwks=false, isActive=false)" -ForegroundColor Green
} | Out-Null

# 14) Idempotence: re-retiring the same kid is a 200 no-op or 4xx, never 500.
Measure-Step "14. DELETE same kid again -> idempotent (no 500)" {
    try {
        $r = Invoke-RestMethod -Method Delete "$BASE/api/v1/identity/signing-keys/$Knew" -Headers $ADMIN
        Write-Host "  second retire returned without throwing" -ForegroundColor Green
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -ge 500) { throw "second retire returned $code (endpoint not idempotent / server bug)" }
        Write-Host "  second retire returned HTTP $code (non-success ok)" -ForegroundColor Green
    }
} | Out-Null

# 15) Cleanup.
Measure-Step "15. RFC 7592 DELETE admin + ROPC registrations" {
    if ($ADMIN_RAT) { Invoke-RestMethod -Method Delete -Uri $ADMIN_RCU -Headers @{ Authorization = "Bearer $ADMIN_RAT" } | Out-Null }
    if ($LR_RAT)    { Invoke-RestMethod -Method Delete -Uri $LR_RCU    -Headers @{ Authorization = "Bearer $LR_RAT" }    | Out-Null }
    Write-Host "  registrations deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
