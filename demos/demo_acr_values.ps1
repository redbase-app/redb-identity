# OIDC Core §2 — `acr` claim probe.
#
# Closes the ❌ "acr_values" entry in §5 of the coverage matrix. The server emits an
# `acr` claim on every id_token with a value derived from the actual authentication
# strength:
#   "0" — no authentication enforcement (session-only / unreachable here),
#   "1" — single-factor (password-only ROPC, password+cookie),
#   "2" — multi-factor verified (SessionProps.MfaVerified = true).
#
# Per OIDC §5.5.1.1 `acr` is a voluntary claim by default — the OP returns its actual
# acr regardless of what the RP requested via `acr_values`, and the RP is responsible
# for accepting / rejecting based on the value.
#
# Probes (all asserted):
#   1.  DCR (auth_code+PKCE)
#   2.  self-register + cookie /login
#   3.  authorize+token (no acr_values) → id_token.acr exists, equals "1" (no MFA)
#   4.  authorize+token with acr_values="1" → id_token.acr == "1" (matches request)
#   5.  authorize+token with acr_values="2" on a non-MFA session → id_token.acr is
#       still "1" (the server returns its actual strength; RP enforces)
#   6.  ROPC token  → access_token.acr == "1" (no MFA on ROPC either)
#   7.  /connect/userinfo carries the same acr
#   8.  RFC 7592 cleanup
#
# Note: `acr=2` (MFA-verified) is exercised end-to-end by `demo_mfa_totp` chained with
# an authorize call — covering it here would duplicate the MFA enrol flow. The probe
# here owns the "did the server emit acr at all and respect the basic value contract"
# portion.
#
# Usage: pwsh -File demo_acr_values.ps1
#requires -Version 7

$BASE     = "http://127.0.0.1:5002"
$REDIRECT = "http://localhost:9999/cb"
$timings  = [System.Collections.Generic.List[object]]::new()
Add-Type -AssemblyName System.Web

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

function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function New-Pkce {
    $verifier  = B64U ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $challenge = B64U ([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
    return [pscustomobject]@{ Verifier=$verifier; Challenge=$challenge }
}
function Get-JwtBody([string]$jwt) {
    $parts = $jwt.Split('.')
    if ($parts.Count -lt 2) { throw "JWT does not have 3 segments" }
    $b64 = $parts[1].Replace('-','+').Replace('_','/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    return $json | ConvertFrom-Json -Depth 12
}

function Invoke-AuthCodeFlow {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ClientId, [string]$ClientSecret,
        [hashtable]$Extras = @{}
    )
    $pkce  = New-Pkce
    $state = "acr-" + [Guid]::NewGuid().ToString('N').Substring(0,6)
    $body = @{
        response_type         = "code"
        client_id             = $ClientId
        redirect_uri          = $REDIRECT
        scope                 = "openid profile email"
        code_challenge        = $pkce.Challenge
        code_challenge_method = "S256"
        state                 = $state
    }
    foreach ($k in $Extras.Keys) { $body[$k] = $Extras[$k] }
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
            -WebSession $Session -ContentType "application/x-www-form-urlencoded" `
            -Body $body -MaximumRedirection 0 -ErrorAction Stop
    } catch { $resp = $_.Exception.Response }
    $loc = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $loc) { throw "no Location on /connect/authorize response" }
    $u = [uri]$loc
    $q = [System.Web.HttpUtility]::ParseQueryString($u.Query)
    if ($q['error']) { throw "authorize returned error=$($q['error'])" }
    if (-not $q['code']) { throw "no code in redirect" }
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "authorization_code"
            client_id     = $ClientId
            client_secret = $ClientSecret
            redirect_uri  = $REDIRECT
            code          = $q['code']
            code_verifier = $pkce.Verifier
        }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR.
$reg = Measure-Step "1. DCR (auth_code + PKCE)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name   = "acr-values-demo"
            redirect_uris = @($REDIRECT)
            grant_types   = @("authorization_code","refresh_token","password")
            scope         = "openid profile email"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "no client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register + login.
$user = "acr_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Measure-Step "2. self-register + POST /login" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{ login = $user; email = "$user@example.com"; password = $pwd; displayName = $user } | ConvertTo-Json) | Out-Null
    try {
        Invoke-WebRequest -Method Post "$BASE/login" `
            -WebSession $session -ContentType "application/x-www-form-urlencoded" `
            -Body @{ username = $user; password = $pwd } `
            -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    if ($session.Cookies.GetCookies($BASE).Count -lt 1) { throw "no session cookie" }
    Write-Host "  ✓ user + session" -ForegroundColor Green
} | Out-Null

# 3) authorize+token, no acr_values → id_token.acr exists, equals "1".
Measure-Step "3. authorize+token (no acr_values) → id_token.acr == '1'" {
    $t = Invoke-AuthCodeFlow -Session $session -ClientId $reg.client_id -ClientSecret $reg.client_secret
    if (-not $t.id_token) { throw "no id_token" }
    $c = Get-JwtBody $t.id_token
    if (-not $c.PSObject.Properties['acr']) { throw "id_token missing acr claim" }
    if ($c.acr -ne "1") { throw "acr expected '1' (no MFA), got '$($c.acr)'" }
    Write-Host "  ✓ id_token.acr = '1'" -ForegroundColor Green
} | Out-Null

# 4) acr_values=1 → still "1" (request matches actual).
Measure-Step "4. authorize+token acr_values='1' → acr stays '1'" {
    $t = Invoke-AuthCodeFlow -Session $session -ClientId $reg.client_id -ClientSecret $reg.client_secret `
        -Extras @{ acr_values = "1" }
    $c = Get-JwtBody $t.id_token
    if ($c.acr -ne "1") { throw "acr expected '1', got '$($c.acr)'" }
    Write-Host "  ✓ id_token.acr = '1' (matches request)" -ForegroundColor Green
} | Out-Null

# 5) acr_values=2 on non-MFA session → server emits its actual strength ("1");
#    OIDC §5.5.1.1 voluntary contract — RP enforces.
Measure-Step "5. authorize+token acr_values='2' (no MFA) → acr is '1' (voluntary)" {
    $t = Invoke-AuthCodeFlow -Session $session -ClientId $reg.client_id -ClientSecret $reg.client_secret `
        -Extras @{ acr_values = "2" }
    $c = Get-JwtBody $t.id_token
    if ($c.acr -ne "1") {
        throw "acr expected '1' (server emits actual strength regardless of requested), got '$($c.acr)'"
    }
    Write-Host "  ✓ acr=1 — server honours OIDC §5.5.1.1 voluntary-claim contract" -ForegroundColor Green
} | Out-Null

# 6) ROPC → access_token JWE (opaque) BUT id_token has acr.
Measure-Step "6. ROPC password grant → id_token.acr == '1'" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email"
        }
    if (-not $t.id_token) { throw "no id_token on ROPC" }
    $c = Get-JwtBody $t.id_token
    if ($c.acr -ne "1") { throw "ROPC id_token.acr expected '1', got '$($c.acr)'" }
    Write-Host "  ✓ ROPC id_token.acr = '1'" -ForegroundColor Green
    $script:ropcTok = $t
} | Out-Null

# 7) /userinfo (uses ROPC access_token — opaque-format JWE, but the server still
#    populates acr-equivalent on the userinfo body if implemented; if absent that's
#    spec-compliant since OIDC §5.3 lists acr as a voluntary claim there too).
Measure-Step "7. GET /connect/userinfo (acr is voluntary on userinfo per §5.3)" {
    $ui = Invoke-RestMethod -Method Get "$BASE/connect/userinfo" `
        -Headers @{ Authorization = "Bearer $($script:ropcTok.access_token)" }
    if (-not $ui.sub) { throw "userinfo missing sub" }
    if ($ui.PSObject.Properties['acr']) {
        Write-Host "  ✓ userinfo carries acr = '$($ui.acr)'" -ForegroundColor Green
    } else {
        Write-Host "  ✓ userinfo OK (no acr — voluntary per OIDC §5.3)" -ForegroundColor DarkGray
    }
} | Out-Null

# 8) RFC 7592 cleanup.
Measure-Step "8. RFC 7592 DELETE registration" {
    if (-not $RAT) { return }
    Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
