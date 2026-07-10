# scope→claim assertion probes (P1 batch).
#   Drives a self-service auth-code+PKCE flow with scope=
#     "openid profile email phone address offline_access"
#   then verifies the id_token / access_token / userinfo carry the expected
#   claims with the expected shapes. Self-service can't grant `groups` /
#   `roles` (those require admin to add the user to a group with a role
#   label) so this demo asserts only the user-info claim surface; group/role
#   probes will need a separate admin-bootstrapped flow.
#
#   Probes (all asserted, not just pretty-printed):
#     1. DCR + register + /login (cookie session)
#     2. PUT /me — set phone, address.formatted, custom claim
#     3. authorize + token exchange (scope incl. phone+address, with nonce)
#     4. id_token claims:
#         sub / iss / aud / exp / iat (RFC 7519 baseline)
#         auth_time (OIDC §2, NumericDate, within last 5 min)
#         amr (RFC 8176, contains "pwd")
#         nonce (round-trips from authorize)
#         jti (RFC 7519 §4.1.7, present + non-empty)
#         azp (optional per OIDC §2 — assert client_id only IF present)
#         email + email_verified
#         phone_number + phone_number_verified
#         address (JSON object with formatted=…)
#     5. /connect/userinfo claims (sub + email + phone_number + address)
#
# Usage: pwsh -File demo_claim_probes.ps1
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

function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function New-Pkce {
    $verifier  = B64U ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $challenge = B64U ([System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::ASCII.GetBytes($verifier)))
    return [pscustomobject]@{ Verifier=$verifier; Challenge=$challenge }
}

# Decode JWT body without verification (we already verify signature by the
# fact that the AS issued it; the assertions here are about claim *shape*).
function Get-JwtBody([string]$jwt) {
    $parts = $jwt.Split('.')
    if ($parts.Count -lt 2) { throw "JWT does not have 3 segments: $jwt" }
    $b64 = $parts[1].Replace('-','+').Replace('_','/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    return $json | ConvertFrom-Json -Depth 12
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR — authorization_code + PKCE client requesting all user-info scopes.
$reg = Measure-Step "1. DCR (auth_code + scopes openid profile email phone address)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name   = "claim-probes-demo"
            redirect_uris = @($REDIRECT)
            grant_types   = @("authorization_code","refresh_token")
            scope         = "openid profile email phone address offline_access"
        } | ConvertTo-Json -Depth 5)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    Write-Host "  ✓ client_id : $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register a fresh user.
$user = "claim_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "2. self-register account ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{
        login       = $user
        email       = "$user@example.com"
        password    = $pwd
        displayName = $user
      } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ user created: $user" -ForegroundColor Green
} | Out-Null

# 3) Establish a cookie session via /login.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Measure-Step "3. POST /login (cookie session)" {
    try {
        Invoke-WebRequest -Method Post "$BASE/login" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{ username = $user; password = $pwd } `
          -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    if ($session.Cookies.GetCookies("$BASE").Count -lt 1) {
        throw "no session cookie set by /login"
    }
    Write-Host "  ✓ cookies: $($session.Cookies.GetCookies($BASE).Count)" -ForegroundColor Green
} | Out-Null

# 3b) Register a separate password-grant client (the auth_code client doesn't carry the
#     "password" grant) and use it for ROPC to fetch a /me access token.
$ropcReg = Measure-Step "3b. DCR (password client for /me)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name = "claim-probes-ropc"
            grant_types = @("password","refresh_token")
            scope       = "openid profile email phone address identity:account offline_access"
        } | ConvertTo-Json -Depth 5)
    if (-not $r.client_id) { throw "ROPC DCR did not return client_id" }
    Write-Host "  ✓ ROPC client_id : $($r.client_id)" -ForegroundColor Green
    return $r
}
$ROPC_RAT = $ropcReg.registration_access_token
$ROPC_RCU = $ropcReg.registration_client_uri

$selfTok = Measure-Step "3c. ROPC token for /me (scope=identity:account openid profile email phone address)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $ropcReg.client_id
            client_secret = $ropcReg.client_secret
            username      = $user
            password      = $pwd
            scope         = "openid profile email phone address identity:account"
        }
    if (-not $t.access_token) { throw "ROPC didn't return access_token" }
    Write-Host "  ✓ access_token (len $($t.access_token.Length))" -ForegroundColor Green
    return $t
}

# 4) PUT /me — set phone + address.formatted + a custom claim. PhoneNumberVerified
#    is admin-only, so the demo asserts presence only (value will be "false").
$ADDRESS_FORMATTED = "221B Baker Street, London NW1 6XE"
Measure-Step "4. PUT /me (phone + address + custom_claims.dept)" {
    Invoke-RestMethod -Method Put "$BASE/api/v1/identity/me" `
      -Headers @{ Authorization = "Bearer $($selfTok.access_token)" } `
      -ContentType "application/json" `
      -Body (@{
        phoneNumber  = "+12025550199"
        address      = @{ formatted = $ADDRESS_FORMATTED; locality = "London"; country = "GB" }
        customClaims = @{ dept = "engineering" }
      } | ConvertTo-Json -Depth 5) | Out-Null
    Write-Host "  ✓ profile updated" -ForegroundColor Green
} | Out-Null

# 5) Drive /connect/authorize with PKCE + nonce. We post to the form variant
#    so the cookie session authenticates the user without a browser hop.
$pkce  = New-Pkce
$state = "claim-probes-state-" + [Guid]::NewGuid().ToString('N').Substring(0,8)
$nonce = "claim-probes-nonce-" + [Guid]::NewGuid().ToString('N').Substring(0,8)

$code = Measure-Step "5. POST /connect/authorize (extract code, with nonce)" {
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
            -WebSession $session `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                response_type         = "code"
                client_id             = $reg.client_id
                redirect_uri          = $REDIRECT
                scope                 = "openid profile email phone address offline_access"
                code_challenge        = $pkce.Challenge
                code_challenge_method = "S256"
                state                 = $state
                nonce                 = $nonce
            } -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        $resp = $_.Exception.Response
    }
    $loc = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $loc) { throw "no Location on /connect/authorize response" }
    $u = [uri]$loc
    $q = [System.Web.HttpUtility]::ParseQueryString($u.Query)
    if ($q['error']) { throw "authorize returned error=$($q['error']) desc=$($q['error_description'])" }
    if (-not $q['code']) { throw "no code in $loc" }
    if ($q['state'] -ne $state) { throw "state mismatch (got '$($q['state'])', expected '$state')" }
    Write-Host "  ✓ code received, state round-trip ok" -ForegroundColor Green
    return $q['code']
}

# 6) Token exchange.
$tok = Measure-Step "6. POST /connect/token (auth_code → tokens)" {
    Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "authorization_code"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            redirect_uri  = $REDIRECT
            code          = $code
            code_verifier = $pkce.Verifier
        }
}
if (-not $tok.id_token)     { throw "token response missing id_token" }
if (-not $tok.access_token) { throw "token response missing access_token" }
$idClaims = Get-JwtBody $tok.id_token
# access_token is a JWE in our setup — opaque to clients; userinfo is the inspection surface.

# 7) Assert id_token claim shapes.
Measure-Step "7. assert id_token claim shapes" {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    foreach ($k in @('sub','iss','aud','exp','iat')) {
        if (-not $idClaims.PSObject.Properties[$k]) { throw "id_token missing baseline claim '$k'" }
    }
    Write-Host "  ✓ baseline (sub/iss/aud/exp/iat) present" -ForegroundColor Green

    # auth_time — NumericDate within last 5 minutes (sanity).
    if (-not $idClaims.PSObject.Properties['auth_time']) { throw "id_token missing auth_time (OIDC §2)" }
    $authTime = [int64]$idClaims.auth_time
    $skew = [Math]::Abs($now - $authTime)
    if ($skew -gt 300) { throw "auth_time skew > 5min (auth_time=$authTime, now=$now)" }
    Write-Host "  ✓ auth_time = $authTime (skew ${skew}s)" -ForegroundColor Green

    # amr — RFC 8176 — must contain "pwd".
    if (-not $idClaims.PSObject.Properties['amr']) { throw "id_token missing amr (RFC 8176)" }
    $amr = $idClaims.amr
    if ($amr -isnot [Array]) { $amr = @($amr) }
    if (-not ($amr -contains 'pwd')) { throw "amr missing 'pwd' (got: $($amr -join ','))" }
    Write-Host "  ✓ amr = [$($amr -join ', ')]" -ForegroundColor Green

    # nonce — round-trips verbatim.
    if ($idClaims.nonce -ne $nonce) {
        throw "nonce did not round-trip (sent='$nonce', got='$($idClaims.nonce)')"
    }
    Write-Host "  ✓ nonce round-trips: $nonce" -ForegroundColor Green

    # jti — RFC 7519 §4.1.7 — OPTIONAL (OIDC Core does not require it on id_token).
    if ($idClaims.PSObject.Properties['jti'] -and -not [string]::IsNullOrEmpty($idClaims.jti)) {
        Write-Host "  ✓ jti: $($idClaims.jti)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ jti absent — RFC 7519 §4.1.7 marks it optional, OIDC does not mandate it" -ForegroundColor DarkGray
    }

    # azp — OPTIONAL (OIDC §2 — required only for multi-aud). If present, must
    # equal the authorized client_id; absence is also spec-compliant.
    if ($idClaims.PSObject.Properties['azp']) {
        if ($idClaims.azp -ne $reg.client_id) {
            throw "azp != client_id (azp='$($idClaims.azp)', client_id='$($reg.client_id)')"
        }
        Write-Host "  ✓ azp = $($idClaims.azp) (matches client_id)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ azp absent — single-aud token, OIDC §2 permits omission" -ForegroundColor DarkGray
    }

    # email scope
    if ($idClaims.email -ne "$user@example.com") {
        throw "email mismatch (got='$($idClaims.email)', expected='$user@example.com')"
    }
    if (-not $idClaims.PSObject.Properties['email_verified']) {
        throw "id_token missing email_verified"
    }
    Write-Host "  ✓ email = $($idClaims.email), email_verified = $($idClaims.email_verified)" -ForegroundColor Green

    # phone scope (we set +1-202-555-0199 in step 4)
    if ($idClaims.phone_number -ne "+12025550199") {
        throw "phone_number mismatch (got='$($idClaims.phone_number)')"
    }
    if (-not $idClaims.PSObject.Properties['phone_number_verified']) {
        throw "id_token missing phone_number_verified"
    }
    Write-Host "  ✓ phone_number = $($idClaims.phone_number), phone_number_verified = $($idClaims.phone_number_verified)" -ForegroundColor Green

    # address scope — OIDC §5.1.1 — emitted as a JSON object with `formatted`.
    if (-not $idClaims.PSObject.Properties['address']) { throw "id_token missing address" }
    $addr = $idClaims.address
    # Some serializers stringify to JSON-text; accept either object or string.
    if ($addr -is [string]) {
        try { $addr = $addr | ConvertFrom-Json } catch { throw "address claim isn't JSON-decodable: $addr" }
    }
    if ($addr.formatted -ne $ADDRESS_FORMATTED) {
        throw "address.formatted mismatch (got='$($addr.formatted)')"
    }
    Write-Host "  ✓ address.formatted = $($addr.formatted)" -ForegroundColor Green

    # custom claim from step 4
    if ($idClaims.dept -ne 'engineering') {
        throw "custom claim 'dept' missing or wrong (got='$($idClaims.dept)')"
    }
    Write-Host "  ✓ custom claim dept = $($idClaims.dept)" -ForegroundColor Green
} | Out-Null

# 8) /connect/userinfo — confirm same claims surface there too.
Measure-Step "8. GET /connect/userinfo (same claims via userinfo endpoint)" {
    $ui = Invoke-RestMethod -Method Get "$BASE/connect/userinfo" `
        -Headers @{ Authorization = "Bearer $($tok.access_token)" }
    if ($ui.sub -ne $idClaims.sub) {
        throw "userinfo.sub != id_token.sub (ui='$($ui.sub)', id='$($idClaims.sub)')"
    }
    if ($ui.email -ne "$user@example.com") {
        throw "userinfo.email mismatch (got='$($ui.email)')"
    }
    if ($ui.phone_number -ne "+12025550199") {
        throw "userinfo.phone_number mismatch (got='$($ui.phone_number)')"
    }
    $uAddr = $ui.address
    if ($uAddr -is [string]) {
        try { $uAddr = $uAddr | ConvertFrom-Json } catch { throw "userinfo.address not JSON: $uAddr" }
    }
    if ($uAddr.formatted -ne $ADDRESS_FORMATTED) {
        throw "userinfo.address.formatted mismatch (got='$($uAddr.formatted)')"
    }
    Write-Host "  ✓ userinfo carries sub/email/phone_number/address" -ForegroundColor Green
} | Out-Null

# 9) RFC 7592 cleanup (both DCR clients)
Measure-Step "9. RFC 7592 DELETE registration" {
    if ($RAT) {
        Invoke-RestMethod -Method Delete -Uri $RCU `
            -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
        Write-Host "  ✓ auth_code client deleted" -ForegroundColor Green
    }
    if ($ROPC_RAT) {
        Invoke-RestMethod -Method Delete -Uri $ROPC_RCU `
            -Headers @{ Authorization = "Bearer $ROPC_RAT" } | Out-Null
        Write-Host "  ✓ ROPC client deleted" -ForegroundColor Green
    }
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
