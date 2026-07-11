# Auth-code response extras — locks 4 advertised but un-probed surfaces:
#   1. RFC 9207 iss in auth-response (authorization_response_iss_parameter_supported: true)
#   2. prompt=none on no session → error redirect with error=login_required (OIDC §3.1.2.1)
#   3. response_mode=form_post → HTML auto-submit form with code (OIDC FAPI / form-post)
#   4. response_mode=fragment → redirect with #code= (legacy implicit/hybrid carrier)
# Builds on the same session+DCR setup as demo_authcode_pkce.ps1.
# Usage: pwsh -File demo_auth_extras.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
$REDIRECT = $REDIRECT_CB
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

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function New-Pkce {
    $verifierBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($verifierBytes)
    $verifier = ConvertTo-Base64Url $verifierBytes
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $challenge = ConvertTo-Base64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ verifier=$verifier; challenge=$challenge }
}

# Helper: call /connect/authorize, capture the raw response (status, Location header, body).
function Invoke-Authorize {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession] $sess,
        [hashtable] $body
    )
    try {
        return Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
          -WebSession $sess `
          -ContentType "application/x-www-form-urlencoded" `
          -Body $body -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        if ($_.Exception.Response) {
            $r = $_.Exception.Response
            $loc = $null
            if ($r.Headers.Location) { $loc = $r.Headers.Location.ToString() }
            return [pscustomobject]@{
                StatusCode = [int]$r.StatusCode
                Headers    = @{ Location = $loc }
                Content    = ""
            }
        }
        # PowerShell 7.4+ surfaces redirect-when-MaxRedirection-0 as RedirectException.
        return Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
          -WebSession $sess `
          -ContentType "application/x-www-form-urlencoded" `
          -Body $body -MaximumRedirection 0 -SkipHttpErrorCheck
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 0) DCR — register a confidential code+PKCE client.
$reg = Measure-Step "0. DCR (authorization_code + PKCE)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" `
      -ContentType "application/json" `
      -Body (@{
        client_name   = "auth-extras-demo"
        redirect_uris = @($REDIRECT)
        grant_types   = @("authorization_code","refresh_token")
        scope         = "openid profile email offline_access"
      } | ConvertTo-Json)
}
Write-Host "  client_id : $($reg.client_id)"

# 1) Seed user + cookie session.
$user = "ae_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$pwd  = "Test1234Pass!"
Measure-Step "1. account/register + /login" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
      -ContentType "application/json" `
      -Body (@{ login=$user; email="$user@example.com"; password=$pwd; displayName=$user } | ConvertTo-Json) | Out-Null
} | Out-Null

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Measure-Step "  /login (cookie jar)" {
    try {
        Invoke-WebRequest -Method Post "$BASE/login" `
          -WebSession $session `
          -ContentType "application/x-www-form-urlencoded" `
          -Body @{ username=$user; password=$pwd } `
          -MaximumRedirection 0 -ErrorAction Stop | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -notin 200,302) { throw }
    }
    if ($session.Cookies.GetCookies("$BASE").Count -lt 1) { throw "no session cookie" }
} | Out-Null

# ─── Probe A: RFC 9207 iss in auth-response (response_mode=query, default) ────────
Measure-Step "A. RFC 9207 — iss=... in auth-response Location" {
    $pkce = New-Pkce
    $resp = Invoke-Authorize $session @{
        response_type         = "code"
        client_id             = $reg.client_id
        redirect_uri          = $REDIRECT
        scope                 = "openid"
        code_challenge        = $pkce.challenge
        code_challenge_method = "S256"
        state                 = "rfc9207"
        nonce                 = [Guid]::NewGuid().ToString('N')
    }
    $loc = if ($resp.Headers.Location -is [string]) { $resp.Headers.Location } else { ($resp.Headers.Location | Select-Object -First 1).ToString() }
    if (-not $loc) { throw "no Location header" }
    if ($loc -notmatch '[?&]iss=([^&]+)') {
        throw "auth-response Location has no iss= parameter (RFC 9207 advertised but not emitted): $loc"
    }
    $issEnc = $Matches[1]
    $issDec = [Uri]::UnescapeDataString($issEnc)
    Write-Host "  iss : $issDec"
    if ($issDec -notmatch '^https?://') { throw "iss is not an absolute URL: $issDec" }
    if ($loc -notmatch '[?&]code=') { throw "auth-response Location missing code=" }
    Write-Host "  ✓ iss + code + state all present" -ForegroundColor Green
} | Out-Null

# ─── Probe B: prompt=none → must redirect with error if no decision possible ─────
# OIDC §3.1.2.6: when prompt=none and the user can't be authenticated silently OR
# consent is needed, server MUST return login_required / consent_required / interaction_required.
# In our setup user IS logged in via session, so prompt=none should succeed silently.
# To force the error, we use a FRESH session (no cookies) — server should redirect with error.
Measure-Step "B. prompt=none with no session → error=login_required" {
    $pkce = New-Pkce
    $emptySession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $resp = Invoke-Authorize $emptySession @{
        response_type         = "code"
        client_id             = $reg.client_id
        redirect_uri          = $REDIRECT
        scope                 = "openid"
        code_challenge        = $pkce.challenge
        code_challenge_method = "S256"
        state                 = "promptnone"
        prompt                = "none"
    }
    $loc = if ($resp.Headers.Location -is [string]) { $resp.Headers.Location } else { ($resp.Headers.Location | Select-Object -First 1).ToString() }
    Write-Host "  status   : $($resp.StatusCode)"
    Write-Host "  location : $loc"
    if (-not $loc) { throw "expected error redirect, got no Location (status $($resp.StatusCode))" }
    if ($loc -notmatch '[?&#]error=([^&]+)') {
        throw "prompt=none with no session did NOT return error= (got: $loc) — server allowed silent auth without a user"
    }
    $err = [Uri]::UnescapeDataString($Matches[1])
    $allowed = @('login_required','interaction_required','consent_required','account_selection_required')
    if ($allowed -notcontains $err) {
        throw "prompt=none returned unexpected error: $err (expected one of: $($allowed -join ', '))"
    }
    Write-Host "  ✓ error = $err (RFC-compliant)" -ForegroundColor Green
} | Out-Null

# ─── Probe C: response_mode=form_post → HTML auto-submit with code ───────────────
Measure-Step "C. response_mode=form_post → HTML form-post body" {
    $pkce = New-Pkce
    $resp = Invoke-Authorize $session @{
        response_type         = "code"
        response_mode         = "form_post"
        client_id             = $reg.client_id
        redirect_uri          = $REDIRECT
        scope                 = "openid"
        code_challenge        = $pkce.challenge
        code_challenge_method = "S256"
        state                 = "formpost"
        nonce                 = [Guid]::NewGuid().ToString('N')
    }
    Write-Host "  status : $($resp.StatusCode)"
    $body = if ($resp.Content) { $resp.Content } else { "" }
    if ($resp.StatusCode -ne 200) {
        throw "form_post should return 200 with HTML body, got $($resp.StatusCode)"
    }
    if ($body -notmatch '(?i)<form[^>]*method=["'']?post["'']?') {
        throw "form_post body has no <form method=post>: $($body.Substring(0, [Math]::Min(200, $body.Length)))…"
    }
    if ($body -notmatch '(?i)action=["'']?' + [regex]::Escape($REDIRECT)) {
        throw "form_post form action does not target redirect_uri ($REDIRECT)"
    }
    if ($body -notmatch '(?i)name=["'']?code["'']?') {
        throw "form_post body has no code field"
    }
    Write-Host "  ✓ HTML form posts code to $REDIRECT" -ForegroundColor Green
} | Out-Null

# ─── Probe D: response_mode=fragment → redirect with #code= (not ?code=) ─────────
Measure-Step "D. response_mode=fragment → Location with #code=" {
    $pkce = New-Pkce
    $resp = Invoke-Authorize $session @{
        response_type         = "code"
        response_mode         = "fragment"
        client_id             = $reg.client_id
        redirect_uri          = $REDIRECT
        scope                 = "openid"
        code_challenge        = $pkce.challenge
        code_challenge_method = "S256"
        state                 = "fragmode"
        nonce                 = [Guid]::NewGuid().ToString('N')
    }
    $loc = if ($resp.Headers.Location -is [string]) { $resp.Headers.Location } else { ($resp.Headers.Location | Select-Object -First 1).ToString() }
    if (-not $loc) { throw "no Location header" }
    Write-Host "  location : $loc"
    $hashIdx = $loc.IndexOf('#')
    if ($hashIdx -lt 0) {
        throw "response_mode=fragment did NOT use # carrier — params on query instead: $loc"
    }
    $frag = $loc.Substring($hashIdx + 1)
    if ($frag -notmatch '(?:^|&)code=') {
        throw "fragment carrier has no code= : $frag"
    }
    Write-Host "  ✓ code delivered in URL fragment" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
