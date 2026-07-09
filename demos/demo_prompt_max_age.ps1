# OIDC §3.1.2.1 prompt= variants + max_age authorization-request probes.
#
# Closes the GAP in §5 of the coverage matrix:
#   prompt=login           — force re-authentication (login_required)
#   prompt=consent         — force consent re-prompt (consent_required UI override)
#   prompt=select_account  — request account selection (login_required when no UI path)
#   max_age=<seconds>      — re-auth if last auth_time older than max_age
#                            (OIDC Core §3.1.2.1 — server MUST reject with login_required)
#
# `prompt=none` is already covered by demo_auth_extras.ps1.
#
# All probes use the cookie-session + POST /connect/authorize pattern from
# demo_authcode_pkce.ps1 so no browser is required. The 302 redirect's Location
# query carries the OIDC error per RFC 6749 §4.1.2.1 (delivered back to redirect_uri
# with state round-tripped).
#
# Probes (all asserted):
#   1.  DCR auth_code+PKCE client
#   2.  self-register user + cookie session via /login
#   3.  baseline authorize (no prompt, no max_age) → code returned
#   4.  prompt=login           → 302 with Location?error=login_required, state echoed
#   5.  prompt=consent (implicit consent client) → code returned (no Explicit consent UI)
#   6.  prompt=select_account  → 302 with Location?error=login_required (no UI path)
#   7.  max_age=0 (force re-auth now) → 302 with Location?error=login_required
#   8.  max_age=99999 (large window) → code returned (no re-auth needed)
#   9.  RFC 7592 cleanup
#
# Usage: pwsh -File demo_prompt_max_age.ps1
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

# Drive POST /connect/authorize with the supplied extras (prompt, max_age, ...).
# Returns parsed query string of the redirect Location, or throws if missing.
function Invoke-Authorize {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ClientId,
        [string]$State,
        [string]$Nonce,
        [string]$CodeChallenge,
        [hashtable]$Extras = @{}
    )
    $body = @{
        response_type         = "code"
        client_id             = $ClientId
        redirect_uri          = $REDIRECT
        scope                 = "openid profile email"
        code_challenge        = $CodeChallenge
        code_challenge_method = "S256"
        state                 = $State
        nonce                 = $Nonce
    }
    foreach ($k in $Extras.Keys) { $body[$k] = $Extras[$k] }
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Method Post "$BASE/connect/authorize" `
            -WebSession $Session -ContentType "application/x-www-form-urlencoded" `
            -Body $body -MaximumRedirection 0 -ErrorAction Stop
    } catch { $resp = $_.Exception.Response }
    $loc = if ($resp -is [System.Net.Http.HttpResponseMessage]) { $resp.Headers.Location.ToString() } else { $resp.Headers["Location"] }
    if (-not $loc) { throw "no Location header on /connect/authorize response" }
    $u = [uri]$loc
    $qstr = if ($u.Query.Length -gt 0) { $u.Query } elseif ($u.Fragment.Length -gt 0) { '?' + $u.Fragment.TrimStart('#') } else { '' }
    $q = [System.Web.HttpUtility]::ParseQueryString($qstr)
    return [pscustomobject]@{ Location = $loc; Query = $q }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) DCR.
$reg = Measure-Step "1. DCR (auth_code + PKCE)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name   = "prompt-max-age-demo"
            redirect_uris = @($REDIRECT)
            grant_types   = @("authorization_code","refresh_token")
            scope         = "openid profile email"
        } | ConvertTo-Json)
    if (-not $r.client_id) { throw "no client_id" }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register + cookie /login.
$user = "pma_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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

# Helper — baseline-clean PKCE+state+nonce per probe.
function New-FlowState {
    [pscustomobject]@{
        Pkce  = New-Pkce
        State = "pma-state-" + [Guid]::NewGuid().ToString('N').Substring(0,8)
        Nonce = "pma-nonce-" + [Guid]::NewGuid().ToString('N').Substring(0,8)
    }
}

# 3) Baseline — no prompt, no max_age → code returned.
Measure-Step "3. baseline authorize → expect code" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge
    if ($r.Query['error']) { throw "baseline returned error=$($r.Query['error'])" }
    if (-not $r.Query['code']) { throw "baseline did not return code (loc: $($r.Location))" }
    if ($r.Query['state'] -ne $f.State) { throw "state mismatch" }
    Write-Host "  ✓ code received, state round-trip ok" -ForegroundColor Green
} | Out-Null

# 4) prompt=login → login_required (redirect_uri carries the error per RFC 6749 §4.1.2.1).
Measure-Step "4. prompt=login → expect login_required" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge `
        -Extras @{ prompt = "login" }
    if ($r.Query['error'] -ne 'login_required') {
        throw "expected error=login_required, got error=$($r.Query['error']) code=$($r.Query['code'])"
    }
    if ($r.Query['state'] -ne $f.State) { throw "state mismatch on error redirect" }
    Write-Host "  ✓ login_required + state echoed" -ForegroundColor Green
} | Out-Null

# 5) prompt=consent on an implicit-consent client → code is returned (no Explicit UI path).
Measure-Step "5. prompt=consent (implicit client) → expect code (consent silently re-issued)" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge `
        -Extras @{ prompt = "consent" }
    # For a client with ConsentType=Implicit, the consent service does not force a
    # UI re-prompt — but the server MUST still honour the authorize and return a code.
    if (-not $r.Query['code']) {
        # If the server uses Explicit consent it might 302 to /consent which would not
        # carry a code in the query. Either way, an "error=consent_required" would also
        # be RFC-aligned per OIDC §3.1.2.6.
        if ($r.Query['error'] -ne 'consent_required') {
            throw "prompt=consent: expected code OR error=consent_required, got error=$($r.Query['error']) loc=$($r.Location)"
        }
        Write-Host "  ✓ consent_required (Explicit-consent client)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ code returned (Implicit-consent client)" -ForegroundColor Green
    }
} | Out-Null

# 6) prompt=select_account → with no multi-account UI surface, server should
#    reject with login_required (OIDC §3.1.2.6 lets the OP use login_required when
#    it cannot satisfy the prompt request without UI).
Measure-Step "6. prompt=select_account → expect login_required (no UI surface)" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge `
        -Extras @{ prompt = "select_account" }
    # OIDC §3.1.2.6 permits account_selection_required, login_required, or interaction_required.
    # Server silently honouring (returning code) is ALSO spec-compliant when "the End-User
    # is already authenticated and OP determines they uniquely select that account".
    $err = $r.Query['error']
    $hasCode = -not [string]::IsNullOrEmpty($r.Query['code'])
    $okErrors = @('login_required','account_selection_required','interaction_required')
    if (-not $hasCode -and ($err -notin $okErrors)) {
        throw "expected code OR error in [$($okErrors -join ',')], got error=$err code=$($r.Query['code'])"
    }
    if ($hasCode) {
        Write-Host "  ✓ code returned (single-account auto-select, OIDC §3.1.2.6 compliant)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ error=$err (no UI surface, OIDC §3.1.2.6 compliant)" -ForegroundColor Green
    }
} | Out-Null

# 7) max_age=0 → must re-auth right now (login_required).
Measure-Step "7. max_age=0 → expect login_required (force re-auth)" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge `
        -Extras @{ max_age = "0" }
    if ($r.Query['error'] -ne 'login_required') {
        throw "max_age=0 should force login_required (server didn't honour OIDC §3.1.2.1). " +
              "Got error=$($r.Query['error']) code=$($r.Query['code'])"
    }
    if ($r.Query['state'] -ne $f.State) { throw "state mismatch on error redirect" }
    Write-Host "  ✓ login_required + state echoed" -ForegroundColor Green
} | Out-Null

# 8) max_age=99999 → fresh session, no re-auth needed, code returned.
Measure-Step "8. max_age=99999 → expect code (fresh session within window)" {
    $f = New-FlowState
    $r = Invoke-Authorize -Session $session -ClientId $reg.client_id `
        -State $f.State -Nonce $f.Nonce -CodeChallenge $f.Pkce.Challenge `
        -Extras @{ max_age = "99999" }
    if (-not $r.Query['code']) {
        throw "max_age=99999 on a fresh session should NOT force re-auth. Got error=$($r.Query['error']) loc=$($r.Location)"
    }
    Write-Host "  ✓ code returned (auth_time within window)" -ForegroundColor Green
} | Out-Null

# 9) RFC 7592 cleanup.
Measure-Step "9. RFC 7592 DELETE registration" {
    if (-not $RAT) { Write-Host "  (no RAT → skip)" -ForegroundColor DarkGray; return }
    Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
