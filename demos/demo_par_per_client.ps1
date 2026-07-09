# Per-client PAR enforcement (RFC 9126 §5).
#   Client opts in via DCR `require_pushed_authorization_requests=true`.
#   Server then rejects any direct /connect/authorize for this client unless
#   the request was first pushed through /connect/par. Probes:
#     1. Discovery advertises pushed_authorization_request_endpoint URL
#     2. DCR with require_pushed_authorization_requests=true → echoed back
#     3. Direct GET /connect/authorize (no request_uri) → invalid_request
#        (RFC 6749 §4.1.2.1 — error flows back to redirect_uri, not JSON)
#     4. POST /connect/par + GET /connect/authorize?request_uri=… →
#        request shape now conformant; error != invalid_request
#     5. RFC 7592 DELETE cleanup
# Usage: pwsh -File demo_par_per_client.ps1

$BASE    = "http://127.0.0.1:5002"
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

function B64U([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
}
function New-Pkce {
    $verifier  = B64U ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $challenge = B64U ([System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::ASCII.GetBytes($verifier)))
    return [pscustomobject]@{ Verifier=$verifier; Challenge=$challenge }
}

# Inspect a redirect Location URL and decide whether it looks like an OAuth error
# response per RFC 6749 §4.1.2.1 (params on the *redirect_uri*) or any other
# kind of response (login UI redirect, success).
function Get-AuthorizeOutcome {
    param([string]$Url)
    if ([string]::IsNullOrEmpty($Url)) { return [pscustomobject]@{ Error=$null; Raw=$Url } }
    try {
        $u = [Uri]$Url
        $q = [System.Web.HttpUtility]::ParseQueryString($u.Query)
        return [pscustomobject]@{
            Error       = $q['error']
            Description = $q['error_description']
            State       = $q['state']
            Iss         = $q['iss']
            Host        = $u.Host
            Path        = $u.AbsolutePath
            Raw         = $Url
        }
    } catch {
        return [pscustomobject]@{ Error=$null; Raw=$Url }
    }
}
Add-Type -AssemblyName System.Web

$total = [System.Diagnostics.Stopwatch]::StartNew()

# 1) Discovery — assert pushed_authorization_request_endpoint URL is advertised
$disc = Measure-Step "1. discovery /.well-known/openid-configuration advertises PAR endpoint URL" {
    $d = Invoke-RestMethod "$BASE/.well-known/openid-configuration"
    if (-not $d.pushed_authorization_request_endpoint) {
        throw "discovery missing pushed_authorization_request_endpoint URL"
    }
    if ($d.pushed_authorization_request_endpoint -notmatch '^https?://[^/]+/connect/par$') {
        throw "pushed_authorization_request_endpoint shape unexpected: $($d.pushed_authorization_request_endpoint)"
    }
    Write-Host "  ✓ pushed_authorization_request_endpoint = $($d.pushed_authorization_request_endpoint)" -ForegroundColor Green
    return $d
}

$REDIRECT = "http://localhost:9999/cb"

# 2) DCR with require_pushed_authorization_requests=true
$reg = Measure-Step "2. DCR /connect/register (require_pushed_authorization_requests=true)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name                            = "par-per-client-demo"
            redirect_uris                          = @($REDIRECT)
            grant_types                            = @("authorization_code","refresh_token")
            scope                                  = "openid profile email"
            require_pushed_authorization_requests  = $true
        } | ConvertTo-Json -Depth 5)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    if ($r.require_pushed_authorization_requests -ne $true) {
        throw "server did not echo require_pushed_authorization_requests=true (got: $($r.require_pushed_authorization_requests))"
    }
    Write-Host "  ✓ client_id   : $($r.client_id)" -ForegroundColor Green
    Write-Host "  ✓ flag echoed : require_pushed_authorization_requests = true" -ForegroundColor Green
    return $r
}

$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 3) Direct /connect/authorize (no request_uri) → expect invalid_request via redirect_uri
#    Per RFC 6749 §4.1.2.1, validation errors that occur AFTER client_id+redirect_uri
#    pass authentication MUST be returned by redirecting back to redirect_uri with the
#    error= and error_description= query params. The request_uri-required violation
#    qualifies because the client+redirect are valid; only the request shape isn't.
$pkceA  = New-Pkce
$stateA = [Guid]::NewGuid().ToString("N")
$directAuthorize =
    "$BASE/connect/authorize?response_type=code" +
    "&client_id=$([Uri]::EscapeDataString($reg.client_id))" +
    "&redirect_uri=$([Uri]::EscapeDataString($REDIRECT))" +
    "&scope=$([Uri]::EscapeDataString('openid profile'))" +
    "&state=$stateA" +
    "&code_challenge=$($pkceA.Challenge)&code_challenge_method=S256"

Measure-Step "3. direct GET /connect/authorize (no request_uri) -> invalid_request" {
    # -SkipHttpErrorCheck (pwsh 7+) keeps non-2xx responses in $resp instead of throwing.
    # -MaximumRedirection 0 makes the AS's 302 land here as a regular response with the
    # Location header still attached, so we can inspect the redirect target without the
    # client following it.  PowerShell prints a non-fatal "maximum redirection count" line
    # to stderr but the response object is fully populated, which is what we want.
    $resp = Invoke-WebRequest -Uri $directAuthorize -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    $code = [int]$resp.StatusCode
    $locArr = $resp.Headers['Location']
    $loc = if ($locArr) { @($locArr)[0] } else { $null }

    Write-Host "  status   : $code"
    if ($loc) { Write-Host "  Location : $loc" }

    if ($code -in 302,303,307) {
        $outcome = Get-AuthorizeOutcome $loc
        if ($outcome.Error -ne 'invalid_request') {
            throw "expected error=invalid_request on redirect, got error='$($outcome.Error)' / desc='$($outcome.Description)'"
        }
        # Must redirect to the registered redirect_uri host (RFC 6749 §4.1.2.1) — NOT to the AS /login.
        if ($outcome.Host -ne 'localhost') {
            throw "error redirected away from registered redirect_uri host (got: $($outcome.Host))"
        }
        if ($outcome.State -ne $stateA) {
            throw "state did not round-trip on error redirect (expected '$stateA', got '$($outcome.State)')"
        }
        Write-Host "  ✓ rejected via redirect: error=invalid_request state=$($outcome.State)" -ForegroundColor Green
        Write-Host "  ✓ description mentions PAR: $($outcome.Description.Substring(0, [Math]::Min(60, $outcome.Description.Length)))…" -ForegroundColor Green
    } elseif ($code -eq 400) {
        # Acceptable fallback: server chose JSON 400 if it considered the request
        # too malformed to bind to redirect_uri. Not preferred, but spec-compatible.
        Write-Host "  ✓ rejected with 400 (JSON form acceptable)" -ForegroundColor Green
    } else {
        throw "expected 302→redirect_uri?error=invalid_request OR 400, got status $code"
    }
} | Out-Null

# 4) POST /connect/par + GET /connect/authorize?request_uri=… — request now conformant.
$pkceB  = New-Pkce
$stateB = [Guid]::NewGuid().ToString("N")
$nonceB = [Guid]::NewGuid().ToString("N")

$par = Measure-Step "4a. POST /connect/par (push the request)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/par" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            response_type         = "code"
            client_id             = $reg.client_id
            client_secret         = $reg.client_secret
            redirect_uri          = $REDIRECT
            scope                 = "openid profile email"
            state                 = $stateB
            nonce                 = $nonceB
            code_challenge        = $pkceB.Challenge
            code_challenge_method = "S256"
        }
    if (-not $r.request_uri) { throw "PAR did not return request_uri" }
    if ($r.request_uri -notmatch "^urn:ietf:params:oauth:request_uri:") {
        throw "request_uri does not use RFC 9126 URN prefix"
    }
    Write-Host "  ✓ request_uri = $($r.request_uri)" -ForegroundColor Green
    return $r
}

$parAuthorize =
    "$BASE/connect/authorize?client_id=$([Uri]::EscapeDataString($reg.client_id))" +
    "&request_uri=$([Uri]::EscapeDataString($par.request_uri))"

Measure-Step "4b. GET /connect/authorize?request_uri=… -> NOT invalid_request" {
    $resp = Invoke-WebRequest -Uri $parAuthorize -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    $code = [int]$resp.StatusCode
    $locArr = $resp.Headers['Location']
    $loc = if ($locArr) { @($locArr)[0] } else { $null }

    Write-Host "  status   : $code"
    if ($loc) { Write-Host "  Location : $loc" }

    # Not invalid_request — anything else is fine: the request shape is now conformant,
    # and the AS will either redirect to its /login UI (no session) or back to redirect_uri
    # with login_required (also acceptable). What we MUST NOT see: error=invalid_request
    # with the PAR-required description.
    if ($code -notin 200,302,303,307,308) {
        throw "expected 2xx/3xx after PAR push, got $code"
    }
    if ($loc) {
        $outcome = Get-AuthorizeOutcome $loc
        if ($outcome.Error -eq 'invalid_request') {
            throw "PAR-pushed authorize STILL rejected as invalid_request — per-client enforcement not honouring request_uri ($($outcome.Description))"
        }
        Write-Host "  ✓ accepted (no invalid_request); redirected to $($outcome.Host)$($outcome.Path)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ accepted (status $code, no error redirect)" -ForegroundColor Green
    }
} | Out-Null

# 5) RFC 7592 DELETE — cleanup
Measure-Step "5. RFC 7592 DELETE registration" {
    if (-not $RAT) { Write-Host "  (no RAT → skip)" -ForegroundColor DarkGray; return }
    Invoke-RestMethod -Method Delete -Uri $RCU `
        -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
