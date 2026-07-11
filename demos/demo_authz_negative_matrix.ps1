# Conformance probe — /connect/authorize error matrix (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6).
# Request validation happens BEFORE end-user authentication, so these run without a login session.
#
# STRICT: every assertion encodes the spec requirement. A failing step = a real server deviation
# to FIX (in the server), never a demo to soften. Two delivery contracts per RFC 6749 §4.1.2.1:
#   • VALID client + VALID redirect_uri, other error (scope/response_type/missing response_type)
#       → error MUST be delivered to the redirect_uri as a query parameter (error=...).
#   • MISSING/UNKNOWN client_id, or UNREGISTERED/MISSING redirect_uri
#       → server MUST NOT redirect to the supplied URI; error is returned directly (no 302).
# Usage: pwsh -File demo_authz_negative_matrix.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$REDIRECT_CB = if ($BASE -like 'https:*') { 'https://localhost:9999/cb' } else { 'http://localhost:9999/cb' }
$REDIRECT = $REDIRECT_CB
$GOOD_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # valid 43-char base64url S256 challenge
$timings = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""; Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Action; $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" }); return $r
    } catch {
        $sw.Stop(); Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" }); throw
    }
}

# Probe /authorize with a raw HttpClient (AllowAutoRedirect=false) so a 302 is observed directly.
# Returns status, redirect Location, redirect-delivered error, body-delivered error, redirect host.
function Probe-Authorize([hashtable]$Params) {
    $handler = [System.Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
    # Raw HttpClient does not honour $PSDefaultParameterValues SkipCertificateCheck — accept the
    # dev/self-signed TLS cert explicitly so an https base works out of the box.
    $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        $dict = [System.Collections.Generic.Dictionary[string,string]]::new()
        foreach ($k in $Params.Keys) { $dict[$k] = [string]$Params[$k] }
        $content = [System.Net.Http.FormUrlEncodedContent]::new($dict)
        $resp = $client.PostAsync("$BASE/connect/authorize", $content).GetAwaiter().GetResult()
        $status = [int]$resp.StatusCode
        $loc = if ($resp.Headers.Location) { $resp.Headers.Location.ToString() } else { $null }
        $respBody = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $redirectErr = $null; $errHost = $null
        if ($loc) {
            $u = [uri]$loc; $errHost = $u.Host
            foreach ($pair in $u.Query.TrimStart('?').Split('&')) { $i=$pair.IndexOf('='); if ($i -gt 0 -and $pair.Substring(0,$i) -eq 'error') { $redirectErr = [uri]::UnescapeDataString($pair.Substring($i+1)) } }
        }
        $bodyErr = $null
        if ($respBody -and $respBody.TrimStart().StartsWith('{')) { try { $bodyErr = ($respBody | ConvertFrom-Json).error } catch {} }
        $isRedirect = ($status -ge 300 -and $status -lt 400 -and $loc)
        [pscustomobject]@{ status=$status; location=$loc; isRedirect=$isRedirect; redirectError=$redirectErr; bodyError=$bodyErr; redirectHost=$errHost }
    } finally { $client.Dispose() }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

$reg = Measure-Step "0. DCR valid client (redirect_uri=$REDIRECT)" {
    Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
        client_name="authz-neg"; redirect_uris=@($REDIRECT)
        grant_types=@("authorization_code","refresh_token"); scope="openid profile"
    } | ConvertTo-Json)
}
$CID = $reg.client_id

# ── Group 1: valid client + valid redirect → error MUST be delivered via the redirect_uri ──
Measure-Step "1. unsupported response_type=token → error via redirect_uri" {
    $r = Probe-Authorize @{ response_type="token"; client_id=$CID; redirect_uri=$REDIRECT; scope="openid" }
    if (-not $r.isRedirect -or $r.redirectHost -ne 'localhost') { throw "expected redirect back to localhost:9999; status=$($r.status) loc=$($r.location)" }
    if ($r.redirectError -notin @('unsupported_response_type','unauthorized_client')) { throw "want unsupported_response_type via redirect, got '$($r.redirectError)'" }
    Write-Host "  ✓ error='$($r.redirectError)' delivered via redirect_uri" -ForegroundColor Green
} | Out-Null

Measure-Step "2. missing response_type → invalid_request via redirect_uri" {
    $r = Probe-Authorize @{ client_id=$CID; redirect_uri=$REDIRECT; scope="openid" }
    if (-not $r.isRedirect -or $r.redirectHost -ne 'localhost') { throw "expected redirect back to localhost; status=$($r.status) loc=$($r.location)" }
    if ($r.redirectError -ne 'invalid_request') { throw "want invalid_request via redirect, got '$($r.redirectError)'" }
    Write-Host "  ✓ error='invalid_request' delivered via redirect_uri" -ForegroundColor Green
} | Out-Null

Measure-Step "3. unknown scope → error=invalid_scope MUST be delivered via redirect_uri (RFC 6749 §4.1.2.1)" {
    $r = Probe-Authorize @{ response_type="code"; client_id=$CID; redirect_uri=$REDIRECT; scope="openid totally_unknown_scope_xyz"; code_challenge=$GOOD_CHALLENGE; code_challenge_method="S256" }
    if (-not $r.isRedirect) { throw "invalid_scope returned directly (status=$($r.status), body error='$($r.bodyError)') — RFC 6749 §4.1.2.1 requires delivery via the redirect_uri" }
    if ($r.redirectHost -ne 'localhost') { throw "expected redirect back to localhost; loc=$($r.location)" }
    if ($r.redirectError -ne 'invalid_scope') { throw "want invalid_scope via redirect, got '$($r.redirectError)'" }
    Write-Host "  ✓ error='invalid_scope' delivered via redirect_uri" -ForegroundColor Green
} | Out-Null

# ── Group 2: untrusted target → server MUST NOT redirect to it ──────────────────────────────
Measure-Step "4. valid client + UNREGISTERED redirect_uri (complete req) → NO redirect, direct invalid_request" {
    $evil = "http://evil.attacker.example/cb"
    $r = Probe-Authorize @{ response_type="code"; client_id=$CID; redirect_uri=$evil; scope="openid"; code_challenge=$GOOD_CHALLENGE; code_challenge_method="S256"; state="s" }
    if ($r.redirectHost -eq 'evil.attacker.example') { throw "OPEN REDIRECT: error redirected to unregistered redirect_uri '$evil' (loc=$($r.location))" }
    if ($r.bodyError -ne 'invalid_request') { throw "want direct invalid_request for unregistered redirect_uri, got error='$($r.bodyError)' status=$($r.status)" }
    Write-Host "  ✓ unregistered redirect_uri → direct invalid_request, no redirect (status=$($r.status))" -ForegroundColor Green
} | Out-Null

Measure-Step "5. unknown client_id → server MUST NOT redirect" {
    $r = Probe-Authorize @{ response_type="code"; client_id=[Guid]::NewGuid().ToString(); redirect_uri=$REDIRECT; scope="openid"; code_challenge=$GOOD_CHALLENGE; code_challenge_method="S256" }
    if ($r.isRedirect) { throw "OPEN REDIRECT: error redirected for an unknown client (loc=$($r.location))" }
    Write-Host "  ✓ unknown client → no redirect (status=$($r.status))" -ForegroundColor Green
} | Out-Null

Measure-Step "6. missing client_id → server MUST NOT redirect (RFC 6749 §4.1.2.1)" {
    $r = Probe-Authorize @{ response_type="code"; redirect_uri=$REDIRECT; scope="openid"; code_challenge=$GOOD_CHALLENGE; code_challenge_method="S256" }
    if ($r.isRedirect) { throw "OPEN REDIRECT: error redirected to redirect_uri without a validated client_id (loc=$($r.location))" }
    Write-Host "  ✓ missing client_id → no redirect (status=$($r.status))" -ForegroundColor Green
} | Out-Null

Measure-Step "7. missing code_challenge + UNREGISTERED redirect_uri → MUST NOT redirect to it" {
    $evil = "http://evil.attacker.example/cb"
    $r = Probe-Authorize @{ response_type="code"; client_id=$CID; redirect_uri=$evil; scope="openid"; state="s" }  # no code_challenge
    if ($r.redirectHost -eq 'evil.attacker.example') { throw "OPEN REDIRECT: PKCE error redirected to unregistered redirect_uri '$evil' (loc=$($r.location))" }
    Write-Host "  ✓ no redirect to unregistered URI even with missing code_challenge (status=$($r.status))" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""; Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan
